/**
 * @file dictionary.h
 * @brief WPA/WPA2 Dictionary Attack Module
 * 
 * WPA/WPA2 字典攻击模块
 * 使用捕获的握手包进行密码破解
 */

#ifndef DICTIONARY_H
#define DICTIONARY_H

#include "config.h"
#include "handshake.h"

#if ENABLE_SD_CARD
#include <SD.h>
#include <SPI.h>
#endif

// ==================== 攻击状态定义 ====================

enum AttackState {
    ATTACK_IDLE = 0,
    ATTACK_PREPARING,
    ATTACK_RUNNING,
    ATTACK_PAUSED,
    ATTACK_COMPLETED,
    ATTACK_FAILED
};

// ==================== 攻击结果定义 ====================

enum AttackResult {
    RESULT_NONE = 0,
    RESULT_SUCCESS,
    RESULT_FAILED,
    RESULT_CANCELLED,
    RESULT_ERROR
};

// ==================== 进度回调类型 ====================

typedef void (*AttackProgressCallback)(uint32_t tested, uint32_t total, 
                                        const char* currentPassword, float speed);
typedef void (*AttackResultCallback)(AttackResult result, const char* password);

// ==================== 攻击统计结构 ====================

struct AttackStats {
    uint32_t totalPasswords;
    uint32_t testedPasswords;
    uint32_t skippedPasswords;
    uint32_t failedPasswords;
    float passwordsPerSecond;
    uint32_t elapsedTimeMs;
    uint32_t estimatedTimeMs;
    uint8_t progressPercent;
    char currentPassword[MAX_PASSWORD_LENGTH + 1];
    char foundPassword[MAX_PASSWORD_LENGTH + 1];
};

// ==================== 类定义 ====================

class DictionaryAttack {
public:
    DictionaryAttack();
    ~DictionaryAttack();

    // 初始化和清理
    bool begin();
    void end();

    // 设置目标
    bool setTargetHandshake(const WPAHandshake* handshake);
    bool loadDictionary(const char* filename);
    bool loadDictionaryFromStream(Stream* stream);
    
    // 攻击控制
    bool startAttack();
    void stopAttack();
    void pauseAttack();
    void resumeAttack();
    
    // 状态查询
    AttackState getState() const { return state; }
    AttackResult getResult() const { return result; }
    bool isRunning() const { return state == ATTACK_RUNNING; }
    bool isCompleted() const { return state == ATTACK_COMPLETED; }
    
    // 获取统计
    const AttackStats* getStats() const { return &stats; }
    void getProgressString(char* buffer, size_t len) const;
    
    // 回调设置
    void setProgressCallback(AttackProgressCallback callback);
    void setResultCallback(AttackResultCallback callback);
    
    // 测试单个密码
    bool testPassword(const char* password);
    
    // 批量测试
    bool testPasswordBatch(const char** passwords, int count);
    
    // 生成 PMK (Pairwise Master Key)
    static void generatePMK(const char* password, const char* ssid, 
                            uint8_t* pmk, size_t pmkLen = 32);
    
    // 生成 PTK (Pairwise Transient Key)
    static void generatePTK(const uint8_t* pmk, const uint8_t* anonce, 
                            const uint8_t* snonce, const uint8_t* macAp, 
                            const uint8_t* macSta, uint8_t* ptk, size_t ptkLen = 64);
    
    // 计算 MIC
    static void calculateMIC(const uint8_t* ptk, const uint8_t* data, size_t len, 
                             uint8_t* mic, uint8_t keyVersion);

    // 配置
    void setBatchSize(uint16_t size) { batchSize = size; }
    void setMaxPasswordLength(uint8_t len) { maxPasswordLength = len; }
    void setMinPasswordLength(uint8_t len) { minPasswordLength = len; }

private:
    AttackState state;
    AttackResult result;
    AttackStats stats;
    
    WPAHandshake targetHandshake;
    bool hasTarget;
    
    // 字典文件
#if ENABLE_SD_CARD
    File dictFile;
    char dictFilename[128];
    bool dictLoaded;
#endif
    
    // 配置
    uint16_t batchSize;
    uint8_t maxPasswordLength;
    uint8_t minPasswordLength;
    
    // 任务
    TaskHandle_t attackTaskHandle;
    bool taskRunning;
    
    // 回调
    AttackProgressCallback progressCallback;
    AttackResultCallback resultCallback;
    
    // 内部方法
    static void attackTask(void* parameter);
    void runAttack();
    bool processPassword(const char* password);
    bool verifyPassword(const char* password);
    
    // 密码读取
    bool readNextPassword(char* buffer, size_t len);
    void skipInvalidPasswords();
    
    // 加密函数
    static void hmacSha1(const uint8_t* key, size_t keyLen, 
                         const uint8_t* data, size_t dataLen, 
                         uint8_t* output);
    static void pbkdf2HmacSha1(const char* password, const char* salt, 
                               int iterations, uint8_t* output, size_t outLen);
    static void prf(const uint8_t* key, size_t keyLen, const char* label,
                    const uint8_t* data, size_t dataLen, 
                    uint8_t* output, size_t outLen);
    
    // 辅助函数
    void updateStats();
    void notifyProgress();
    void notifyResult(AttackResult res, const char* password);
    void resetStats();
};

// ==================== 全局实例 ====================
extern DictionaryAttack DictAttack;

// ==================== 辅助函数 ====================
const char* getAttackStateString(AttackState state);
const char* getAttackResultString(AttackResult result);
void formatDuration(uint32_t ms, char* buffer, size_t len);
void formatSpeed(float pps, char* buffer, size_t len);

// ==================== 常用密码列表 (内置小字典) ====================
extern const char* commonPasswords[];
extern const int commonPasswordsCount;

#endif // DICTIONARY_H
