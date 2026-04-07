/**
 * @file handshake.h
 * @brief WPA/WPA2 Handshake Capture Module
 * 
 * WPA/WPA2 4-way handshake 捕获模块
 * 用于捕获和存储握手包，支持离线破解
 */

#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include "config.h"
#include "packet_parser.h"

// ==================== 握手包状态定义 ====================

enum HandshakeState {
    HS_NONE = 0,           // 未开始
    HS_MSG1_RECEIVED,      // 收到 Message 1 (AP -> STA)
    HS_MSG2_RECEIVED,      // 收到 Message 2 (STA -> AP)
    HS_MSG3_RECEIVED,      // 收到 Message 3 (AP -> STA)
    HS_MSG4_RECEIVED,      // 收到 Message 4 (STA -> AP)
    HS_COMPLETE            // 握手完成
};

// ==================== 握手包数据结构 ====================

struct WPAHandshake {
    // 网络标识
    uint8_t bssid[6];
    uint8_t station[6];
    char ssid[33];
    
    // 握手消息
    bool hasMsg1;
    bool hasMsg2;
    bool hasMsg3;
    bool hasMsg4;
    
    // Message 1 数据 (AP -> STA)
    uint8_t msg1Anonce[32];
    uint16_t msg1KeyInfo;
    uint8_t msg1ReplayCounter[8];
    uint32_t msg1Timestamp;
    
    // Message 2 数据 (STA -> AP)
    uint8_t msg2Snonce[32];
    uint8_t msg2Mic[16];
    uint16_t msg2KeyInfo;
    uint8_t msg2ReplayCounter[8];
    uint32_t msg2Timestamp;
    uint8_t msg2Eapol[512];      // 完整 EAPOL 帧
    uint16_t msg2EapolLen;
    
    // Message 3 数据 (AP -> STA)
    uint8_t msg3Anonce[32];
    uint8_t msg3Mic[16];
    uint16_t msg3KeyInfo;
    uint8_t msg3ReplayCounter[8];
    uint32_t msg3Timestamp;
    uint8_t msg3Eapol[512];
    uint16_t msg3EapolLen;
    
    // Message 4 数据 (STA -> AP)
    uint8_t msg4Mic[16];
    uint16_t msg4KeyInfo;
    uint8_t msg4ReplayCounter[8];
    uint32_t msg4Timestamp;
    
    // 状态
    HandshakeState state;
    uint32_t lastUpdate;
    bool complete;
    bool valid;
    
    // 统计
    uint32_t captureTime;        // 捕获耗时 (毫秒)
};

// ==================== HCCAPX 文件格式 (用于 hashcat) ====================

#define HCCAPX_SIGNATURE 0x58504348  // "HCPX"
#define HCCAPX_VERSION 4

struct HCCAPXRecord {
    uint32_t signature;          // HCCAPX_SIGNATURE
    uint32_t version;            // HCCAPX_VERSION
    uint8_t messagePair;         // 消息对标识
    uint8_t essidLen;
    uint8_t essid[32];
    uint8_t keyver;              // 1=RC4, 2=AES
    uint8_t keymic[16];
    uint8_t macAp[6];
    uint8_t nonceAp[32];
    uint8_t macSta[6];
    uint8_t nonceSta[32];
    uint16_t eapolLen;
    uint8_t eapol[256];
};

// ==================== 类定义 ====================

class HandshakeCapture {
public:
    HandshakeCapture();
    ~HandshakeCapture();

    // 初始化和清理
    bool begin();
    void end();

    // 处理数据包 (由 WiFiSniffer 调用)
    void processPacket(const uint8_t* packet, uint16_t len, const PacketInfo* info);

    // 目标设置
    void setTargetBSSID(const uint8_t* bssid);
    void setTargetStation(const uint8_t* station);
    void clearTarget();
    bool hasTarget() const { return targetSet; }
    
    // 获取目标信息
    void getTargetBSSID(uint8_t* bssid) const;
    void getTargetStation(uint8_t* station) const;

    // 握手包管理
    bool isHandshakeComplete() const;
    bool hasValidHandshake() const;
    const WPAHandshake* getHandshake() const { return &handshake; }
    void resetHandshake();

    // 获取握手包质量评分 (0-100)
    int getHandshakeQuality() const;
    
    // 获取握手包信息字符串
    void getHandshakeInfo(char* buffer, size_t len) const;

    // 保存到文件
    bool saveToHCCAPX(const char* filename) const;
    bool saveToPCAP(const char* filename) const;
    
    // 导出为各种格式
    bool exportToHashcat(const char* filename) const;
    bool exportToJohn(const char* filename) const;
    bool exportToAircrack(const char* filename) const;

    // 统计
    uint32_t getTotalEAPOLPackets() const { return totalEAPOL; }
    uint32_t getHandshakeAttempts() const { return handshakeAttempts; }

    // 自动捕获模式
    void enableAutoCapture(bool enable) { autoCapture = enable; }
    bool isAutoCaptureEnabled() const { return autoCapture; }

private:
    WPAHandshake handshake;
    bool targetSet;
    bool hasBSSID;
    bool hasStation;
    uint8_t targetBSSID[6];
    uint8_t targetStation[6];
    
    // 统计
    uint32_t totalEAPOL;
    uint32_t handshakeAttempts;
    
    // 自动捕获
    bool autoCapture;
    
    // 内部处理函数
    void processEAPOL(const uint8_t* packet, uint16_t len, const PacketInfo* info);
    void processMessage1(const uint8_t* eapol, uint16_t len, const EAPOLKeyHeader* key);
    void processMessage2(const uint8_t* eapol, uint16_t len, const EAPOLKeyHeader* key, 
                         const uint8_t* src, const uint8_t* dst);
    void processMessage3(const uint8_t* eapol, uint16_t len, const EAPOLKeyHeader* key);
    void processMessage4(const uint8_t* eapol, uint16_t len, const EAPOLKeyHeader* key);
    
    // 验证函数
    bool validateHandshake() const;
    bool checkReplayCounter(const uint8_t* counter1, const uint8_t* counter2) const;
    
    // 辅助函数
    void updateSSID(const uint8_t* bssid);
    int findHandshakeMessage(const EAPOLKeyHeader* key) const;
    void copyEAPOLFrame(const uint8_t* src, uint16_t len, uint8_t* dst, uint16_t* dstLen);
    
    // HCCAPX 构建
    void buildHCCAPX(HCCAPXRecord* record) const;
};

// ==================== 全局实例 ====================
extern HandshakeCapture Handshake;

// ==================== 辅助函数 ====================
const char* getHandshakeStateString(HandshakeState state);
const char* getHandshakeQualityString(int quality);
void printHandshakeInfo(const WPAHandshake* hs);

#endif // HANDSHAKE_H
