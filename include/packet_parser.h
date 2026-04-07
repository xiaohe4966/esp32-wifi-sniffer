/**
 * @file packet_parser.h
 * @brief 802.11 Packet Parser Module
 * 
 * 802.11 数据包解析模块
 * 解析各种 WiFi 帧类型和提取有用信息
 */

#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include "config.h"

// ==================== 802.11 帧结构定义 ====================

// Frame Control 字段
struct FrameControl {
    uint8_t protocolVersion : 2;
    uint8_t type : 2;
    uint8_t subtype : 4;
    uint8_t toDS : 1;
    uint8_t fromDS : 1;
    uint8_t moreFrag : 1;
    uint8_t retry : 1;
    uint8_t powerMgmt : 1;
    uint8_t moreData : 1;
    uint8_t protectedFrame : 1;
    uint8_t order : 1;
};

// 802.11 MAC 头部 (24 字节)
struct IEEE80211Header {
    FrameControl fc;
    uint16_t duration;
    uint8_t addr1[6];  // Receiver Address
    uint8_t addr2[6];  // Transmitter Address
    uint8_t addr3[6];  // BSSID / Destination
    uint16_t seqCtrl;
    // addr4 仅在 WDS (4-address) 帧中存在
};

// QoS Control 字段 (2 字节)
struct QoSControl {
    uint8_t tid : 4;
    uint8_t bit4 : 1;
    uint8_t ackPolicy : 2;
    uint8_t reserved : 1;
    uint8_t txopLimit;
};

// 802.11 数据帧头部 (带 QoS)
struct IEEE80211DataHeader {
    FrameControl fc;
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seqCtrl;
    QoSControl qos;
};

// Beacon / Probe Response 帧的固定参数
struct BeaconFixedParams {
    uint64_t timestamp;
    uint16_t beaconInterval;
    uint16_t capInfo;
};

// Authentication 帧的固定参数
struct AuthFixedParams {
    uint16_t authAlgorithm;
    uint16_t authSeq;
    uint16_t statusCode;
};

// Association Request 帧的固定参数
struct AssocReqFixedParams {
    uint16_t capInfo;
    uint16_t listenInterval;
};

// Association Response 帧的固定参数
struct AssocRespFixedParams {
    uint16_t capInfo;
    uint16_t statusCode;
    uint16_t assocId;
};

// Deauthentication 帧的固定参数
struct DeauthFixedParams {
    uint16_t reasonCode;
};

// ==================== EAPOL 帧结构 (用于 WPA/WPA2 握手) ====================

#define EAPOL_VERSION 0x01
#define EAPOL_KEY_TYPE 0x03

// EAPOL 头部
struct EAPOLHeader {
    uint8_t version;
    uint8_t type;
    uint16_t length;
};

// EAPOL-Key 头部
struct EAPOLKeyHeader {
    uint8_t type;
    uint16_t keyInfo;
    uint16_t keyLength;
    uint8_t replayCounter[8];
    uint8_t nonce[32];      // ANonce or SNonce
    uint8_t iv[16];
    uint8_t rsc[8];
    uint8_t reserved[8];
    uint8_t mic[16];
    uint16_t keyDataLength;
    // 后面跟着 keyData
};

// Key Information 字段位定义
#define KEY_INFO_KEY_TYPE (1 << 3)      // 1=Pairwise, 0=Group
#define KEY_INFO_INSTALL (1 << 6)       // 安装 PTK
#define KEY_INFO_ACK (1 << 7)           // 需要响应
#define KEY_INFO_MIC (1 << 8)           // MIC 存在
#define KEY_INFO_SECURE (1 << 9)        // 安全标志
#define KEY_INFO_ERROR (1 << 10)        // 错误标志
#define KEY_INFO_REQUEST (1 << 11)      // 请求标志
#define KEY_INFO_ENCDATA (1 << 12)      // 加密数据
#define KEY_INFO_SMK (1 << 13)          // SMK 消息

// ==================== 信息元素 (Information Elements) ====================

// 常见的 IE 类型
#define IE_SSID 0
#define IE_SUPPORTED_RATES 1
#define IE_DS_PARAMETER_SET 3
#define IE_CF_PARAMETER_SET 4
#define IE_TIM 5
#define IE_IBSS_PARAMETER_SET 6
#define IE_COUNTRY 7
#define IE_BSS_LOAD 11
#define IE_POWER_CONSTRAINT 32
#define IE_TPC_REPORT 35
#define IE_CHANNEL_SWITCH_ANNOUNCEMENT 37
#define IE_QUIET 40
#define IE_IBSS_DFS 41
#define IE_ERP_INFORMATION 42
#define IE_HT_CAPABILITIES 45
#define IE_QOS_CAPABILITY 46
#define IE_RSN_INFORMATION 48
#define IE_EXTENDED_SUPPORTED_RATES 50
#define IE_MOBILITY_DOMAIN 54
#define IE_FAST_BSS_TRANSITION 55
#define IE_TIMEOUT_INTERVAL 56
#define IE_RIC_DATA 57
#define IE_HT_OPERATION 61
#define IE_SECONDARY_CHANNEL_OFFSET 62
#define IE_WAPI 68
#define IE_VENDOR_SPECIFIC 221

// IE 头部结构
struct IEHeader {
    uint8_t id;
    uint8_t length;
};

// ==================== 类定义 ====================

class PacketParser {
public:
    PacketParser();
    ~PacketParser();

    // 解析 802.11 帧
    bool parseFrame(const uint8_t* packet, uint16_t len, PacketInfo* info);
    
    // 获取帧类型信息
    static uint8_t getFrameType(const uint8_t* packet);
    static uint8_t getFrameSubtype(const uint8_t* packet);
    static bool isToDS(const uint8_t* packet);
    static bool isFromDS(const uint8_t* packet);
    static bool isProtected(const uint8_t* packet);
    
    // 获取地址
    static void getDestination(const uint8_t* packet, uint8_t* addr);
    static void getSource(const uint8_t* packet, uint8_t* addr);
    static void getBSSID(const uint8_t* packet, uint8_t* addr);
    static void getTransmitter(const uint8_t* packet, uint8_t* addr);
    static void getReceiver(const uint8_t* packet, uint8_t* addr);
    
    // 解析管理帧
    bool parseBeacon(const uint8_t* packet, uint16_t len, char* ssid, size_t ssidLen, 
                     uint8_t* channel, WiFiAuthMode* authMode);
    bool parseProbeResponse(const uint8_t* packet, uint16_t len, char* ssid, size_t ssidLen);
    bool parseProbeRequest(const uint8_t* packet, uint16_t len, char* ssid, size_t ssidLen);
    bool parseAuthentication(const uint8_t* packet, uint16_t len, uint16_t* algorithm, 
                             uint16_t* seq, uint16_t* status);
    bool parseDeauthentication(const uint8_t* packet, uint16_t len, uint16_t* reason);
    
    // 解析 EAPOL 帧 (WPA/WPA2 握手)
    bool isEAPOL(const uint8_t* packet, uint16_t len);
    bool parseEAPOL(const uint8_t* packet, uint16_t len, EAPOLKeyHeader* keyInfo);
    bool isHandshakeMessage(const uint8_t* packet, uint16_t len, int* msgNumber);
    int findHandshakeMessage(const EAPOLKeyHeader* key);
    
    // 解析信息元素
    const uint8_t* findIE(const uint8_t* ies, uint16_t iesLen, uint8_t ieId);
    bool getSSID(const uint8_t* ies, uint16_t iesLen, char* ssid, size_t maxLen);
    bool getChannel(const uint8_t* ies, uint16_t iesLen, uint8_t* channel);
    bool getRSNInfo(const uint8_t* ies, uint16_t iesLen, WiFiAuthMode* authMode);
    
    // 辅助函数
    static uint16_t getSequenceNumber(const uint8_t* packet);
    static uint16_t getFragmentNumber(const uint8_t* packet);
    static uint32_t getFrameLength(const uint8_t* packet, uint16_t len);
    
    // 数据包打印
    void printFrameInfo(const PacketInfo* info);
    void printHexDump(const uint8_t* data, uint16_t len, uint16_t offset = 0);

private:
    // 内部解析函数
    bool parseIEs(const uint8_t* packet, uint16_t len, uint16_t fixedParamsLen,
                  char* ssid, size_t ssidLen, uint8_t* channel, WiFiAuthMode* authMode);
    WiFiAuthMode detectEncryption(const uint8_t* ies, uint16_t iesLen);
    
    // 静态辅助函数
    static uint8_t* getAddressPtr(const uint8_t* packet, int addrIndex);
};

// ==================== 全局实例 ====================
extern PacketParser Parser;

// ==================== 辅助宏 ====================
#define FC_TO_DS(fc) (((fc) >> 8) & 0x01)
#define FC_FROM_DS(fc) (((fc) >> 9) & 0x01)
#define FC_MORE_FRAG(fc) (((fc) >> 10) & 0x01)
#define FC_RETRY(fc) (((fc) >> 11) & 0x01)
#define FC_PWR_MGMT(fc) (((fc) >> 12) & 0x01)
#define FC_MORE_DATA(fc) (((fc) >> 13) & 0x01)
#define FC_PROTECTED(fc) (((fc) >> 14) & 0x01)
#define FC_ORDER(fc) (((fc) >> 15) & 0x01)

#endif // PACKET_PARSER_H
