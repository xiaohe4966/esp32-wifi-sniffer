/**
 * @file config.h
 * @brief ESP32 WiFi Sniffer Configuration
 * 
 * WiFi 抓包工具配置文件
 * 用于无线安全研究和教育目的
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <Arduino.h>

// ==================== 版本信息 ====================
#define FIRMWARE_VERSION "1.0.0"
#define FIRMWARE_NAME "ESP32-WiFi-Sniffer"

// ==================== 硬件配置 ====================
// OLED 显示屏 (可选)
#define ENABLE_OLED true
#define OLED_SDA 8
#define OLED_SCL 9
#define OLED_ADDR 0x3C
#define OLED_WIDTH 128
#define OLED_HEIGHT 64

// SD 卡模块 (可选)
#define ENABLE_SD_CARD true
#define SD_CS 10
#define SD_MOSI 11
#define SD_MISO 13
#define SD_SCK 12

// LED 指示灯
#define LED_PIN 2

// ==================== WiFi 配置 ====================
// AP 模式配置 (用于 Web 界面)
#define AP_SSID "ESP32-Sniffer"
#define AP_PASSWORD "12345678"
#define AP_CHANNEL 11
#define AP_MAX_CONNECTIONS 4

// STA 模式配置 (可选，用于上传数据)
// #define STA_SSID "YourNetwork"
// #define STA_PASSWORD "YourPassword"

// ==================== 抓包配置 ====================
// 信道配置
#define MIN_CHANNEL_2G 1
#define MAX_CHANNEL_2G 14
#define MIN_CHANNEL_5G 36
#define MAX_CHANNEL_5G 165
#define CHANNEL_HOP_INTERVAL 200  // 毫秒

// 抓包缓冲区
#define MAX_PACKET_SIZE 2346  // 最大 802.11 帧大小
#define PACKET_BUFFER_SIZE 32 // 缓冲区包数量

// PCAP 文件配置
#define PCAP_FILENAME "/sdcard/capture.pcap"
#define PCAP_MAX_SIZE_MB 100  // 单个 PCAP 文件最大大小 (MB)
#define PCAP_ROTATE_COUNT 10  // 保留的 PCAP 文件数量

// ==================== 攻击配置 ====================
// Deauth 攻击配置
#define DEAUTH_BURST_COUNT 10
#define DEAUTH_INTERVAL_MS 100
#define DEAUTH_REASON 7  // Class 3 frame received from nonassociated STA

// 字典攻击配置
#define DICTIONARY_FILE "/sdcard/wordlist.txt"
#define MAX_PASSWORD_LENGTH 64
#define MIN_PASSWORD_LENGTH 8
#define DICT_BATCH_SIZE 100  // 每批处理的密码数量

// ==================== Web 服务器配置 ====================
#define WEB_SERVER_PORT 80
#define WEB_SOCKET_PORT 81
#define MAX_WEB_CLIENTS 4

// ==================== 串口配置 ====================
#define SERIAL_BAUD_RATE 115200
#define SERIAL_COMMAND_TIMEOUT 5000  // 毫秒

// ==================== 功能开关 ====================
// 启用/禁用特定功能
#define ENABLE_WIFI_SNIFFER true
#define ENABLE_HANDSHAKE_CAPTURE true
#define ENABLE_DEAUTH_ATTACK true
#define ENABLE_DICT_ATTACK true
#define ENABLE_WEB_SERVER true
#define ENABLE_WEBSOCKET true

// ==================== 调试配置 ====================
#define DEBUG_LEVEL 3  // 0=无, 1=错误, 2=警告, 3=信息, 4=调试

#define DEBUG_PRINT(level, fmt, ...) \
    do { \
        if (DEBUG_LEVEL >= level) { \
            Serial.printf("[%s] " fmt "\n", __FUNCTION__, ##__VA_ARGS__); \
        } \
    } while(0)

#define LOG_ERROR(fmt, ...) DEBUG_PRINT(1, "[ERROR] " fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) DEBUG_PRINT(2, "[WARN] " fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) DEBUG_PRINT(3, "[INFO] " fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) DEBUG_PRINT(4, "[DEBUG] " fmt, ##__VA_ARGS__)

// ==================== 安全限制 ====================
// 防止误操作的安全限制
#define MAX_DEAUTH_PER_MINUTE 60
#define MAX_CAPTURE_DURATION_MS 3600000  // 1 小时
#define REQUIRE_CONFIRMATION_FOR_ATTACK true

// ==================== 802.11 帧类型定义 ====================
#define FRAME_TYPE_MANAGEMENT 0x00
#define FRAME_TYPE_CONTROL 0x01
#define FRAME_TYPE_DATA 0x02
#define FRAME_TYPE_EXTENSION 0x03

// Management Frame Subtypes
#define MGMT_SUBTYPE_ASSOC_REQ 0x00
#define MGMT_SUBTYPE_ASSOC_RESP 0x01
#define MGMT_SUBTYPE_REASSOC_REQ 0x02
#define MGMT_SUBTYPE_REASSOC_RESP 0x03
#define MGMT_SUBTYPE_PROBE_REQ 0x04
#define MGMT_SUBTYPE_PROBE_RESP 0x05
#define MGMT_SUBTYPE_BEACON 0x08
#define MGMT_SUBTYPE_ATIM 0x09
#define MGMT_SUBTYPE_DISASSOC 0x0A
#define MGMT_SUBTYPE_AUTH 0x0B
#define MGMT_SUBTYPE_DEAUTH 0x0C
#define MGMT_SUBTYPE_ACTION 0x0D

// Control Frame Subtypes
#define CTRL_SUBTYPE_BLOCK_ACK_REQ 0x08
#define CTRL_SUBTYPE_BLOCK_ACK 0x09
#define CTRL_SUBTYPE_PS_POLL 0x0A
#define CTRL_SUBTYPE_RTS 0x0B
#define CTRL_SUBTYPE_CTS 0x0C
#define CTRL_SUBTYPE_ACK 0x0D
#define CTRL_SUBTYPE_CF_END 0x0E
#define CTRL_SUBTYPE_CF_END_ACK 0x0F

// Data Frame Subtypes
#define DATA_SUBTYPE_DATA 0x00
#define DATA_SUBTYPE_DATA_CF_ACK 0x01
#define DATA_SUBTYPE_DATA_CF_POLL 0x02
#define DATA_SUBTYPE_DATA_CF_ACK_POLL 0x03
#define DATA_SUBTYPE_NULL 0x04
#define DATA_SUBTYPE_CF_ACK 0x05
#define DATA_SUBTYPE_CF_POLL 0x06
#define DATA_SUBTYPE_CF_ACK_POLL 0x07
#define DATA_SUBTYPE_QOS_DATA 0x08
#define DATA_SUBTYPE_QOS_DATA_CF_ACK 0x09
#define DATA_SUBTYPE_QOS_DATA_CF_POLL 0x0A
#define DATA_SUBTYPE_QOS_DATA_CF_ACK_POLL 0x0B
#define DATA_SUBTYPE_QOS_NULL 0x0C
#define DATA_SUBTYPE_QOS_CF_POLL 0x0E
#define DATA_SUBTYPE_QOS_CF_ACK_POLL 0x0F

// ==================== 加密类型 ====================
enum WiFiAuthMode {
    AUTH_OPEN = 0,
    AUTH_WEP,
    AUTH_WPA_PSK,
    AUTH_WPA2_PSK,
    AUTH_WPA_WPA2_PSK,
    AUTH_WPA2_ENTERPRISE,
    AUTH_WPA3_PSK,
    AUTH_WPA2_WPA3_PSK,
    AUTH_UNKNOWN
};

// ==================== 数据结构 ====================
// WiFi 网络信息结构
struct WiFiNetwork {
    uint8_t bssid[6];
    char ssid[33];
    int8_t rssi;
    uint8_t channel;
    WiFiAuthMode authMode;
    bool hasHandshake;
    uint32_t packetCount;
    uint32_t dataPacketCount;
    uint32_t lastSeen;
};

// 数据包信息结构
struct PacketInfo {
    uint32_t timestamp;
    uint8_t channel;
    int8_t rssi;
    uint8_t frameType;
    uint8_t frameSubtype;
    uint8_t source[6];
    uint8_t destination[6];
    uint8_t bssid[6];
    uint16_t sequence;
    uint16_t length;
};

// 握手包信息结构
struct HandshakeInfo {
    uint8_t bssid[6];
    uint8_t station[6];
    uint8_t anonce[32];
    uint8_t snonce[32];
    uint8_t mic[16];
    uint16_t keyVersion;
    bool complete;
    uint32_t timestamp;
};

// 全局状态枚举
enum DeviceMode {
    MODE_IDLE = 0,
    MODE_SCANNING,
    MODE_SNIFFING,
    MODE_HANDSHAKE_CAPTURE,
    MODE_DEAUTH_ATTACK,
    MODE_DICT_ATTACK,
    MODE_WEB_SERVER
};

// ==================== 全局变量声明 ====================
extern DeviceMode currentMode;
extern volatile bool snifferRunning;
extern volatile bool channelHopping;
extern uint8_t currentChannel;

#endif // CONFIG_H
