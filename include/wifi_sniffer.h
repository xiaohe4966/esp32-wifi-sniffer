/**
 * @file wifi_sniffer.h
 * @brief WiFi Sniffer Core Module
 * 
 * WiFi 抓包核心模块头文件
 * 提供混杂模式抓包和信道切换功能
 */

#ifndef WIFI_SNIFFER_H
#define WIFI_SNIFFER_H

#include "config.h"
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>

// ==================== 回调函数类型定义 ====================
typedef void (*PacketCallback)(const uint8_t* packet, uint16_t len, const PacketInfo* info);
typedef void (*NetworkFoundCallback)(const WiFiNetwork* network);

// ==================== 类定义 ====================
class WiFiSniffer {
public:
    WiFiSniffer();
    ~WiFiSniffer();

    // 初始化和清理
    bool begin();
    void end();

    // 抓包控制
    bool startSniffing();
    void stopSniffing();
    bool isRunning() const { return running; }

    // 信道控制
    void setChannel(uint8_t channel);
    uint8_t getCurrentChannel() const { return currentChannel; }
    void startChannelHopping();
    void stopChannelHopping();
    bool isChannelHopping() const { return channelHopping; }

    // 回调设置
    void setPacketCallback(PacketCallback callback);
    void setNetworkCallback(NetworkFoundCallback callback);
    void setNetworkFoundCallback(NetworkFoundCallback callback);

    // 网络扫描
    void startScan();
    void stopScan();
    bool isScanning() const { return scanning; }
    int getNetworkCount() const { return networkCount; }
    const WiFiNetwork* getNetwork(int index) const;
    const WiFiNetwork* findNetwork(const uint8_t* bssid) const;
    void clearNetworks();

    // 统计信息
    uint32_t getTotalPackets() const { return totalPackets; }
    uint32_t getManagementPackets() const { return mgmtPackets; }
    uint32_t getControlPackets() const { return ctrlPackets; }
    uint32_t getDataPackets() const { return dataPackets; }
    uint32_t getUnknownPackets() const { return unknownPackets; }
    void resetStatistics();

    // 过滤器设置
    void setFilterFrameType(uint8_t frameType, bool enable);
    void setFilterBSSID(const uint8_t* bssid, bool filter);
    void setFilterChannel(uint8_t channel);
    void clearFilters();

    // 获取信号强度
    int8_t getRSSI() const { return lastRSSI; }

    // 静态回调函数 (供 ESP-IDF 调用)
    static void IRAM_ATTR wifiSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type);

private:
    bool running;
    bool channelHopping;
    bool scanning;
    uint8_t currentChannel;
    uint8_t targetChannel;
    
    // 统计数据
    volatile uint32_t totalPackets;
    volatile uint32_t mgmtPackets;
    volatile uint32_t ctrlPackets;
    volatile uint32_t dataPackets;
    volatile uint32_t unknownPackets;
    volatile int8_t lastRSSI;

    // 网络列表
    static const int MAX_NETWORKS = 64;
    WiFiNetwork networks[MAX_NETWORKS];
    int networkCount;

    // 回调函数
    PacketCallback packetCallback;
    NetworkFoundCallback networkCallback;
    NetworkFoundCallback networkFoundCallback;

    // 过滤器
    uint8_t filterFrameTypes;
    uint8_t filterBSSID[6];
    bool bssidFilterEnabled;
    uint8_t channelFilter;

    // 任务句柄
    TaskHandle_t channelHopTaskHandle;
    TaskHandle_t scanTaskHandle;

    // 内部方法
    void processPacket(const uint8_t* packet, uint16_t len, int8_t rssi, uint8_t channel);
    void parse80211Header(const uint8_t* packet, uint16_t len, PacketInfo* info);
    void updateNetworkList(const PacketInfo* info, const uint8_t* packet, uint16_t len);
    int findOrCreateNetwork(const uint8_t* bssid);
    void extractSSID(const uint8_t* packet, uint16_t len, char* ssid, size_t maxLen);
    uint8_t extractChannel(const uint8_t* packet, uint16_t len);
    WiFiAuthMode detectAuthMode(const uint8_t* packet, uint16_t len);

    // 静态实例指针 (用于回调)
    static WiFiSniffer* instance;

    // 任务函数
    static void channelHopTask(void* parameter);
    static void scanTask(void* parameter);
};

// ==================== 全局实例 ====================
extern WiFiSniffer Sniffer;

// ==================== 辅助函数 ====================
const char* getFrameTypeString(uint8_t type, uint8_t subtype);
const char* getAuthModeString(WiFiAuthMode mode);
void macToString(const uint8_t* mac, char* str, size_t len);
bool parseMAC(const char* str, uint8_t* mac);
uint8_t getChannelFromFrequency(uint16_t freq);
uint16_t getFrequencyFromChannel(uint8_t channel);

#endif // WIFI_SNIFFER_H
