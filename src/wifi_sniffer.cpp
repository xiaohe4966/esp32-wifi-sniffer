/**
 * @file wifi_sniffer.cpp
 * @brief WiFi Sniffer Core Implementation
 */

#include "wifi_sniffer.h"
#include "packet_parser.h"

// ==================== 静态成员定义 ====================
WiFiSniffer* WiFiSniffer::instance = nullptr;

// ==================== 全局实例 ====================
WiFiSniffer Sniffer;

// ==================== 构造函数/析构函数 ====================
WiFiSniffer::WiFiSniffer() 
    : running(false)
    , channelHopping(false)
    , scanning(false)
    , currentChannel(1)
    , targetChannel(1)
    , totalPackets(0)
    , mgmtPackets(0)
    , ctrlPackets(0)
    , dataPackets(0)
    , unknownPackets(0)
    , lastRSSI(0)
    , networkCount(0)
    , packetCallback(nullptr)
    , networkCallback(nullptr)
    , filterFrameTypes(0xFF)
    , bssidFilterEnabled(false)
    , channelFilter(0)
    , channelHopTaskHandle(nullptr)
    , scanTaskHandle(nullptr) {
    
    memset(networks, 0, sizeof(networks));
    memset(filterBSSID, 0, sizeof(filterBSSID));
    instance = this;
}

WiFiSniffer::~WiFiSniffer() {
    end();
}

// ==================== 初始化 ====================
bool WiFiSniffer::begin() {
    LOG_INFO("Initializing WiFi sniffer...");
    
    // 设置 WiFi 为 STA 模式
    WiFi.mode(WIFI_MODE_STA);
    
    // 初始化 promiscuous mode
    esp_err_t err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) {
        LOG_ERROR("Failed to set promiscuous mode: %d", err);
        return false;
    }
    
    // 设置回调函数
    err = esp_wifi_set_promiscuous_rx_cb(&WiFiSniffer::wifiSnifferCallback);
    if (err != ESP_OK) {
        LOG_ERROR("Failed to set promiscuous callback: %d", err);
        return false;
    }
    
    // 设置 promiscuous filter
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL
    };
    esp_wifi_set_promiscuous_filter(&filter);
    
    LOG_INFO("WiFi sniffer initialized successfully");
    return true;
}

void WiFiSniffer::end() {
    stopSniffing();
    stopChannelHopping();
    stopScan();
    
    esp_wifi_set_promiscuous(false);
    LOG_INFO("WiFi sniffer stopped");
}

// ==================== 抓包控制 ====================
bool WiFiSniffer::startSniffing() {
    if (running) {
        LOG_WARN("Sniffer already running");
        return true;
    }
    
    running = true;
    snifferRunning = true;
    currentMode = MODE_SNIFFING;
    
    LOG_INFO("Sniffer started on channel %d", currentChannel);
    return true;
}

void WiFiSniffer::stopSniffing() {
    if (!running) return;
    
    running = false;
    snifferRunning = false;
    
    if (currentMode == MODE_SNIFFING) {
        currentMode = MODE_IDLE;
    }
    
    LOG_INFO("Sniffer stopped");
}

// ==================== 信道控制 ====================
void WiFiSniffer::setChannel(uint8_t channel) {
    if (channel < 1 || channel > 14) {
        // 5GHz 信道
        if (channel < 36 || channel > 165) {
            LOG_ERROR("Invalid channel: %d", channel);
            return;
        }
    }
    
    currentChannel = channel;
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    
    LOG_DEBUG("Channel set to %d", channel);
}

void WiFiSniffer::startChannelHopping() {
    if (channelHopping) return;
    
    channelHopping = true;
    ::channelHopping = true;
    
    xTaskCreatePinnedToCore(
        channelHopTask,
        "ChannelHop",
        2048,
        this,
        1,
        &channelHopTaskHandle,
        0
    );
    
    LOG_INFO("Channel hopping started");
}

void WiFiSniffer::stopChannelHopping() {
    if (!channelHopping) return;
    
    channelHopping = false;
    ::channelHopping = false;
    
    if (channelHopTaskHandle) {
        vTaskDelete(channelHopTaskHandle);
        channelHopTaskHandle = nullptr;
    }
    
    LOG_INFO("Channel hopping stopped");
}

// ==================== 回调设置 ====================
void WiFiSniffer::setPacketCallback(PacketCallback callback) {
    packetCallback = callback;
}

void WiFiSniffer::setNetworkFoundCallback(NetworkFoundCallback callback) {
    networkCallback = callback;
}

// ==================== 网络扫描 ====================
void WiFiSniffer::startScan() {
    if (scanning) return;
    
    scanning = true;
    currentMode = MODE_SCANNING;
    clearNetworks();
    
    // 启动信道跳变
    startChannelHopping();
    
    LOG_INFO("Network scan started");
}

void WiFiSniffer::stopScan() {
    if (!scanning) return;
    
    scanning = false;
    stopChannelHopping();
    
    if (currentMode == MODE_SCANNING) {
        currentMode = MODE_IDLE;
    }
    
    LOG_INFO("Network scan stopped, found %d networks", networkCount);
}

const WiFiNetwork* WiFiSniffer::getNetwork(int index) const {
    if (index < 0 || index >= networkCount) return nullptr;
    return &networks[index];
}

const WiFiNetwork* WiFiSniffer::findNetwork(const uint8_t* bssid) const {
    for (int i = 0; i < networkCount; i++) {
        if (memcmp(networks[i].bssid, bssid, 6) == 0) {
            return &networks[i];
        }
    }
    return nullptr;
}

void WiFiSniffer::clearNetworks() {
    memset(networks, 0, sizeof(networks));
    networkCount = 0;
}

// ==================== 统计 ====================
void WiFiSniffer::resetStatistics() {
    totalPackets = 0;
    mgmtPackets = 0;
    ctrlPackets = 0;
    dataPackets = 0;
    unknownPackets = 0;
}

// ==================== 过滤器 ====================
void WiFiSniffer::setFilterFrameType(uint8_t frameType, bool enable) {
    if (enable) {
        filterFrameTypes |= (1 << frameType);
    } else {
        filterFrameTypes &= ~(1 << frameType);
    }
}

void WiFiSniffer::setFilterBSSID(const uint8_t* bssid, bool filter) {
    bssidFilterEnabled = filter;
    if (filter) {
        memcpy(filterBSSID, bssid, 6);
    }
}

void WiFiSniffer::setFilterChannel(uint8_t channel) {
    channelFilter = channel;
}

void WiFiSniffer::clearFilters() {
    filterFrameTypes = 0xFF;
    bssidFilterEnabled = false;
    channelFilter = 0;
}

// ==================== 回调处理 (ISR) ====================
void IRAM_ATTR WiFiSniffer::wifiSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!instance || !instance->running) return;
    
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    
    // 获取元数据
    int8_t rssi = pkt->rx_ctrl.rssi;
    uint8_t channel = pkt->rx_ctrl.channel;
    
    instance->lastRSSI = rssi;
    
    // 处理数据包
    instance->processPacket(pkt->payload, pkt->rx_ctrl.sig_len, rssi, channel);
}

// ==================== 数据包处理 ====================
void WiFiSniffer::processPacket(const uint8_t* packet, uint16_t len, int8_t rssi, uint8_t channel) {
    if (len < 24) return;  // 太小的包
    
    // 解析头部
    PacketInfo info;
    parse80211Header(packet, len, &info);
    
    info.timestamp = millis();
    info.channel = channel;
    info.rssi = rssi;
    info.length = len;
    
    // 应用过滤器
    if (!(filterFrameTypes & (1 << info.frameType))) return;
    if (channelFilter && channel != channelFilter) return;
    if (bssidFilterEnabled && memcmp(info.bssid, filterBSSID, 6) != 0) return;
    
    // 更新统计
    totalPackets++;
    switch (info.frameType) {
        case FRAME_TYPE_MANAGEMENT:
            mgmtPackets++;
            break;
        case FRAME_TYPE_CONTROL:
            ctrlPackets++;
            break;
        case FRAME_TYPE_DATA:
            dataPackets++;
            break;
        default:
            unknownPackets++;
            break;
    }
    
    // 更新网络列表
    if (scanning) {
        updateNetworkList(&info, packet, len);
    }
    
    // 调用回调
    if (packetCallback) {
        packetCallback(packet, len, &info);
    }
}

void WiFiSniffer::parse80211Header(const uint8_t* packet, uint16_t len, PacketInfo* info) {
    memset(info, 0, sizeof(PacketInfo));
    
    // Frame Control
    uint16_t fc = packet[0] | (packet[1] << 8);
    info->frameType = (fc >> 2) & 0x03;
    info->frameSubtype = (fc >> 4) & 0x0F;
    
    // 解析地址 (根据 ToDS/FromDS)
    bool toDS = (fc >> 8) & 0x01;
    bool fromDS = (fc >> 9) & 0x01;
    
    // 复制地址
    memcpy(info->destination, packet + 4, 6);
    memcpy(info->source, packet + 10, 6);
    memcpy(info->bssid, packet + 16, 6);
    
    // 序列号
    info->sequence = (packet[22] | (packet[23] << 8)) >> 4;
}

void WiFiSniffer::updateNetworkList(const PacketInfo* info, const uint8_t* packet, uint16_t len) {
    // 只处理 Beacon 和 Probe Response
    if (info->frameType != FRAME_TYPE_MANAGEMENT) return;
    if (info->frameSubtype != MGMT_SUBTYPE_BEACON && 
        info->frameSubtype != MGMT_SUBTYPE_PROBE_RESP) {
        return;
    }
    
    // 查找或创建网络
    int index = findOrCreateNetwork(info->bssid);
    if (index < 0) return;
    
    WiFiNetwork* net = &networks[index];
    
    // 更新信息
    net->rssi = info->rssi;
    net->channel = info->channel;
    net->lastSeen = millis();
    net->packetCount++;
    
    // 提取 SSID
    if (net->ssid[0] == '\0') {
        extractSSID(packet, len, net->ssid, sizeof(net->ssid));
    }
    
    // 检测加密类型
    if (net->authMode == AUTH_UNKNOWN) {
        net->authMode = detectAuthMode(packet, len);
    }
    
    // 通知新网络
    if (index == networkCount - 1 && networkCallback) {
        networkCallback(net);
    }
}

int WiFiSniffer::findOrCreateNetwork(const uint8_t* bssid) {
    // 查找现有网络
    for (int i = 0; i < networkCount; i++) {
        if (memcmp(networks[i].bssid, bssid, 6) == 0) {
            return i;
        }
    }
    
    // 创建新网络
    if (networkCount >= MAX_NETWORKS) return -1;
    
    int index = networkCount++;
    memset(&networks[index], 0, sizeof(WiFiNetwork));
    memcpy(networks[index].bssid, bssid, 6);
    networks[index].authMode = AUTH_UNKNOWN;
    
    return index;
}

void WiFiSniffer::extractSSID(const uint8_t* packet, uint16_t len, char* ssid, size_t maxLen) {
    ssid[0] = '\0';
    
    // 跳过 MAC 头部 (24 字节) 和固定参数 (12 字节 for Beacon)
    uint16_t offset = 36;
    
    while (offset + 2 < len) {
        uint8_t id = packet[offset];
        uint8_t ieLen = packet[offset + 1];
        
        if (id == IE_SSID && ieLen > 0 && ieLen <= 32) {
            size_t copyLen = min((size_t)ieLen, maxLen - 1);
            memcpy(ssid, packet + offset + 2, copyLen);
            ssid[copyLen] = '\0';
            return;
        }
        
        offset += 2 + ieLen;
    }
}

WiFiAuthMode WiFiSniffer::detectAuthMode(const uint8_t* packet, uint16_t len) {
    // 检查 Capability Info 中的 Privacy bit
    uint16_t capInfo = packet[34] | (packet[35] << 8);
    bool privacy = capInfo & 0x0010;
    
    if (!privacy) return AUTH_OPEN;
    
    // 查找 RSN IE (WPA2)
    uint16_t offset = 36;
    bool hasRSN = false;
    bool hasWPA = false;
    
    while (offset + 2 < len) {
        uint8_t id = packet[offset];
        uint8_t ieLen = packet[offset + 1];
        
        if (id == IE_RSN_INFORMATION) {
            hasRSN = true;
        } else if (id == IE_VENDOR_SPECIFIC) {
            // 检查 WPA OUI (00:50:F2:01)
            if (ieLen >= 4 && 
                packet[offset + 2] == 0x00 &&
                packet[offset + 3] == 0x50 &&
                packet[offset + 4] == 0xF2 &&
                packet[offset + 5] == 0x01) {
                hasWPA = true;
            }
        }
        
        offset += 2 + ieLen;
    }
    
    if (hasRSN && hasWPA) return AUTH_WPA_WPA2_PSK;
    if (hasRSN) return AUTH_WPA2_PSK;
    if (hasWPA) return AUTH_WPA_PSK;
    
    // 假设 WEP
    return AUTH_WEP;
}

// ==================== 任务函数 ====================
void WiFiSniffer::channelHopTask(void* parameter) {
    WiFiSniffer* sniffer = (WiFiSniffer*)parameter;
    
    const uint8_t channels[] = {1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10};
    const int numChannels = sizeof(channels) / sizeof(channels[0]);
    int currentIndex = 0;
    
    while (sniffer->channelHopping) {
        sniffer->setChannel(channels[currentIndex]);
        currentIndex = (currentIndex + 1) % numChannels;
        vTaskDelay(pdMS_TO_TICKS(CHANNEL_HOP_INTERVAL));
    }
    
    vTaskDelete(NULL);
}

void WiFiSniffer::scanTask(void* parameter) {
    // 扫描任务逻辑
    vTaskDelete(NULL);
}

// ==================== 辅助函数 ====================
const char* getFrameTypeString(uint8_t type, uint8_t subtype) {
    switch (type) {
        case FRAME_TYPE_MANAGEMENT:
            switch (subtype) {
                case MGMT_SUBTYPE_ASSOC_REQ: return "AssocReq";
                case MGMT_SUBTYPE_ASSOC_RESP: return "AssocResp";
                case MGMT_SUBTYPE_REASSOC_REQ: return "ReassocReq";
                case MGMT_SUBTYPE_REASSOC_RESP: return "ReassocResp";
                case MGMT_SUBTYPE_PROBE_REQ: return "ProbeReq";
                case MGMT_SUBTYPE_PROBE_RESP: return "ProbeResp";
                case MGMT_SUBTYPE_BEACON: return "Beacon";
                case MGMT_SUBTYPE_ATIM: return "ATIM";
                case MGMT_SUBTYPE_DISASSOC: return "Disassoc";
                case MGMT_SUBTYPE_AUTH: return "Auth";
                case MGMT_SUBTYPE_DEAUTH: return "Deauth";
                case MGMT_SUBTYPE_ACTION: return "Action";
                default: return "Mgmt-?";
            }
        case FRAME_TYPE_CONTROL:
            switch (subtype) {
                case CTRL_SUBTYPE_BLOCK_ACK_REQ: return "BlockAckReq";
                case CTRL_SUBTYPE_BLOCK_ACK: return "BlockAck";
                case CTRL_SUBTYPE_PS_POLL: return "PsPoll";
                case CTRL_SUBTYPE_RTS: return "RTS";
                case CTRL_SUBTYPE_CTS: return "CTS";
                case CTRL_SUBTYPE_ACK: return "ACK";
                default: return "Ctrl-?";
            }
        case FRAME_TYPE_DATA:
            switch (subtype) {
                case DATA_SUBTYPE_DATA: return "Data";
                case DATA_SUBTYPE_NULL: return "Null";
                case DATA_SUBTYPE_QOS_DATA: return "QoSData";
                case DATA_SUBTYPE_QOS_NULL: return "QoSNull";
                default: return "Data-?";
            }
        default:
            return "Unknown";
    }
}

const char* getAuthModeString(WiFiAuthMode mode) {
    switch (mode) {
        case AUTH_OPEN: return "OPEN";
        case AUTH_WEP: return "WEP";
        case AUTH_WPA_PSK: return "WPA";
        case AUTH_WPA2_PSK: return "WPA2";
        case AUTH_WPA_WPA2_PSK: return "WPA/WPA2";
        case AUTH_WPA2_ENTERPRISE: return "WPA2-Ent";
        case AUTH_WPA3_PSK: return "WPA3";
        case AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3";
        default: return "Unknown";
    }
}

void macToString(const uint8_t* mac, char* str, size_t len) {
    snprintf(str, len, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool parseMAC(const char* str, uint8_t* mac) {
    int values[6];
    if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) == 6) {
        for (int i = 0; i < 6; i++) {
            mac[i] = (uint8_t)values[i];
        }
        return true;
    }
    return false;
}
