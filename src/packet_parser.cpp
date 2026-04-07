/**
 * @file packet_parser.cpp
 * @brief 802.11 Packet Parser Implementation
 */

#include "packet_parser.h"
#include "wifi_sniffer.h"

// ==================== 全局实例 ====================
PacketParser Parser;

// ==================== 构造函数/析构函数 ====================
PacketParser::PacketParser() {
}

PacketParser::~PacketParser() {
}

// ==================== 帧解析 ====================
bool PacketParser::parseFrame(const uint8_t* packet, uint16_t len, PacketInfo* info) {
    if (len < 24) return false;
    
    memset(info, 0, sizeof(PacketInfo));
    
    // 解析 Frame Control
    uint16_t fc = packet[0] | (packet[1] << 8);
    info->frameType = (fc >> 2) & 0x03;
    info->frameSubtype = (fc >> 4) & 0x0F;
    
    // 解析地址
    getDestination(packet, info->destination);
    getSource(packet, info->source);
    getBSSID(packet, info->bssid);
    
    // 序列号
    info->sequence = getSequenceNumber(packet);
    info->length = len;
    
    return true;
}

// ==================== 帧类型获取 ====================
uint8_t PacketParser::getFrameType(const uint8_t* packet) {
    return (packet[0] >> 2) & 0x03;
}

uint8_t PacketParser::getFrameSubtype(const uint8_t* packet) {
    return (packet[0] >> 4) & 0x0F;
}

bool PacketParser::isToDS(const uint8_t* packet) {
    return (packet[1] >> 0) & 0x01;
}

bool PacketParser::isFromDS(const uint8_t* packet) {
    return (packet[1] >> 1) & 0x01;
}

bool PacketParser::isProtected(const uint8_t* packet) {
    return (packet[1] >> 6) & 0x01;
}

// ==================== 地址获取 ====================
void PacketParser::getDestination(const uint8_t* packet, uint8_t* addr) {
    memcpy(addr, packet + 4, 6);
}

void PacketParser::getSource(const uint8_t* packet, uint8_t* addr) {
    bool toDS = isToDS(packet);
    bool fromDS = isFromDS(packet);
    
    if (!toDS && !fromDS) {
        // IBSS 或管理帧
        memcpy(addr, packet + 10, 6);
    } else if (!toDS && fromDS) {
        // From AP
        memcpy(addr, packet + 10, 6);
    } else if (toDS && !fromDS) {
        // To AP
        memcpy(addr, packet + 16, 6);
    } else {
        // WDS
        memcpy(addr, packet + 24, 6);
    }
}

void PacketParser::getBSSID(const uint8_t* packet, uint8_t* addr) {
    bool toDS = isToDS(packet);
    bool fromDS = isFromDS(packet);
    
    if (!toDS && !fromDS) {
        memcpy(addr, packet + 16, 6);
    } else if (!toDS && fromDS) {
        memcpy(addr, packet + 4, 6);
    } else if (toDS && !fromDS) {
        memcpy(addr, packet + 4, 6);
    } else {
        memcpy(addr, packet + 16, 6);
    }
}

void PacketParser::getTransmitter(const uint8_t* packet, uint8_t* addr) {
    memcpy(addr, packet + 10, 6);
}

void PacketParser::getReceiver(const uint8_t* packet, uint8_t* addr) {
    memcpy(addr, packet + 4, 6);
}

// ==================== 管理帧解析 ====================
bool PacketParser::parseBeacon(const uint8_t* packet, uint16_t len, 
                                char* ssid, size_t ssidLen,
                                uint8_t* channel, WiFiAuthMode* authMode) {
    if (len < 36) return false;
    
    uint8_t subtype = getFrameSubtype(packet);
    if (subtype != MGMT_SUBTYPE_BEACON && subtype != MGMT_SUBTYPE_PROBE_RESP) {
        return false;
    }
    
    // 跳过 MAC 头部 (24) + 固定参数 (12)
    uint16_t iesOffset = 36;
    uint16_t iesLen = len - iesOffset;
    
    return parseIEs(packet + iesOffset, iesLen, 0, ssid, ssidLen, channel, authMode);
}

bool PacketParser::parseProbeResponse(const uint8_t* packet, uint16_t len, 
                                       char* ssid, size_t ssidLen) {
    return parseBeacon(packet, len, ssid, ssidLen, nullptr, nullptr);
}

bool PacketParser::parseProbeRequest(const uint8_t* packet, uint16_t len, 
                                      char* ssid, size_t ssidLen) {
    if (len < 24) return false;
    
    uint8_t subtype = getFrameSubtype(packet);
    if (subtype != MGMT_SUBTYPE_PROBE_REQ) return false;
    
    // Probe Request 没有固定参数
    uint16_t iesOffset = 24;
    uint16_t iesLen = len - iesOffset;
    
    WiFiAuthMode mode;
    return parseIEs(packet + iesOffset, iesLen, 0, ssid, ssidLen, nullptr, &mode);
}

bool PacketParser::parseAuthentication(const uint8_t* packet, uint16_t len,
                                        uint16_t* algorithm, uint16_t* seq, 
                                        uint16_t* status) {
    if (len < 30) return false;
    
    uint8_t subtype = getFrameSubtype(packet);
    if (subtype != MGMT_SUBTYPE_AUTH) return false;
    
    if (algorithm) *algorithm = packet[24] | (packet[25] << 8);
    if (seq) *seq = packet[26] | (packet[27] << 8);
    if (status) *status = packet[28] | (packet[29] << 8);
    
    return true;
}

bool PacketParser::parseDeauthentication(const uint8_t* packet, uint16_t len,
                                          uint16_t* reason) {
    if (len < 26) return false;
    
    uint8_t subtype = getFrameSubtype(packet);
    if (subtype != MGMT_SUBTYPE_DEAUTH) return false;
    
    if (reason) *reason = packet[24] | (packet[25] << 8);
    
    return true;
}

// ==================== EAPOL 解析 ====================
bool PacketParser::isEAPOL(const uint8_t* packet, uint16_t len) {
    if (len < 28) return false;
    
    // 检查 LLC/SNAP 头部
    // DSAP = 0xAA, SSAP = 0xAA, Control = 0x03
    if (packet[24] != 0xAA || packet[25] != 0xAA || packet[26] != 0x03) {
        return false;
    }
    
    // OUI = 00:00:00
    if (packet[27] != 0x00 || packet[28] != 0x00 || packet[29] != 0x00) {
        return false;
    }
    
    // Type = 0x888E (EAPOL)
    uint16_t type = packet[30] | (packet[31] << 8);
    return type == 0x888E;
}

bool PacketParser::parseEAPOL(const uint8_t* packet, uint16_t len, 
                               EAPOLKeyHeader* keyInfo) {
    if (!isEAPOL(packet, len)) return false;
    
    // LLC/SNAP 头部 = 8 字节
    uint16_t eapolOffset = 32;
    if (len < eapolOffset + 4) return false;
    
    // 检查 EAPOL 版本和类型
    if (packet[eapolOffset] != EAPOL_VERSION) return false;
    if (packet[eapolOffset + 1] != EAPOL_KEY_TYPE) return false;
    
    // 解析 Key 信息
    if (len < eapolOffset + sizeof(EAPOLKeyHeader)) return false;
    
    uint8_t* key = (uint8_t*)keyInfo;
    memcpy(key, packet + eapolOffset + 4, sizeof(EAPOLKeyHeader));
    
    // 字节序转换
    keyInfo->keyInfo = (packet[eapolOffset + 5] << 8) | packet[eapolOffset + 4];
    keyInfo->keyLength = (packet[eapolOffset + 7] << 8) | packet[eapolOffset + 6];
    keyInfo->keyDataLength = (packet[eapolOffset + 97] << 8) | packet[eapolOffset + 96];
    
    return true;
}

bool PacketParser::isHandshakeMessage(const uint8_t* packet, uint16_t len, int* msgNumber) {
    EAPOLKeyHeader key;
    if (!parseEAPOL(packet, len, &key)) return false;
    
    int msg = findHandshakeMessage(&key);
    if (msgNumber) *msgNumber = msg;
    
    return msg > 0;
}

int PacketParser::findHandshakeMessage(const EAPOLKeyHeader* key) {
    uint16_t keyInfo = key->keyInfo;
    
    bool keyType = keyInfo & KEY_INFO_KEY_TYPE;
    bool install = keyInfo & KEY_INFO_INSTALL;
    bool ack = keyInfo & KEY_INFO_ACK;
    bool mic = keyInfo & KEY_INFO_MIC;
    bool secure = keyInfo & KEY_INFO_SECURE;
    
    // Message 1: Key Type=1, Install=0, ACK=1, MIC=0, Secure=0
    if (keyType && !install && ack && !mic && !secure) return 1;
    
    // Message 2: Key Type=1, Install=0, ACK=0, MIC=1, Secure=0
    if (keyType && !install && !ack && mic && !secure) return 2;
    
    // Message 3: Key Type=1, Install=1, ACK=1, MIC=1, Secure=1
    if (keyType && install && ack && mic && secure) return 3;
    
    // Message 4: Key Type=1, Install=0, ACK=0, MIC=1, Secure=1
    if (keyType && !install && !ack && mic && secure) return 4;
    
    return 0;
}

// ==================== 信息元素解析 ====================
const uint8_t* PacketParser::findIE(const uint8_t* ies, uint16_t iesLen, uint8_t ieId) {
    uint16_t offset = 0;
    
    while (offset + 2 < iesLen) {
        uint8_t id = ies[offset];
        uint8_t len = ies[offset + 1];
        
        if (id == ieId) {
            return ies + offset;
        }
        
        offset += 2 + len;
    }
    
    return nullptr;
}

bool PacketParser::getSSID(const uint8_t* ies, uint16_t iesLen, char* ssid, size_t maxLen) {
    const uint8_t* ie = findIE(ies, iesLen, IE_SSID);
    if (!ie || ie[1] == 0 || ie[1] > 32) {
        ssid[0] = '\0';
        return false;
    }
    
    uint8_t len = ie[1];
    size_t copyLen = min((size_t)len, maxLen - 1);
    memcpy(ssid, ie + 2, copyLen);
    ssid[copyLen] = '\0';
    
    return true;
}

bool PacketParser::getChannel(const uint8_t* ies, uint16_t iesLen, uint8_t* channel) {
    const uint8_t* ie = findIE(ies, iesLen, IE_DS_PARAMETER_SET);
    if (!ie || ie[1] != 1) return false;
    
    *channel = ie[2];
    return true;
}

bool PacketParser::getRSNInfo(const uint8_t* ies, uint16_t iesLen, WiFiAuthMode* authMode) {
    const uint8_t* rsn = findIE(ies, iesLen, IE_RSN_INFORMATION);
    const uint8_t* wpa = nullptr;
    
    // 查找 WPA (Vendor Specific)
    uint16_t offset = 0;
    while (offset + 2 < iesLen) {
        uint8_t id = ies[offset];
        uint8_t len = ies[offset + 1];
        
        if (id == IE_VENDOR_SPECIFIC && len >= 4) {
            if (ies[offset + 2] == 0x00 && ies[offset + 3] == 0x50 &&
                ies[offset + 4] == 0xF2 && ies[offset + 5] == 0x01) {
                wpa = ies + offset;
                break;
            }
        }
        
        offset += 2 + len;
    }
    
    if (rsn && wpa) {
        *authMode = AUTH_WPA_WPA2_PSK;
        return true;
    } else if (rsn) {
        *authMode = AUTH_WPA2_PSK;
        return true;
    } else if (wpa) {
        *authMode = AUTH_WPA_PSK;
        return true;
    }
    
    return false;
}

// ==================== 辅助函数 ====================
uint16_t PacketParser::getSequenceNumber(const uint8_t* packet) {
    return (packet[22] | (packet[23] << 8)) >> 4;
}

uint16_t PacketParser::getFragmentNumber(const uint8_t* packet) {
    return packet[22] & 0x0F;
}

uint32_t PacketParser::getFrameLength(const uint8_t* packet, uint16_t len) {
    return len;
}

// ==================== 打印函数 ====================
void PacketParser::printFrameInfo(const PacketInfo* info) {
    char src[18], dst[18], bssid[18];
    macToString(info->source, src, sizeof(src));
    macToString(info->destination, dst, sizeof(dst));
    macToString(info->bssid, bssid, sizeof(bssid));
    
    LOG_INFO("[%s] %s -> %s (BSSID: %s) CH:%d RSSI:%d SEQ:%d",
             getFrameTypeString(info->frameType, info->frameSubtype),
             src, dst, bssid, info->channel, info->rssi, info->sequence);
}

void PacketParser::printHexDump(const uint8_t* data, uint16_t len, uint16_t offset) {
    for (uint16_t i = 0; i < len; i += 16) {
        Serial.printf("%04X: ", offset + i);
        
        // 十六进制
        for (uint16_t j = 0; j < 16; j++) {
            if (i + j < len) {
                Serial.printf("%02X ", data[i + j]);
            } else {
                Serial.print("   ");
            }
        }
        
        Serial.print(" ");
        
        // ASCII
        for (uint16_t j = 0; j < 16; j++) {
            if (i + j < len) {
                char c = data[i + j];
                Serial.print((c >= 32 && c < 127) ? c : '.');
            }
        }
        
        Serial.println();
    }
}

// ==================== 内部解析函数 ====================
bool PacketParser::parseIEs(const uint8_t* ies, uint16_t iesLen,
                             uint16_t fixedParamsLen,
                             char* ssid, size_t ssidLen,
                             uint8_t* channel, WiFiAuthMode* authMode) {
    bool success = false;
    
    if (ssid && ssidLen > 0) {
        success |= getSSID(ies, iesLen, ssid, ssidLen);
    }
    
    if (channel) {
        success |= getChannel(ies, iesLen, channel);
    }
    
    if (authMode) {
        success |= getRSNInfo(ies, iesLen, authMode);
    }
    
    return success;
}

WiFiAuthMode PacketParser::detectEncryption(const uint8_t* ies, uint16_t iesLen) {
    WiFiAuthMode mode;
    if (getRSNInfo(ies, iesLen, &mode)) {
        return mode;
    }
    return AUTH_OPEN;
}
