/**
 * @file handshake.cpp
 * @brief WPA/WPA2 Handshake Capture Implementation
 */

#include "handshake.h"
#include "wifi_sniffer.h"
#include "sd_manager.h"

// ==================== 全局实例 ====================
HandshakeCapture Handshake;

// ==================== 构造函数/析构函数 ====================
HandshakeCapture::HandshakeCapture()
    : targetSet(false)
    , totalEAPOL(0)
    , handshakeAttempts(0)
    , autoCapture(false) {
    memset(&handshake, 0, sizeof(handshake));
    memset(targetBSSID, 0, sizeof(targetBSSID));
    memset(targetStation, 0, sizeof(targetStation));
}

HandshakeCapture::~HandshakeCapture() {
    end();
}

// ==================== 初始化 ====================
bool HandshakeCapture::begin() {
    LOG_INFO("Initializing handshake capture...");
    resetHandshake();
    return true;
}

void HandshakeCapture::end() {
    // 清理
}

// ==================== 目标设置 ====================
void HandshakeCapture::setTargetBSSID(const uint8_t* bssid) {
    memcpy(targetBSSID, bssid, 6);
    targetSet = true;
    hasBSSID = true;
    
    char bssidStr[18];
    macToString(bssid, bssidStr, sizeof(bssidStr));
    LOG_INFO("Target BSSID set: %s", bssidStr);
}

void HandshakeCapture::setTargetStation(const uint8_t* station) {
    memcpy(targetStation, station, 6);
    targetSet = true;
    hasStation = true;
    
    char staStr[18];
    macToString(station, staStr, sizeof(staStr));
    LOG_INFO("Target station set: %s", staStr);
}

void HandshakeCapture::clearTarget() {
    targetSet = false;
    hasBSSID = false;
    hasStation = false;
    memset(targetBSSID, 0, 6);
    memset(targetStation, 0, 6);
}

void HandshakeCapture::getTargetBSSID(uint8_t* bssid) const {
    memcpy(bssid, targetBSSID, 6);
}

void HandshakeCapture::getTargetStation(uint8_t* station) const {
    memcpy(station, targetStation, 6);
}

// ==================== 数据包处理 ====================
void HandshakeCapture::processPacket(const uint8_t* packet, uint16_t len, 
                                      const PacketInfo* info) {
    // 检查是否是 EAPOL 帧
    if (!Parser.isEAPOL(packet, len)) return;
    
    totalEAPOL++;
    processEAPOL(packet, len, info);
}

void HandshakeCapture::processEAPOL(const uint8_t* packet, uint16_t len, 
                                     const PacketInfo* info) {
    EAPOLKeyHeader key;
    if (!Parser.parseEAPOL(packet, len, &key)) return;
    
    // 确定握手消息类型
    int msgNum = findHandshakeMessage(&key);
    if (msgNum == 0) return;
    
    // 获取源和目标地址
    uint8_t src[6], dst[6];
    Parser.getSource(packet, src);
    Parser.getDestination(packet, dst);
    
    // 检查是否匹配目标
    if (targetSet) {
        bool matchBSSID = memcmp(info->bssid, targetBSSID, 6) == 0;
        bool matchStation = !hasStation || 
                           (memcmp(src, targetStation, 6) == 0) ||
                           (memcmp(dst, targetStation, 6) == 0);
        
        if (!matchBSSID || !matchStation) return;
    }
    
    // 处理消息
    switch (msgNum) {
        case 1:
            processMessage1(packet, len, &key);
            break;
        case 2:
            processMessage2(packet, len, &key, src, dst);
            break;
        case 3:
            processMessage3(packet, len, &key);
            break;
        case 4:
            processMessage4(packet, len, &key);
            break;
    }
    
    // 更新模式
    if (currentMode == MODE_HANDSHAKE_CAPTURE) {
        if (isHandshakeComplete()) {
            LOG_INFO("Handshake capture complete!");
            currentMode = MODE_IDLE;
        }
    }
}

void HandshakeCapture::processMessage1(const uint8_t* eapol, uint16_t len, 
                                        const EAPOLKeyHeader* key) {
    // Message 1 来自 AP
    PacketParser::getBSSID(eapol, handshake.bssid);
    memcpy(handshake.msg1Anonce, key->nonce, 32);
    handshake.msg1KeyInfo = key->keyInfo;
    memcpy(handshake.msg1ReplayCounter, key->replayCounter, 8);
    handshake.msg1Timestamp = millis();
    handshake.hasMsg1 = true;
    
    if (handshake.state < HS_MSG1_RECEIVED) {
        handshake.state = HS_MSG1_RECEIVED;
        handshake.lastUpdate = millis();
    }
    
    LOG_DEBUG("Handshake Message 1 received");
}

void HandshakeCapture::processMessage2(const uint8_t* eapol, uint16_t len,
                                        const EAPOLKeyHeader* key,
                                        const uint8_t* src, const uint8_t* dst) {
    // Message 2 来自 STA
    if (!handshake.hasMsg1) return;
    
    // 验证 Replay Counter
    if (!checkReplayCounter(key->replayCounter, handshake.msg1ReplayCounter)) return;
    
    memcpy(handshake.station, src, 6);
    memcpy(handshake.msg2Snonce, key->nonce, 32);
    memcpy(handshake.msg2Mic, key->mic, 16);
    handshake.msg2KeyInfo = key->keyInfo;
    memcpy(handshake.msg2ReplayCounter, key->replayCounter, 8);
    handshake.msg2Timestamp = millis();
    copyEAPOLFrame(eapol, len, handshake.msg2Eapol, &handshake.msg2EapolLen);
    handshake.hasMsg2 = true;
    
    if (handshake.state < HS_MSG2_RECEIVED) {
        handshake.state = HS_MSG2_RECEIVED;
        handshake.lastUpdate = millis();
    }
    
    LOG_DEBUG("Handshake Message 2 received");
}

void HandshakeCapture::processMessage3(const uint8_t* eapol, uint16_t len,
                                        const EAPOLKeyHeader* key) {
    // Message 3 来自 AP
    if (!handshake.hasMsg2) return;
    
    memcpy(handshake.msg3Anonce, key->nonce, 32);
    memcpy(handshake.msg3Mic, key->mic, 16);
    handshake.msg3KeyInfo = key->keyInfo;
    memcpy(handshake.msg3ReplayCounter, key->replayCounter, 8);
    handshake.msg3Timestamp = millis();
    copyEAPOLFrame(eapol, len, handshake.msg3Eapol, &handshake.msg3EapolLen);
    handshake.hasMsg3 = true;
    
    if (handshake.state < HS_MSG3_RECEIVED) {
        handshake.state = HS_MSG3_RECEIVED;
        handshake.lastUpdate = millis();
    }
    
    LOG_DEBUG("Handshake Message 3 received");
}

void HandshakeCapture::processMessage4(const uint8_t* eapol, uint16_t len,
                                        const EAPOLKeyHeader* key) {
    // Message 4 来自 STA
    if (!handshake.hasMsg3) return;
    
    memcpy(handshake.msg4Mic, key->mic, 16);
    handshake.msg4KeyInfo = key->keyInfo;
    memcpy(handshake.msg4ReplayCounter, key->replayCounter, 8);
    handshake.msg4Timestamp = millis();
    handshake.hasMsg4 = true;
    
    handshake.state = HS_MSG4_RECEIVED;
    handshake.lastUpdate = millis();
    handshake.complete = true;
    handshake.captureTime = handshake.msg4Timestamp - handshake.msg1Timestamp;
    
    LOG_INFO("Handshake Message 4 received - Handshake complete!");
    
    // 验证握手包
    handshake.valid = validateHandshake();
    
    // 自动保存
    if (handshake.valid) {
        saveToHCCAPX("/sdcard/handshake.hccapx");
        saveToPCAP("/sdcard/handshake.pcap");
    }
}

// ==================== 握手包管理 ====================
bool HandshakeCapture::isHandshakeComplete() const {
    return handshake.complete && handshake.valid;
}

bool HandshakeCapture::hasValidHandshake() const {
    return handshake.valid;
}

void HandshakeCapture::resetHandshake() {
    memset(&handshake, 0, sizeof(handshake));
    handshake.state = HS_NONE;
}

int HandshakeCapture::getHandshakeQuality() const {
    if (!handshake.hasMsg1 && !handshake.hasMsg2) return 0;
    
    int score = 0;
    if (handshake.hasMsg1) score += 25;
    if (handshake.hasMsg2) score += 25;
    if (handshake.hasMsg3) score += 25;
    if (handshake.hasMsg4) score += 25;
    
    return score;
}

void HandshakeCapture::getHandshakeInfo(char* buffer, size_t len) const {
    char bssid[18], station[18];
    macToString(handshake.bssid, bssid, sizeof(bssid));
    macToString(handshake.station, station, sizeof(station));
    
    snprintf(buffer, len,
             "BSSID: %s\nStation: %s\nSSID: %s\n"
             "Messages: %d%d%d%d\nQuality: %d%%\nValid: %s",
             bssid, station, handshake.ssid,
             handshake.hasMsg1, handshake.hasMsg2, 
             handshake.hasMsg3, handshake.hasMsg4,
             getHandshakeQuality(),
             handshake.valid ? "Yes" : "No");
}

// ==================== 保存功能 ====================
bool HandshakeCapture::saveToHCCAPX(const char* filename) const {
#if ENABLE_SD_CARD
    if (!isHandshakeComplete()) return false;
    
    HCCAPXRecord record;
    buildHCCAPX(&record);
    
    File file = SD.open(filename, FILE_WRITE);
    if (!file) return false;
    
    size_t written = file.write((uint8_t*)&record, sizeof(record));
    file.close();
    
    if (written == sizeof(record)) {
        LOG_INFO("Handshake saved to %s", filename);
        return true;
    }
    
    return false;
#else
    (void)filename;
    LOG_WARN("SD card not available");
    return false;
#endif
}

bool HandshakeCapture::saveToPCAP(const char* filename) const {
    if (!isHandshakeComplete()) return false;
    
    // 创建新的 PCAP 文件
#if ENABLE_SD_CARD
    SDMgr.createPCAP(filename);
    
    // 写入 Message 2 和 Message 3 (包含 MIC)
    if (handshake.hasMsg2) {
        SDMgr.writePacket(handshake.msg2Eapol, handshake.msg2EapolLen);
    }
    if (handshake.hasMsg3) {
        SDMgr.writePacket(handshake.msg3Eapol, handshake.msg3EapolLen);
    }
    
    SDMgr.closePCAP();
    
    LOG_INFO("Handshake saved to %s", filename);
#else
    (void)filename;
    LOG_WARN("SD card not available");
#endif
    return true;
}

bool HandshakeCapture::exportToHashcat(const char* filename) const {
    return saveToHCCAPX(filename);
}

bool HandshakeCapture::exportToJohn(const char* filename) const {
    // John the Ripper 格式 (wpapsk)
    // 需要实现特定格式
    LOG_WARN("John format export not yet implemented");
    return false;
}

bool HandshakeCapture::exportToAircrack(const char* filename) const {
    return saveToPCAP(filename);
}

// ==================== 验证函数 ====================
bool HandshakeCapture::validateHandshake() const {
    // 基本验证
    if (!handshake.hasMsg1 || !handshake.hasMsg2) return false;
    
    // 验证 ANonce 一致性
    if (handshake.hasMsg3) {
        if (memcmp(handshake.msg1Anonce, handshake.msg3Anonce, 32) != 0) {
            LOG_WARN("ANonce mismatch between Message 1 and 3");
            return false;
        }
    }
    
    // 验证 Replay Counter
    if (handshake.hasMsg2 && handshake.hasMsg3) {
        if (memcmp(handshake.msg2ReplayCounter, handshake.msg3ReplayCounter, 8) != 0) {
            LOG_WARN("Replay Counter mismatch");
            return false;
        }
    }
    
    return true;
}

bool HandshakeCapture::checkReplayCounter(const uint8_t* counter1, 
                                           const uint8_t* counter2) const {
    return memcmp(counter1, counter2, 8) == 0;
}

// ==================== 辅助函数 ====================
void HandshakeCapture::updateSSID(const uint8_t* bssid) {
    // 从网络列表中查找 SSID
    const WiFiNetwork* net = Sniffer.findNetwork(bssid);
    if (net && net->ssid[0] != '\0') {
        strncpy(handshake.ssid, net->ssid, sizeof(handshake.ssid) - 1);
        handshake.ssid[sizeof(handshake.ssid) - 1] = '\0';
    }
}

int HandshakeCapture::findHandshakeMessage(const EAPOLKeyHeader* key) const {
    return Parser.findHandshakeMessage(key);
}

void HandshakeCapture::copyEAPOLFrame(const uint8_t* src, uint16_t len, 
                                       uint8_t* dst, uint16_t* dstLen) {
    uint16_t copyLen = min(len, (uint16_t)512);
    memcpy(dst, src, copyLen);
    *dstLen = copyLen;
}

void HandshakeCapture::buildHCCAPX(HCCAPXRecord* record) const {
    memset(record, 0, sizeof(HCCAPXRecord));
    
    record->signature = HCCAPX_SIGNATURE;
    record->version = HCCAPX_VERSION;
    
    // 确定消息对
    if (handshake.hasMsg1 && handshake.hasMsg2) {
        record->messagePair = 0;  // M1+M2
    } else if (handshake.hasMsg2 && handshake.hasMsg3) {
        record->messagePair = 2;  // M2+M3
    } else {
        record->messagePair = 0;
    }
    
    // ESSID
    record->essidLen = strlen(handshake.ssid);
    memcpy(record->essid, handshake.ssid, record->essidLen);
    
    // Key Version (从 Key Info 提取)
    record->keyver = (handshake.msg2KeyInfo >> 3) & 0x07;
    if (record->keyver == 0) record->keyver = 2;  // 默认 AES
    
    // MIC (使用 Message 2 的 MIC)
    memcpy(record->keymic, handshake.msg2Mic, 16);
    
    // AP MAC 和 ANonce
    memcpy(record->macAp, handshake.bssid, 6);
    memcpy(record->nonceAp, handshake.msg1Anonce, 32);
    
    // Station MAC 和 SNonce
    memcpy(record->macSta, handshake.station, 6);
    memcpy(record->nonceSta, handshake.msg2Snonce, 32);
    
    // EAPOL 数据 (Message 2)
    record->eapolLen = handshake.msg2EapolLen;
    memcpy(record->eapol, handshake.msg2Eapol, min((uint16_t)256, record->eapolLen));
}

// ==================== 全局辅助函数 ====================
const char* getHandshakeStateString(HandshakeState state) {
    switch (state) {
        case HS_NONE: return "None";
        case HS_MSG1_RECEIVED: return "Msg1";
        case HS_MSG2_RECEIVED: return "Msg2";
        case HS_MSG3_RECEIVED: return "Msg3";
        case HS_MSG4_RECEIVED: return "Msg4";
        case HS_COMPLETE: return "Complete";
        default: return "Unknown";
    }
}

const char* getHandshakeQualityString(int quality) {
    if (quality >= 100) return "Excellent";
    if (quality >= 75) return "Good";
    if (quality >= 50) return "Fair";
    if (quality >= 25) return "Poor";
    return "Bad";
}

void printHandshakeInfo(const WPAHandshake* hs) {
    char bssid[18], station[18];
    macToString(hs->bssid, bssid, sizeof(bssid));
    macToString(hs->station, station, sizeof(station));
    
    LOG_INFO("Handshake Info:");
    LOG_INFO("  BSSID: %s", bssid);
    LOG_INFO("  Station: %s", station);
    LOG_INFO("  SSID: %s", hs->ssid);
    LOG_INFO("  Messages: M1=%d M2=%d M3=%d M4=%d",
             hs->hasMsg1, hs->hasMsg2, hs->hasMsg3, hs->hasMsg4);
    LOG_INFO("  Complete: %s", hs->complete ? "Yes" : "No");
    LOG_INFO("  Valid: %s", hs->valid ? "Yes" : "No");
}
