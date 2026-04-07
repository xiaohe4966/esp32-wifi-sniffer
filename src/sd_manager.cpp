/**
 * @file sd_manager.cpp
 * @brief SD Card Manager Implementation
 */

#include "sd_manager.h"
#include "wifi_sniffer.h"
#include "packet_parser.h"
#include "handshake.h"

#if ENABLE_SD_CARD

// ==================== 全局实例 ====================
SDManager SDMgr;

// ==================== 构造函数/析构函数 ====================
SDManager::SDManager()
    : ready(false)
    , pcapPacketCount(0)
    , logPacketCount(0)
    , logLevel(3)
    , bytesWritten(0)
    , writeErrors(0) {
    memset(currentPCAP, 0, sizeof(currentPCAP));
}

SDManager::~SDManager() {
    end();
}

// ==================== 初始化 ====================
bool SDManager::begin(uint8_t csPin) {
    LOG_INFO("Initializing SD card...");
    
    // 配置 SPI
    SPI.begin(SD_SCK, SD_MISO, SD_MOSI, csPin);
    
    if (!SD.begin(csPin)) {
        LOG_ERROR("SD card initialization failed!");
        return false;
    }
    
    ready = true;
    
    // 创建目录结构
    if (!SD.exists("/sdcard/captures")) {
        SD.mkdir("/sdcard/captures");
    }
    if (!SD.exists("/sdcard/handshakes")) {
        SD.mkdir("/sdcard/handshakes");
    }
    if (!SD.exists("/sdcard/logs")) {
        SD.mkdir("/sdcard/logs");
    }
    
    LOG_INFO("SD card initialized successfully");
    return true;
}

void SDManager::end() {
    closePCAP();
    SD.end();
    ready = false;
}

// ==================== 基本信息 ====================
uint64_t SDManager::getTotalBytes() const {
    if (!ready) return 0;
    return SD.totalBytes();
}

uint64_t SDManager::getUsedBytes() const {
    if (!ready) return 0;
    return SD.usedBytes();
}

uint64_t SDManager::getFreeBytes() const {
    return getTotalBytes() - getUsedBytes();
}

void SDManager::getInfoString(char* buffer, size_t len) const {
    char total[16], used[16], free[16];
    formatBytes(getTotalBytes(), total, sizeof(total));
    formatBytes(getUsedBytes(), used, sizeof(used));
    formatBytes(getFreeBytes(), free, sizeof(free));
    
    snprintf(buffer, len, "%s / %s (Free: %s)", used, total, free);
}

// ==================== 文件操作 ====================
bool SDManager::exists(const char* path) const {
    if (!ready) return false;
    return SD.exists(path);
}

bool SDManager::remove(const char* path) {
    if (!ready) return false;
    return SD.remove(path);
}

bool SDManager::rename(const char* oldPath, const char* newPath) {
    if (!ready) return false;
    return SD.rename(oldPath, newPath);
}

bool SDManager::mkdir(const char* path) {
    if (!ready) return false;
    return SD.mkdir(path);
}

bool SDManager::rmdir(const char* path) {
    if (!ready) return false;
    return SD.rmdir(path);
}

// ==================== 目录操作 ====================
int SDManager::listDirectory(const char* path, FileInfo* files, int maxFiles) {
    if (!ready) return 0;
    
    File dir = SD.open(path);
    if (!dir || !dir.isDirectory()) return 0;
    
    int count = 0;
    File file = dir.openNextFile();
    
    while (file && count < maxFiles) {
        strncpy(files[count].name, file.name(), sizeof(files[count].name) - 1);
        files[count].size = file.size();
        files[count].isDirectory = file.isDirectory();
        files[count].modified = file.getLastWrite();
        
        count++;
        file = dir.openNextFile();
    }
    
    dir.close();
    return count;
}

void SDManager::printDirectory(const char* path) {
    if (!ready) return;
    
    File dir = SD.open(path);
    if (!dir || !dir.isDirectory()) return;
    
    Serial.printf("Directory: %s\n", path);
    Serial.println("----------------------------------------");
    
    File file = dir.openNextFile();
    while (file) {
        char sizeStr[16];
        formatBytes(file.size(), sizeStr, sizeof(sizeStr));
        
        Serial.printf("  %s %10s %s\n",
                     file.isDirectory() ? "[DIR]" : "[FILE]",
                     sizeStr,
                     file.name());
        
        file = dir.openNextFile();
    }
    
    dir.close();
}

// ==================== PCAP 文件操作 ====================
bool SDManager::createPCAP(const char* filename) {
    if (!ready) return false;
    
    // 关闭之前的 PCAP
    closePCAP();
    
    // 打开新文件
    pcapFile = SD.open(filename, FILE_WRITE);
    if (!pcapFile) {
        LOG_ERROR("Failed to create PCAP file: %s", filename);
        return false;
    }
    
    strncpy(currentPCAP, filename, sizeof(currentPCAP) - 1);
    pcapPacketCount = 0;
    
    // 写入全局头部
    if (!writePCAPHeader()) {
        pcapFile.close();
        return false;
    }
    
    LOG_INFO("PCAP file created: %s", filename);
    return true;
}

bool SDManager::closePCAP() {
    if (pcapFile) {
        pcapFile.close();
        LOG_INFO("PCAP file closed: %d packets", pcapPacketCount);
    }
    
    pcapPacketCount = 0;
    memset(currentPCAP, 0, sizeof(currentPCAP));
    
    return true;
}

bool SDManager::writePacket(const uint8_t* packet, uint16_t len, uint32_t timestamp) {
    if (!pcapFile) return false;
    
    return writePCAPPacket(packet, len, timestamp);
}

uint32_t SDManager::getPCAPFileSize() const {
    if (!pcapFile) return 0;
    return pcapFile.size();
}

// ==================== 文本文件操作 ====================
bool SDManager::appendLine(const char* filename, const char* line) {
    if (!ready) return false;
    
    File file = SD.open(filename, FILE_APPEND);
    if (!file) return false;
    
    file.println(line);
    file.close();
    
    return true;
}

bool SDManager::readLine(const char* filename, int lineNum, char* buffer, size_t len) {
    if (!ready) return false;
    
    File file = SD.open(filename, FILE_READ);
    if (!file) return false;
    
    int currentLine = 0;
    while (file.available() && currentLine < lineNum) {
        String line = file.readStringUntil('\n');
        if (currentLine == lineNum) {
            strncpy(buffer, line.c_str(), len - 1);
            buffer[len - 1] = '\0';
            file.close();
            return true;
        }
        currentLine++;
    }
    
    file.close();
    return false;
}

int SDManager::countLines(const char* filename) {
    if (!ready) return 0;
    
    File file = SD.open(filename, FILE_READ);
    if (!file) return 0;
    
    int count = 0;
    while (file.available()) {
        file.readStringUntil('\n');
        count++;
    }
    
    file.close();
    return count;
}

// ==================== 日志功能 ====================
bool SDManager::logMessage(const char* level, const char* message) {
    if (!ready) return false;
    
    char filename[64];
    snprintf(filename, sizeof(filename), "/sdcard/logs/%s.log", getLogFilename());
    
    // 构造日志行
    char logLine[256];
    time_t now = time(nullptr);
    struct tm* timeinfo = localtime(&now);
    
    snprintf(logLine, sizeof(logLine),
             "[%04d-%02d-%02d %02d:%02d:%02d] [%s] %s",
             timeinfo->tm_year + 1900, timeinfo->tm_mon + 1, timeinfo->tm_mday,
             timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec,
             level, message);
    
    return appendLine(filename, logLine);
}

bool SDManager::logPacket(const PacketInfo* info) {
    if (!ready || logLevel < 4) return false;
    
    char logLine[128];
    snprintf(logLine, sizeof(logLine),
             "Packet: Type=%d Subtype=%d CH=%d RSSI=%d Len=%d",
             info->frameType, info->frameSubtype,
             info->channel, info->rssi, info->length);
    
    return logMessage("DEBUG", logLine);
}

bool SDManager::logHandshake(const WPAHandshake* handshake) {
    if (!ready) return false;
    
    char logLine[256];
    char bssid[18], station[18];
    macToString(handshake->bssid, bssid, sizeof(bssid));
    macToString(handshake->station, station, sizeof(station));
    
    snprintf(logLine, sizeof(logLine),
             "Handshake: %s %s M1=%d M2=%d M3=%d M4=%d",
             bssid, station,
             handshake->hasMsg1, handshake->hasMsg2,
             handshake->hasMsg3, handshake->hasMsg4);
    
    return logMessage("INFO", logLine);
}

// ==================== 文件传输 ====================
bool SDManager::startFileTransfer(const char* filename) {
    if (!ready) return false;
    
    transferFile = SD.open(filename, FILE_READ);
    return transferFile != false;
}

int SDManager::readFileChunk(uint8_t* buffer, size_t len) {
    if (!transferFile) return 0;
    
    return transferFile.read(buffer, len);
}

void SDManager::endFileTransfer() {
    if (transferFile) {
        transferFile.close();
    }
}

size_t SDManager::getFileSize(const char* filename) const {
    if (!ready) return 0;
    
    File file = SD.open(filename, FILE_READ);
    if (!file) return 0;
    
    size_t size = file.size();
    file.close();
    
    return size;
}

// ==================== 批量操作 ====================
bool SDManager::rotatePCAPFiles(const char* baseFilename, int maxFiles) {
    if (!ready) return false;
    
    // 删除最旧的文件
    char oldFile[128];
    snprintf(oldFile, sizeof(oldFile), "%s.%d", baseFilename, maxFiles - 1);
    if (SD.exists(oldFile)) {
        SD.remove(oldFile);
    }
    
    // 重命名现有文件
    for (int i = maxFiles - 2; i >= 0; i--) {
        char src[128], dst[128];
        
        if (i == 0) {
            snprintf(src, sizeof(src), "%s", baseFilename);
        } else {
            snprintf(src, sizeof(src), "%s.%d", baseFilename, i);
        }
        
        snprintf(dst, sizeof(dst), "%s.%d", baseFilename, i + 1);
        
        if (SD.exists(src)) {
            SD.rename(src, dst);
        }
    }
    
    return true;
}

bool SDManager::cleanupOldFiles(const char* pattern, int keepCount) {
    // 实现文件清理逻辑
    return true;
}

// ==================== 内部方法 ====================
bool SDManager::writePCAPHeader() {
    PCAPGlobalHeader header;
    
    header.magicNumber = 0xA1B2C3D4;  // 小端序
    header.versionMajor = 2;
    header.versionMinor = 4;
    header.thiszone = 0;
    header.sigfigs = 0;
    header.snaplen = 65535;
    header.network = LINKTYPE_IEEE802_11;
    
    size_t written = pcapFile.write((uint8_t*)&header, sizeof(header));
    return written == sizeof(header);
}

bool SDManager::writePCAPPacket(const uint8_t* packet, uint16_t len, uint32_t timestamp) {
    PCAPPacketHeader pktHeader;
    
    // 时间戳
    if (timestamp == 0) {
        timestamp = millis();
    }
    
    pktHeader.tsSec = timestamp / 1000;
    pktHeader.tsUsec = (timestamp % 1000) * 1000;
    pktHeader.inclLen = len;
    pktHeader.origLen = len;
    
    // 写入包头
    size_t written = pcapFile.write((uint8_t*)&pktHeader, sizeof(pktHeader));
    if (written != sizeof(pktHeader)) {
        writeErrors++;
        return false;
    }
    
    // 写入数据
    written = pcapFile.write(packet, len);
    if (written != len) {
        writeErrors++;
        return false;
    }
    
    pcapFile.flush();
    pcapPacketCount++;
    bytesWritten += sizeof(pktHeader) + len;
    
    return true;
}

uint32_t SDManager::getTimestamp() {
    return millis();
}

const char* SDManager::getLogFilename() const {
    static char filename[32];
    time_t now = time(nullptr);
    struct tm* timeinfo = localtime(&now);
    
    snprintf(filename, sizeof(filename), "%04d%02d%02d",
             timeinfo->tm_year + 1900,
             timeinfo->tm_mon + 1,
             timeinfo->tm_mday);
    
    return filename;
}

void SDManager::ensureDirectory(const char* path) {
    if (!SD.exists(path)) {
        SD.mkdir(path);
    }
}

// ==================== 辅助函数 ====================
void formatBytes(uint64_t bytes, char* buffer, size_t len) {
    const char* units[] = {"B", "KB", "MB", "GB"};
    int unitIndex = 0;
    double size = bytes;
    
    while (size >= 1024 && unitIndex < 3) {
        size /= 1024;
        unitIndex++;
    }
    
    snprintf(buffer, len, "%.1f %s", size, units[unitIndex]);
}

const char* getFileExtension(const char* filename) {
    const char* dot = strrchr(filename, '.');
    if (!dot || dot == filename) return "";
    return dot + 1;
}

bool isPCAPFile(const char* filename) {
    const char* ext = getFileExtension(filename);
    return strcasecmp(ext, "pcap") == 0 || strcasecmp(ext, "cap") == 0;
}

bool isTextFile(const char* filename) {
    const char* ext = getFileExtension(filename);
    return strcasecmp(ext, "txt") == 0 ||
           strcasecmp(ext, "log") == 0 ||
           strcasecmp(ext, "csv") == 0;
}

#endif // ENABLE_SD_CARD