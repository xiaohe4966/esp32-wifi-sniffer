/**
 * @file sd_manager.h
 * @brief SD Card Manager Module
 * 
 * SD 卡管理模块
 * 提供文件存储、PCAP 格式写入和日志记录功能
 */

#ifndef SD_MANAGER_H
#define SD_MANAGER_H

#include "config.h"
#include "handshake.h"

// ==================== PCAP 文件格式定义 ====================

// PCAP 全局头部 (24 字节)
struct PCAPGlobalHeader {
    uint32_t magicNumber;    // 0xA1B2C3D4 (小端) 或 0xD4C3B2A1 (大端)
    uint16_t versionMajor;   // 2
    uint16_t versionMinor;   // 4
    int32_t thiszone;        // GMT 到本地时间的修正值
    uint32_t sigfigs;        // 时间戳精度
    uint32_t snaplen;        // 最大捕获长度
    uint32_t network;        // 数据链路类型 (1=Ethernet, 105=IEEE802_11)
};

// PCAP 数据包头部 (16 字节)
struct PCAPPacketHeader {
    uint32_t tsSec;          // 时间戳 (秒)
    uint32_t tsUsec;         // 时间戳 (微秒)
    uint32_t inclLen;        // 捕获长度
    uint32_t origLen;        // 原始长度
};

// 数据链路类型
#define LINKTYPE_IEEE802_11 105
#define LINKTYPE_IEEE802_11_RADIOTAP 127

// ==================== 文件信息结构 (始终定义) ====================
struct FileInfo {
    char name[64];
    size_t size;
    time_t modified;
    bool isDirectory;
};

#if ENABLE_SD_CARD
#include <SD.h>
#include <SPI.h>

// ==================== 类定义 ====================
class SDManager {
public:
    SDManager();
    ~SDManager();

    bool begin(uint8_t csPin = SD_CS);
    void end();
    bool isReady() const { return ready; }

    uint64_t getTotalBytes() const;
    uint64_t getUsedBytes() const;
    uint64_t getFreeBytes() const;
    void getInfoString(char* buffer, size_t len) const;

    bool exists(const char* path) const;
    bool remove(const char* path);
    bool rename(const char* oldPath, const char* newPath);
    bool mkdir(const char* path);
    bool rmdir(const char* path);
    
    int listDirectory(const char* path, FileInfo* files, int maxFiles);
    void printDirectory(const char* path);

    bool createPCAP(const char* filename);
    bool closePCAP();
    bool writePacket(const uint8_t* packet, uint16_t len, uint32_t timestamp = 0);
    bool isPCAPOpen() const { return pcapFile; }
    const char* getCurrentPCAP() const { return currentPCAP; }
    uint32_t getPCAPPacketCount() const { return pcapPacketCount; }
    uint32_t getPCAPFileSize() const;

    bool appendLine(const char* filename, const char* line);
    bool readLine(const char* filename, int lineNum, char* buffer, size_t len);
    int countLines(const char* filename);

    bool logMessage(const char* level, const char* message);
    bool logPacket(const PacketInfo* info);
    bool logHandshake(const WPAHandshake* handshake);
    void setLogLevel(uint8_t level) { logLevel = level; }

    bool startFileTransfer(const char* filename);
    int readFileChunk(uint8_t* buffer, size_t len);
    void endFileTransfer();
    size_t getFileSize(const char* filename) const;

    bool rotatePCAPFiles(const char* baseFilename, int maxFiles);
    bool cleanupOldFiles(const char* pattern, int keepCount);

private:
    bool ready;
    File pcapFile;
    File transferFile;
    char currentPCAP[128];
    uint32_t pcapPacketCount;
    uint32_t logPacketCount;
    uint8_t logLevel;
    uint64_t bytesWritten;
    uint32_t writeErrors;

    bool writePCAPHeader();
    bool writePCAPPacket(const uint8_t* packet, uint16_t len, uint32_t timestamp);
    uint32_t getTimestamp();
    const char* getLogFilename() const;
    void ensureDirectory(const char* path);
};

extern SDManager SDMgr;

void formatBytes(uint64_t bytes, char* buffer, size_t len);
const char* getFileExtension(const char* filename);
bool isPCAPFile(const char* filename);
bool isTextFile(const char* filename);

#else
// ==================== SD 卡禁用时的空实现 ====================
class SDManager {
public:
    SDManager() : ready(false) {}
    ~SDManager() {}

    bool begin(uint8_t csPin = 0) { (void)csPin; ready = false; return false; }
    void end() {}
    bool isReady() const { return false; }

    uint64_t getTotalBytes() const { return 0; }
    uint64_t getUsedBytes() const { return 0; }
    uint64_t getFreeBytes() const { return 0; }
    void getInfoString(char* buffer, size_t len) const { if (len > 0) buffer[0] = '\0'; }

    bool exists(const char* path) const { (void)path; return false; }
    bool remove(const char* path) { (void)path; return false; }
    bool rename(const char* oldPath, const char* newPath) { (void)oldPath; (void)newPath; return false; }
    bool mkdir(const char* path) { (void)path; return false; }
    bool rmdir(const char* path) { (void)path; return false; }
    
    int listDirectory(const char* path, FileInfo* files, int maxFiles) { (void)path; (void)files; (void)maxFiles; return 0; }
    void printDirectory(const char* path) { (void)path; }

    bool createPCAP(const char* filename) { (void)filename; return false; }
    bool closePCAP() { return false; }
    bool writePacket(const uint8_t* packet, uint16_t len, uint32_t timestamp) { (void)packet; (void)len; (void)timestamp; return false; }
    bool isPCAPOpen() const { return false; }
    const char* getCurrentPCAP() const { return ""; }
    uint32_t getPCAPPacketCount() const { return 0; }
    uint32_t getPCAPFileSize() const { return 0; }

    bool appendLine(const char* filename, const char* line) { (void)filename; (void)line; return false; }
    bool readLine(const char* filename, int lineNum, char* buffer, size_t len) { (void)filename; (void)lineNum; (void)buffer; (void)len; return false; }
    int countLines(const char* filename) { (void)filename; return 0; }

    bool logMessage(const char* level, const char* message) { (void)level; (void)message; return false; }
    bool logPacket(const PacketInfo* info) { (void)info; return false; }
    bool logHandshake(const WPAHandshake* handshake) { (void)handshake; return false; }
    void setLogLevel(uint8_t level) { (void)level; }

    bool startFileTransfer(const char* filename) { (void)filename; return false; }
    int readFileChunk(uint8_t* buffer, size_t len) { (void)buffer; (void)len; return 0; }
    void endFileTransfer() {}
    size_t getFileSize(const char* filename) const { (void)filename; return 0; }

    bool rotatePCAPFiles(const char* baseFilename, int maxFiles) { (void)baseFilename; (void)maxFiles; return false; }
    bool cleanupOldFiles(const char* pattern, int keepCount) { (void)pattern; (void)keepCount; return false; }

private:
    bool ready;
};

extern SDManager SDMgr;

inline void formatBytes(uint64_t bytes, char* buffer, size_t len) {
    (void)bytes; if (len > 0) buffer[0] = '\0';
}
inline const char* getFileExtension(const char* filename) { (void)filename; return ""; }
inline bool isPCAPFile(const char* filename) { (void)filename; return false; }
inline bool isTextFile(const char* filename) { (void)filename; return false; }

#endif // ENABLE_SD_CARD

#endif // SD_MANAGER_H