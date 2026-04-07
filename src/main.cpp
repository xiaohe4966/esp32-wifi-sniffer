/**
 * @file main.cpp
 * @brief ESP32 WiFi Sniffer Main Entry Point
 * 
 * ESP32 WiFi 抓包工具主程序入口
 */

#include "config.h"
#include "wifi_sniffer.h"
#include "packet_parser.h"
#include "handshake.h"
#include "dictionary.h"
#include "deauth.h"
#include "web_server.h"
#include "sd_manager.h"
#include "oled_display.h"
#include "cli.h"

// ==================== 全局变量定义 ====================
DeviceMode currentMode = MODE_IDLE;
volatile bool snifferRunning = false;
volatile bool channelHopping = false;
uint8_t currentChannel = 1;

// ==================== 函数声明 ====================
void setupHardware();
void setupWiFi();
void setupServices();
void handleMode();
void printBanner();
void packetHandler(const uint8_t* packet, uint16_t len, const PacketInfo* info);
void networkHandler(const WiFiNetwork* network);

// ==================== 初始化 ====================
void setup() {
    // 初始化串口
    Serial.begin(SERIAL_BAUD_RATE);
    delay(1000);
    
    printBanner();
    LOG_INFO("Initializing ESP32 WiFi Sniffer v%s...", FIRMWARE_VERSION);
    
    // 初始化硬件
    setupHardware();
    
    // 初始化 WiFi
    setupWiFi();
    
    // 初始化服务
    setupServices();
    
    // 设置回调
    Sniffer.setPacketCallback(packetHandler);
    Sniffer.setNetworkFoundCallback(networkHandler);
    
    // 启动 CLI
    CLI.begin();
    
    LOG_INFO("Initialization complete. Type 'help' for commands.");
    CLI.showPrompt();
}

// ==================== 主循环 ====================
void loop() {
    // 处理串口命令
    CLI.handleInput();
    
    // 根据当前模式处理
    handleMode();
    
    // 更新显示
    if (Display.isReady()) {
        Display.update();
    }
    
    // 短暂延时
    delay(10);
}

// ==================== 硬件初始化 ====================
void setupHardware() {
    // 初始化 LED
    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, LOW);
    
    // 初始化 OLED
#if ENABLE_OLED
    if (Display.begin()) {
        LOG_INFO("OLED display initialized");
        Display.showBootAnimation();
    } else {
        LOG_WARN("OLED display not found");
    }
#endif

    // 初始化 SD 卡
#if ENABLE_SD_CARD
    if (SDMgr.begin()) {
        LOG_INFO("SD card initialized");
        char info[64];
        SDMgr.getInfoString(info, sizeof(info));
        LOG_INFO("SD: %s", info);
    } else {
        LOG_WARN("SD card not found");
    }
#endif
}

// ==================== WiFi 初始化 ====================
void setupWiFi() {
    // 初始化 WiFi
    WiFi.mode(WIFI_MODE_APSTA);
    
    // 配置 AP
    WiFi.softAPConfig(IPAddress(192, 168, 4, 1), 
                      IPAddress(192, 168, 4, 1), 
                      IPAddress(255, 255, 255, 0));
    WiFi.softAP(AP_SSID, AP_PASSWORD, AP_CHANNEL, 0, AP_MAX_CONNECTIONS);
    
    LOG_INFO("AP started: %s (IP: %s)", AP_SSID, WiFi.softAPIP().toString().c_str());
    
    // 初始化抓包器
    if (Sniffer.begin()) {
        LOG_INFO("WiFi sniffer initialized");
    } else {
        LOG_ERROR("Failed to initialize WiFi sniffer");
    }
}

// ==================== 服务初始化 ====================
void setupServices() {
    // 启动 Web 服务器
#if ENABLE_WEB_SERVER
    if (WebServer.begin()) {
        LOG_INFO("Web server started on port %d", WEB_SERVER_PORT);
        LOG_INFO("Web interface: http://%s", WiFi.softAPIP().toString().c_str());
    } else {
        LOG_ERROR("Failed to start web server");
    }
#endif

    // 初始化握手捕获
#if ENABLE_HANDSHAKE_CAPTURE
    Handshake.begin();
    LOG_INFO("Handshake capture initialized");
#endif

    // 初始化字典攻击
#if ENABLE_DICT_ATTACK
    DictAttack.begin();
    LOG_INFO("Dictionary attack initialized");
#endif

    // 初始化 Deauth
#if ENABLE_DEAUTH_ATTACK
    Deauth.begin();
    LOG_INFO("Deauth attack initialized");
#endif
}

// ==================== 模式处理 ====================
void handleMode() {
    switch (currentMode) {
        case MODE_IDLE:
            // 空闲模式 - 什么都不做
            break;
            
        case MODE_SCANNING:
            // 扫描模式 - 由 Sniffer 处理
            break;
            
        case MODE_SNIFFING:
            // 抓包模式 - 由 Sniffer 处理
            break;
            
        case MODE_HANDSHAKE_CAPTURE:
            // 握手包捕获模式
            if (Handshake.isHandshakeComplete()) {
                LOG_INFO("Handshake capture complete!");
                currentMode = MODE_IDLE;
            }
            break;
            
        case MODE_DEAUTH_ATTACK:
            // Deauth 攻击模式 - 由 Deauth 处理
            break;
            
        case MODE_DICT_ATTACK:
            // 字典攻击模式 - 由 DictAttack 处理
            break;
            
        case MODE_WEB_SERVER:
            // Web 服务器模式 - 由 WebServer 处理
            break;
            
        default:
            break;
    }
}

// ==================== 数据包回调 ====================
void packetHandler(const uint8_t* packet, uint16_t len, const PacketInfo* info) {
    // 更新 LED
    digitalWrite(LED_PIN, HIGH);
    
    // 保存到 SD 卡
#if ENABLE_SD_CARD
    if (SDMgr.isPCAPOpen()) {
        SDMgr.writePacket(packet, len);
    }
#endif

    // 处理握手包
#if ENABLE_HANDSHAKE_CAPTURE
    if (currentMode == MODE_HANDSHAKE_CAPTURE || Handshake.isAutoCaptureEnabled()) {
        Handshake.processPacket(packet, len, info);
    }
#endif

    // 广播到 WebSocket
#if ENABLE_WEBSOCKET
    WebServer.onPacketCaptured(info);
#endif

    // 更新显示
    if (Display.isReady()) {
        Display.setPacketCount(Sniffer.getTotalPackets());
        Display.setRSSI(info->rssi);
    }
    
    digitalWrite(LED_PIN, LOW);
}

// ==================== 网络发现回调 ====================
void networkHandler(const WiFiNetwork* network) {
    char bssidStr[18];
    macToString(network->bssid, bssidStr, sizeof(bssidStr));
    
    LOG_INFO("Network found: %s [%s] CH:%d RSSI:%d %s",
             network->ssid,
             bssidStr,
             network->channel,
             network->rssi,
             getAuthModeString(network->authMode));
    
    // 更新显示
    if (Display.isReady()) {
        Display.setNetworkCount(Sniffer.getNetworkCount());
    }
    
    // 广播到 WebSocket
#if ENABLE_WEBSOCKET
    WebServer.broadcastScanResult(network);
#endif
}

// ==================== 打印启动横幅 ====================
void printBanner() {
    Serial.println();
    Serial.println("╔══════════════════════════════════════════════════════════════╗");
    Serial.println("║                                                              ║");
    Serial.println("║           ESP32 WiFi Sniffer & Dictionary Attack             ║");
    Serial.println("║                                                              ║");
    Serial.println("║     ⚠️  FOR SECURITY RESEARCH AND EDUCATIONAL USE ONLY ⚠️     ║");
    Serial.println("║                                                              ║");
    Serial.printf("║              Firmware Version: %-10s                    ║\n", FIRMWARE_VERSION);
    Serial.println("╚══════════════════════════════════════════════════════════════╝");
    Serial.println();
    Serial.println("WARNING: This tool is for authorized security testing only!");
    Serial.println("Unauthorized access to computer networks is illegal.");
    Serial.println();
}
