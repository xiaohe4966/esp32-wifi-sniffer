/**
 * @file web_server.h
 * @brief Web Server and WebSocket Module
 * 
 * Web 服务器和 WebSocket 模块
 * 提供配置界面和实时监控功能
 */

#ifndef WEB_SERVER_H
#define WEB_SERVER_H

#include "config.h"
#include "handshake.h"
#include "dictionary.h"
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>

// ==================== WebSocket 事件类型 ====================

enum WSEventType {
    WS_EVT_STATUS = 0,      // 状态更新
    WS_EVT_SCAN_RESULT,     // 扫描结果
    WS_EVT_PACKET,          // 数据包信息
    WS_EVT_HANDSHAKE,       // 握手包更新
    WS_EVT_ATTACK_PROGRESS, // 攻击进度
    WS_EVT_LOG              // 日志消息
};

// ==================== API 响应结构 ====================

struct APIResponse {
    bool success;
    String message;
    JsonObject data;
    
    APIResponse() : success(false) {}
};

// ==================== 类定义 ====================

class WebServerManager {
public:
    WebServerManager();
    ~WebServerManager();

    // 初始化和清理
    bool begin();
    void end();
    bool isRunning() const { return running; }
    
    // 主循环调用
    void update();  // 检查扫描超时等

    // 服务器控制
    void startServer();
    void stopServer();

    // WebSocket 广播
    void broadcastStatus();
    void broadcastScanResult(const WiFiNetwork* network);
    void broadcastPacket(const PacketInfo* info);
    void broadcastHandshake(const WPAHandshake* handshake);
    void broadcastAttackProgress(const AttackStats* stats);
    void broadcastLog(const char* level, const char* message);

    // 处理函数 (供其他模块调用)
    void onWiFiScanComplete();
    void onPacketCaptured(const PacketInfo* info);
    void onHandshakeCaptured(const WPAHandshake* handshake);
    void onAttackProgress(const AttackStats* stats);

private:
    bool running;
    AsyncWebServer* server;
    AsyncWebSocket* ws;
    
    // 客户端管理
    uint32_t lastBroadcast;
    static const uint32_t BROADCAST_INTERVAL = 100; // ms
    
    // 扫描控制
    uint32_t scanStartTime;
    static const uint32_t SCAN_DURATION = 10000; // 10秒扫描时长

    // 路由设置
    void setupRoutes();
    void setupWebSocket();
    void setupStaticFiles();

    // API 处理器
    void handleStatus(AsyncWebServerRequest* request);
    void handleScan(AsyncWebServerRequest* request);
    void handleNetworks(AsyncWebServerRequest* request);
    void handleCaptureStart(AsyncWebServerRequest* request);
    void handleCaptureStop(AsyncWebServerRequest* request);
    void handleCaptureDownload(AsyncWebServerRequest* request);
    void handleAttackStart(AsyncWebServerRequest* request);
    void handleAttackStop(AsyncWebServerRequest* request);
    void handleAttackStatus(AsyncWebServerRequest* request);
    void handleConfigGet(AsyncWebServerRequest* request);
    void handleConfigPost(AsyncWebServerRequest* request);
    void handleHandshakeDownload(AsyncWebServerRequest* request);

    // WebSocket 处理器
    void onWebSocketEvent(AsyncWebSocket* server, AsyncWebSocketClient* client, 
                          AwsEventType type, void* arg, uint8_t* data, size_t len);
    void handleWebSocketMessage(AsyncWebSocketClient* client, void* arg, 
                                uint8_t* data, size_t len);

    // 辅助函数
    void sendJSON(AsyncWebServerRequest* request, const JsonDocument& doc);
    void sendError(AsyncWebServerRequest* request, const char* message, int code = 400);
    void sendSuccess(AsyncWebServerRequest* request, const char* message = nullptr);
    void sendFile(AsyncWebServerRequest* request, const char* path, const char* contentType);
    
    // JSON 构建
    void buildStatusJSON(JsonObject obj);
    void buildNetworkJSON(JsonObject obj, const WiFiNetwork* network);
    void buildPacketJSON(JsonObject obj, const PacketInfo* info);
    void buildHandshakeJSON(JsonObject obj, const WPAHandshake* handshake);
    void buildAttackStatsJSON(JsonObject obj, const AttackStats* stats);
    void buildConfigJSON(JsonObject obj);

    // CORS 处理
    void handleCORS(AsyncWebServerRequest* request);

    // 静态实例指针 (用于回调)
    static WebServerManager* instance;
};

// ==================== 全局实例 ====================
extern WebServerManager WebServer;

// ==================== HTML 模板 ====================
extern const char INDEX_HTML[];
extern const char STYLE_CSS[];
extern const char APP_JS[];

#endif // WEB_SERVER_H
