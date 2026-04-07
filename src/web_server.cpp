/**
 * @file web_server.cpp
 * @brief Web Server and WebSocket Implementation
 */

#include "web_server.h"
#include "web_assets.h"
#include "wifi_sniffer.h"
#include <SPIFFS.h>
#include "handshake.h"
#include "dictionary.h"
#include "deauth.h"
#include "sd_manager.h"

// ==================== 静态成员定义 ====================
WebServerManager* WebServerManager::instance = nullptr;

// ==================== 全局实例 ====================
WebServerManager WebServer;

// ==================== 构造函数/析构函数 ====================
WebServerManager::WebServerManager()
    : running(false)
    , server(nullptr)
    , ws(nullptr)
    , lastBroadcast(0) {
    instance = this;
}

WebServerManager::~WebServerManager() {
    end();
}

// ==================== 初始化 ====================
bool WebServerManager::begin() {
    LOG_INFO("Initializing web server...");
    
    server = new AsyncWebServer(WEB_SERVER_PORT);
    ws = new AsyncWebSocket("/ws");
    
    setupRoutes();
    setupWebSocket();
    setupStaticFiles();
    
    server->begin();
    running = true;
    
    LOG_INFO("Web server started on port %d", WEB_SERVER_PORT);
    return true;
}

void WebServerManager::end() {
    if (ws) {
        ws->closeAll();
        delete ws;
        ws = nullptr;
    }
    
    if (server) {
        server->end();
        delete server;
        server = nullptr;
    }
    
    running = false;
}

// ==================== 服务器控制 ====================
void WebServerManager::startServer() {
    if (!running) {
        server->begin();
        running = true;
    }
}

void WebServerManager::stopServer() {
    if (running) {
        server->end();
        running = false;
    }
}

// ==================== WebSocket 广播 ====================
void WebServerManager::broadcastStatus() {
    if (!ws || ws->count() == 0) return;
    
    StaticJsonDocument<512> doc;
    buildStatusJSON(doc.to<JsonObject>());
    
    char buffer[512];
    size_t len = serializeJson(doc, buffer);
    
    ws->textAll(buffer, len);
}

void WebServerManager::broadcastScanResult(const WiFiNetwork* network) {
    if (!ws || ws->count() == 0) return;
    
    StaticJsonDocument<256> doc;
    doc["type"] = "scan_result";
    buildNetworkJSON(doc["data"].to<JsonObject>(), network);
    
    char buffer[256];
    size_t len = serializeJson(doc, buffer);
    
    ws->textAll(buffer, len);
}

void WebServerManager::broadcastPacket(const PacketInfo* info) {
    if (!ws || ws->count() == 0) return;
    if (millis() - lastBroadcast < BROADCAST_INTERVAL) return;
    
    StaticJsonDocument<256> doc;
    doc["type"] = "packet";
    buildPacketJSON(doc["data"].to<JsonObject>(), info);
    
    char buffer[256];
    size_t len = serializeJson(doc, buffer);
    
    ws->textAll(buffer, len);
    lastBroadcast = millis();
}

void WebServerManager::broadcastHandshake(const WPAHandshake* handshake) {
    if (!ws || ws->count() == 0) return;
    
    StaticJsonDocument<512> doc;
    doc["type"] = "handshake";
    buildHandshakeJSON(doc["data"].to<JsonObject>(), handshake);
    
    char buffer[512];
    size_t len = serializeJson(doc, buffer);
    
    ws->textAll(buffer, len);
}

void WebServerManager::broadcastAttackProgress(const AttackStats* stats) {
    if (!ws || ws->count() == 0) return;
    
    StaticJsonDocument<256> doc;
    doc["type"] = "attack_progress";
    buildAttackStatsJSON(doc["data"].to<JsonObject>(), stats);
    
    char buffer[256];
    size_t len = serializeJson(doc, buffer);
    
    ws->textAll(buffer, len);
}

void WebServerManager::broadcastLog(const char* level, const char* message) {
    if (!ws || ws->count() == 0) return;
    
    StaticJsonDocument<256> doc;
    doc["type"] = "log";
    doc["level"] = level;
    doc["message"] = message;
    doc["timestamp"] = millis();
    
    char buffer[256];
    size_t len = serializeJson(doc, buffer);
    
    ws->textAll(buffer, len);
}

// ==================== 处理函数 ====================
void WebServerManager::onWiFiScanComplete() {
    // 通知所有客户端扫描完成
    if (!ws || ws->count() == 0) return;
    
    StaticJsonDocument<64> doc;
    doc["type"] = "scan_complete";
    
    char buffer[64];
    size_t len = serializeJson(doc, buffer);
    
    ws->textAll(buffer, len);
}

void WebServerManager::onPacketCaptured(const PacketInfo* info) {
    broadcastPacket(info);
}

void WebServerManager::onHandshakeCaptured(const WPAHandshake* handshake) {
    broadcastHandshake(handshake);
}

void WebServerManager::onAttackProgress(const AttackStats* stats) {
    broadcastAttackProgress(stats);
}

// ==================== 路由设置 ====================
void WebServerManager::setupRoutes() {
    // CORS 预检
    server->on("/api/", HTTP_OPTIONS, [this](AsyncWebServerRequest* request) {
        handleCORS(request);
        request->send(200);
    });

    // API 路由
    server->on("/api/status", HTTP_GET, [this](AsyncWebServerRequest* request) {
        handleStatus(request);
    });
    
    server->on("/api/scan", HTTP_GET, [this](AsyncWebServerRequest* request) {
        handleScan(request);
    });
    
    server->on("/api/networks", HTTP_GET, [this](AsyncWebServerRequest* request) {
        handleNetworks(request);
    });
    
#if ENABLE_SD_CARD
    server->on("/api/capture/start", HTTP_POST, [this](AsyncWebServerRequest* request) {
        handleCaptureStart(request);
    });
    
    server->on("/api/capture/stop", HTTP_POST, [this](AsyncWebServerRequest* request) {
        handleCaptureStop(request);
    });
    
    server->on("/api/capture/download", HTTP_GET, [this](AsyncWebServerRequest* request) {
        handleCaptureDownload(request);
    });
#endif
    
    server->on("/api/attack/start", HTTP_POST, [this](AsyncWebServerRequest* request) {
        handleAttackStart(request);
    });
    
    server->on("/api/attack/stop", HTTP_POST, [this](AsyncWebServerRequest* request) {
        handleAttackStop(request);
    });
    
    server->on("/api/attack/status", HTTP_GET, [this](AsyncWebServerRequest* request) {
        handleAttackStatus(request);
    });
    
    server->on("/api/config", HTTP_GET, [this](AsyncWebServerRequest* request) {
        handleConfigGet(request);
    });
    
    server->on("/api/config", HTTP_POST, [this](AsyncWebServerRequest* request) {
        handleConfigPost(request);
    });
    
#if ENABLE_SD_CARD
    server->on("/api/handshake/download", HTTP_GET, [this](AsyncWebServerRequest* request) {
        handleHandshakeDownload(request);
    });
#endif

    // 根路由 -> index.html (优先从 SPIFFS 读取，否则使用内置)
    server->on("/", HTTP_GET, [](AsyncWebServerRequest* request) {
        if (SPIFFS.exists("/index.html")) {
            request->send(SPIFFS, "/index.html", "text/html");
        } else {
            request->send(200, "text/html", INDEX_HTML);
        }
    });

    // 静态文件 (优先从 SPIFFS 读取)
    server->on("/style.css", HTTP_GET, [](AsyncWebServerRequest* request) {
        if (SPIFFS.exists("/style.css")) {
            request->send(SPIFFS, "/style.css", "text/css");
        } else {
            request->send(200, "text/css", STYLE_CSS);
        }
    });
    
    server->on("/app.js", HTTP_GET, [](AsyncWebServerRequest* request) {
        if (SPIFFS.exists("/app.js")) {
            request->send(SPIFFS, "/app.js", "application/javascript");
        } else {
            request->send(200, "application/javascript", APP_JS);
        }
    });

    // 404
    server->onNotFound([](AsyncWebServerRequest* request) {
        request->send(404, "application/json", "{\"error\":\"Not found\"}");
    });
}

void WebServerManager::setupWebSocket() {
    ws->onEvent([this](AsyncWebSocket* server, AsyncWebSocketClient* client,
                       AwsEventType type, void* arg, uint8_t* data, size_t len) {
        onWebSocketEvent(server, client, type, arg, data, len);
    });
    
    server->addHandler(ws);
}

void WebServerManager::setupStaticFiles() {
    // 静态文件已在路由中处理
}

// ==================== API 处理器 ====================
void WebServerManager::handleStatus(AsyncWebServerRequest* request) {
    StaticJsonDocument<512> doc;
    buildStatusJSON(doc.to<JsonObject>());
    sendJSON(request, doc);
}

void WebServerManager::handleScan(AsyncWebServerRequest* request) {
    Sniffer.startScan();
    sendSuccess(request, "Scan started");
}

void WebServerManager::handleNetworks(AsyncWebServerRequest* request) {
    StaticJsonDocument<4096> doc;
    JsonArray networks = doc.createNestedArray("networks");
    
    int count = Sniffer.getNetworkCount();
    for (int i = 0; i < count; i++) {
        const WiFiNetwork* net = Sniffer.getNetwork(i);
        if (net) {
            JsonObject obj = networks.createNestedObject();
            buildNetworkJSON(obj, net);
        }
    }
    
    sendJSON(request, doc);
}

void WebServerManager::handleCaptureStart(AsyncWebServerRequest* request) {
    // 获取参数
    const char* channel = request->getParam("channel") ? 
                          request->getParam("channel")->value().c_str() : nullptr;
    
    if (channel) {
        Sniffer.setChannel(atoi(channel));
    }
    
    Sniffer.startSniffing();
    sendSuccess(request, "Capture started");
}

void WebServerManager::handleCaptureStop(AsyncWebServerRequest* request) {
    Sniffer.stopSniffing();
#if ENABLE_SD_CARD
    SDMgr.closePCAP();
#endif
    sendSuccess(request, "Capture stopped");
}

void WebServerManager::handleCaptureDownload(AsyncWebServerRequest* request) {
#if ENABLE_SD_CARD
    if (!SDMgr.exists(PCAP_FILENAME)) {
        sendError(request, "No capture file available");
        return;
    }
    request->send(SD, PCAP_FILENAME, "application/vnd.tcpdump.pcap", true);
#else
    (void)request;
    sendError(request, "SD card not available");
#endif
}

void WebServerManager::handleAttackStart(AsyncWebServerRequest* request) {
    // 获取参数
    const char* type = request->getParam("type") ? 
                       request->getParam("type")->value().c_str() : "dict";
    
    if (strcmp(type, "deauth") == 0) {
        Deauth.startAttack();
    } else {
        DictAttack.startAttack();
    }
    
    sendSuccess(request, "Attack started");
}

void WebServerManager::handleAttackStop(AsyncWebServerRequest* request) {
    Deauth.stopAttack();
    DictAttack.stopAttack();
    sendSuccess(request, "Attack stopped");
}

void WebServerManager::handleAttackStatus(AsyncWebServerRequest* request) {
    StaticJsonDocument<256> doc;
    
    doc["deauth_running"] = Deauth.isRunning();
    doc["dict_running"] = DictAttack.isRunning();
    doc["dict_state"] = getAttackStateString(DictAttack.getState());
    
    sendJSON(request, doc);
}

void WebServerManager::handleConfigGet(AsyncWebServerRequest* request) {
    StaticJsonDocument<512> doc;
    buildConfigJSON(doc.to<JsonObject>());
    sendJSON(request, doc);
}

void WebServerManager::handleConfigPost(AsyncWebServerRequest* request) {
    // 处理配置更新
    sendSuccess(request, "Configuration updated");
}

void WebServerManager::handleHandshakeDownload(AsyncWebServerRequest* request) {
#if ENABLE_SD_CARD
    const char* format = request->getParam("format") ? 
                         request->getParam("format")->value().c_str() : "hccapx";
    
    if (strcmp(format, "pcap") == 0) {
        request->send(SD, "/sdcard/handshake.pcap", "application/vnd.tcpdump.pcap", true);
    } else {
        request->send(SD, "/sdcard/handshake.hccapx", "application/octet-stream", true);
    }
#else
    (void)request;
    sendError(request, "SD card not available");
#endif
}

// ==================== WebSocket 处理器 ====================
void WebServerManager::onWebSocketEvent(AsyncWebSocket* server, AsyncWebSocketClient* client,
                                         AwsEventType type, void* arg, uint8_t* data, size_t len) {
    switch (type) {
        case WS_EVT_CONNECT:
            LOG_INFO("WebSocket client %u connected", client->id());
            break;
            
        case WS_EVT_DISCONNECT:
            LOG_INFO("WebSocket client %u disconnected", client->id());
            break;
            
        case WS_EVT_DATA:
            handleWebSocketMessage(client, arg, data, len);
            break;
            
        case WS_EVT_PONG:
        case WS_EVT_ERROR:
            break;
    }
}

void WebServerManager::handleWebSocketMessage(AsyncWebSocketClient* client, void* arg,
                                               uint8_t* data, size_t len) {
    AwsFrameInfo* info = (AwsFrameInfo*)arg;
    
    if (info->final && info->index == 0 && info->len == len && info->opcode == WS_TEXT) {
        data[len] = 0;
        
        StaticJsonDocument<256> doc;
        DeserializationError error = deserializeJson(doc, data);
        
        if (error) return;
        
        const char* cmd = doc["cmd"];
        if (!cmd) return;
        
        if (strcmp(cmd, "scan") == 0) {
            Sniffer.startScan();
        } else if (strcmp(cmd, "capture_start") == 0) {
            Sniffer.startSniffing();
        } else if (strcmp(cmd, "capture_stop") == 0) {
            Sniffer.stopSniffing();
        } else if (strcmp(cmd, "get_status") == 0) {
            broadcastStatus();
        }
    }
}

// ==================== 辅助函数 ====================
void WebServerManager::sendJSON(AsyncWebServerRequest* request, const JsonDocument& doc) {
    handleCORS(request);
    
    char buffer[4096];
    size_t len = serializeJson(doc, buffer);
    
    request->send(200, "application/json", buffer);
}

void WebServerManager::sendError(AsyncWebServerRequest* request, const char* message, int code) {
    handleCORS(request);
    
    StaticJsonDocument<256> doc;
    doc["success"] = false;
    doc["error"] = message;
    
    char buffer[256];
    size_t len = serializeJson(doc, buffer);
    
    request->send(code, "application/json", buffer);
}

void WebServerManager::sendSuccess(AsyncWebServerRequest* request, const char* message) {
    handleCORS(request);
    
    StaticJsonDocument<256> doc;
    doc["success"] = true;
    if (message) {
        doc["message"] = message;
    }
    
    char buffer[256];
    size_t len = serializeJson(doc, buffer);
    
    request->send(200, "application/json", buffer);
}

void WebServerManager::sendFile(AsyncWebServerRequest* request, const char* path, 
                                 const char* contentType) {
#if ENABLE_SD_CARD
    handleCORS(request);
    request->send(SD, path, contentType);
#else
    (void)request; (void)path; (void)contentType;
#endif
}

void WebServerManager::handleCORS(AsyncWebServerRequest* request) {
    // CORS headers - new API approach
    if (request->method() == HTTP_OPTIONS) {
        request->send(200);
    }
}

// ==================== JSON 构建 ====================
void WebServerManager::buildStatusJSON(JsonObject obj) {
    obj["firmware"] = FIRMWARE_VERSION;
    obj["mode"] = currentMode;
    obj["channel"] = currentChannel;
    obj["sniffing"] = snifferRunning;
    obj["channel_hopping"] = channelHopping;
    obj["networks"] = Sniffer.getNetworkCount();
    obj["packets"] = Sniffer.getTotalPackets();
    obj["uptime"] = millis() / 1000;
    
    JsonObject wifi = obj.createNestedObject("wifi");
    wifi["ap_ip"] = WiFi.softAPIP().toString();
    wifi["ap_clients"] = WiFi.softAPgetStationNum();
    wifi["rssi"] = Sniffer.getRSSI();
}

void WebServerManager::buildNetworkJSON(JsonObject obj, const WiFiNetwork* network) {
    char bssid[18];
    macToString(network->bssid, bssid, sizeof(bssid));
    
    obj["bssid"] = bssid;
    obj["ssid"] = network->ssid;
    obj["rssi"] = network->rssi;
    obj["channel"] = network->channel;
    obj["auth"] = getAuthModeString(network->authMode);
    obj["packets"] = network->packetCount;
}

void WebServerManager::buildPacketJSON(JsonObject obj, const PacketInfo* info) {
    char src[18], dst[18], bssid[18];
    macToString(info->source, src, sizeof(src));
    macToString(info->destination, dst, sizeof(dst));
    macToString(info->bssid, bssid, sizeof(bssid));
    
    obj["timestamp"] = info->timestamp;
    obj["channel"] = info->channel;
    obj["rssi"] = info->rssi;
    obj["type"] = info->frameType;
    obj["subtype"] = info->frameSubtype;
    obj["src"] = src;
    obj["dst"] = dst;
    obj["bssid"] = bssid;
    obj["length"] = info->length;
}

void WebServerManager::buildHandshakeJSON(JsonObject obj, const WPAHandshake* handshake) {
    char bssid[18], station[18];
    macToString(handshake->bssid, bssid, sizeof(bssid));
    macToString(handshake->station, station, sizeof(station));
    
    obj["bssid"] = bssid;
    obj["station"] = station;
    obj["ssid"] = handshake->ssid;
    obj["complete"] = handshake->complete;
    obj["valid"] = handshake->valid;
    obj["quality"] = Handshake.getHandshakeQuality();
    obj["msg1"] = handshake->hasMsg1;
    obj["msg2"] = handshake->hasMsg2;
    obj["msg3"] = handshake->hasMsg3;
    obj["msg4"] = handshake->hasMsg4;
}

void WebServerManager::buildAttackStatsJSON(JsonObject obj, const AttackStats* stats) {
    obj["total"] = stats->totalPasswords;
    obj["tested"] = stats->testedPasswords;
    obj["progress"] = stats->progressPercent;
    obj["speed"] = stats->passwordsPerSecond;
    obj["current"] = stats->currentPassword;
}

void WebServerManager::buildConfigJSON(JsonObject obj) {
    obj["channel_hop_interval"] = CHANNEL_HOP_INTERVAL;
    obj["deauth_burst"] = DEAUTH_BURST_COUNT;
    obj["deauth_interval"] = DEAUTH_INTERVAL_MS;
    obj["dict_batch_size"] = DICT_BATCH_SIZE;
    obj["max_password_len"] = MAX_PASSWORD_LENGTH;
    obj["pcap_max_size"] = PCAP_MAX_SIZE_MB;
}
