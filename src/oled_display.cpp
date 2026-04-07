/**
 * @file oled_display.cpp
 * @brief OLED Display Implementation
 */

#include "oled_display.h"
#include "wifi_sniffer.h"
#include "dictionary.h"

#if ENABLE_OLED

// ==================== 图标位图 (8x8) ====================
const unsigned char ICON_WIFI[] = {
    0x00, 0x00, 0xF8, 0x04, 0xF4, 0x14, 0x14, 0x14
};

const unsigned char ICON_LOCK[] = {
    0x00, 0x78, 0x84, 0x84, 0xFC, 0xFC, 0xFC, 0x00
};

const unsigned char ICON_PACKET[] = {
    0x00, 0x7E, 0x81, 0xA5, 0x81, 0xA5, 0x81, 0x7E
};

const unsigned char ICON_ATTACK[] = {
    0x00, 0x04, 0x0E, 0x1F, 0x1F, 0x0E, 0x04, 0x00
};

// ==================== 全局实例 ====================
OLEDDisplay Display;

// ==================== 构造函数/析构函数 ====================
OLEDDisplay::OLEDDisplay()
    : display(nullptr)
    , ready(false)
    , currentPage(PAGE_MAIN)
    , currentMode(MODE_IDLE)
    , currentChannel(1)
    , packetCount(0)
    , networkCount(0)
    , rssi(0)
    , progress(0)
    , displayedNetworks(0)
    , selectedNetwork(0)
    , logLineIndex(0)
    , screensaverEnabled(true)
    , lastActivity(0)
    , animationFrame(0)
    , lastAnimationUpdate(0) {
    memset(statusText, 0, sizeof(statusText));
    memset(networks, 0, sizeof(networks));
    memset(logLines, 0, sizeof(logLines));
}

OLEDDisplay::~OLEDDisplay() {
    end();
}

// ==================== 初始化 ====================
bool OLEDDisplay::begin(uint8_t sda, uint8_t scl, uint8_t addr) {
    LOG_INFO("Initializing OLED display...");
    
    Wire.begin(sda, scl);
    
    display = new Adafruit_SSD1306(OLED_WIDTH, OLED_HEIGHT, &Wire, -1);
    
    if (!display->begin(SSD1306_SWITCHCAPVCC, addr)) {
        LOG_ERROR("OLED initialization failed");
        delete display;
        display = nullptr;
        return false;
    }
    
    display->clearDisplay();
    display->setTextSize(1);
    display->setTextColor(SSD1306_WHITE);
    display->display();
    
    ready = true;
    lastActivity = millis();
    
    LOG_INFO("OLED display initialized");
    return true;
}

void OLEDDisplay::end() {
    if (display) {
        display->ssd1306_command(SSD1306_DISPLAYOFF);
        delete display;
        display = nullptr;
    }
    ready = false;
}

// ==================== 基本控制 ====================
void OLEDDisplay::clear() {
    if (!ready) return;
    display->clearDisplay();
}

void OLEDDisplay::refresh() {
    if (!ready) return;
    display->display();
}

void OLEDDisplay::setContrast(uint8_t contrast) {
    if (!ready) return;
    display->ssd1306_command(SSD1306_SETCONTRAST);
    display->ssd1306_command(contrast);
}

void OLEDDisplay::invert(bool invert) {
    if (!ready) return;
    display->invertDisplay(invert);
}

void OLEDDisplay::sleep(bool sleep) {
    if (!ready) return;
    if (sleep) {
        display->ssd1306_command(SSD1306_DISPLAYOFF);
    } else {
        display->ssd1306_command(SSD1306_DISPLAYON);
    }
}

// ==================== 页面导航 ====================
void OLEDDisplay::nextPage() {
    currentPage = (DisplayPage)((currentPage + 1) % PAGE_COUNT);
    resetScreensaverTimer();
}

void OLEDDisplay::prevPage() {
    currentPage = (DisplayPage)((currentPage - 1 + PAGE_COUNT) % PAGE_COUNT);
    resetScreensaverTimer();
}

void OLEDDisplay::setPage(DisplayPage page) {
    currentPage = page;
    resetScreensaverTimer();
}

// ==================== 更新显示 ====================
void OLEDDisplay::update() {
    if (!ready) return;
    
    // 检查屏幕保护
    if (screensaverEnabled && millis() - lastActivity > SCREENSAVER_TIMEOUT) {
        sleep(true);
        return;
    }
    
    updatePage(currentPage);
}

void OLEDDisplay::updatePage(DisplayPage page) {
    clear();
    
    switch (page) {
        case PAGE_MAIN:
            showMainPage();
            break;
        case PAGE_NETWORKS:
            showNetworksPage();
            break;
        case PAGE_PACKETS:
            showPacketsPage();
            break;
        case PAGE_HANDSHAKE:
            showHandshakePage();
            break;
        case PAGE_ATTACK:
            showAttackPage();
            break;
        case PAGE_LOG:
            showLogPage();
            break;
    }
    
    display->display();
}

// ==================== 特定页面 ====================
void OLEDDisplay::showMainPage() {
    drawHeader();
    
    // 模式
    display->setCursor(0, 16);
    display->print("Mode: ");
    display->print(getModeString(currentMode));
    
    // 信道
    display->setCursor(0, 26);
    display->print("CH: ");
    display->print(currentChannel);
    
    // 信号强度
    drawSignalBars(100, 16, rssi);
    
    // 数据包数
    display->setCursor(0, 36);
    display->print("Packets: ");
    display->print(packetCount);
    
    // 网络数
    display->setCursor(0, 46);
    display->print("Networks: ");
    display->print(networkCount);
    
    // 状态
    display->setCursor(0, 56);
    display->print(getShortStatus());
    
    drawFooter();
}

void OLEDDisplay::showNetworksPage() {
    drawHeader();
    
    display->setCursor(0, 16);
    display->print("Networks (");
    display->print(networkCount);
    display->print("):");
    
    for (int i = 0; i < min(displayedNetworks, 4); i++) {
        int y = 28 + i * 10;
        
        // 选中指示
        if (i == selectedNetwork) {
            display->fillRect(0, y - 1, 128, 10, SSD1306_WHITE);
            display->setTextColor(SSD1306_BLACK);
        }
        
        display->setCursor(2, y);
        
        // 显示 SSID (截断)
        char ssid[13];
        strncpy(ssid, networks[i].ssid, 12);
        ssid[12] = '\0';
        display->print(ssid);
        
        // 显示信道
        display->setCursor(90, y);
        display->print("CH");
        display->print(networks[i].channel);
        
        // 恢复颜色
        if (i == selectedNetwork) {
            display->setTextColor(SSD1306_WHITE);
        }
    }
    
    drawFooter();
}

void OLEDDisplay::showPacketsPage() {
    drawHeader();
    
    display->setCursor(0, 16);
    display->print("Packet Statistics:");
    
    display->setCursor(0, 28);
    display->print("Total: ");
    display->print(packetCount);
    
    display->setCursor(0, 38);
    display->print("Mgmt: ");
    display->print(Sniffer.getManagementPackets());
    
    display->setCursor(0, 48);
    display->print("Data: ");
    display->print(Sniffer.getDataPackets());
    
    display->setCursor(0, 58);
    display->print("Ctrl: ");
    display->print(Sniffer.getControlPackets());
    
    drawFooter();
}

void OLEDDisplay::showHandshakePage() {
    drawHeader();
    
    display->setCursor(0, 16);
    display->print("Handshake:");
    
    const WPAHandshake* hs = Handshake.getHandshake();
    
    display->setCursor(0, 28);
    display->print("M1:");
    display->print(hs->hasMsg1 ? "OK" : "--");
    
    display->setCursor(40, 28);
    display->print("M2:");
    display->print(hs->hasMsg2 ? "OK" : "--");
    
    display->setCursor(80, 28);
    display->print("M3:");
    display->print(hs->hasMsg3 ? "OK" : "--");
    
    display->setCursor(0, 40);
    display->print("M4:");
    display->print(hs->hasMsg4 ? "OK" : "--");
    
    display->setCursor(0, 52);
    display->print("Quality: ");
    display->print(Handshake.getHandshakeQuality());
    display->print("%");
    
    drawFooter();
}

void OLEDDisplay::showAttackPage() {
    drawHeader();
    
    display->setCursor(0, 16);
    display->print("Dictionary Attack:");
    
    const AttackStats* stats = DictAttack.getStats();
    
    display->setCursor(0, 28);
    display->print("Progress: ");
    display->print(stats->progressPercent);
    display->print("%");
    
    // 进度条
    drawProgressBar(0, 38, 128, 6, stats->progressPercent);
    
    display->setCursor(0, 48);
    display->print("Speed: ");
    
    char speedStr[16];
    formatSpeed(stats->passwordsPerSecond, speedStr, sizeof(speedStr));
    display->print(speedStr);
    
    display->setCursor(0, 58);
    display->print("State: ");
    display->print(getAttackStateString(DictAttack.getState()));
    
    drawFooter();
}

void OLEDDisplay::showLogPage() {
    drawHeader();
    
    display->setCursor(0, 16);
    display->print("Log:");
    
    for (int i = 0; i < 4; i++) {
        int idx = (logLineIndex - 3 + i + 4) % 4;
        display->setCursor(0, 28 + i * 10);
        display->print(logLines[idx]);
    }
    
    drawFooter();
}

// ==================== 状态更新 ====================
void OLEDDisplay::setMode(DeviceMode mode) {
    currentMode = mode;
    resetScreensaverTimer();
}

void OLEDDisplay::setChannel(uint8_t channel) {
    currentChannel = channel;
}

void OLEDDisplay::setPacketCount(uint32_t count) {
    packetCount = count;
}

void OLEDDisplay::setNetworkCount(int count) {
    networkCount = count;
}

void OLEDDisplay::setRSSI(int8_t rssiVal) {
    rssi = rssiVal;
}

void OLEDDisplay::setProgress(uint8_t percent) {
    progress = percent;
}

void OLEDDisplay::setStatus(const char* status) {
    strncpy(statusText, status, sizeof(statusText) - 1);
    statusText[sizeof(statusText) - 1] = '\0';
}

void OLEDDisplay::setNetworkList(const WiFiNetwork* nets, int count) {
    int copyCount = min(count, 5);
    for (int i = 0; i < copyCount; i++) {
        memcpy(&networks[i], &nets[i], sizeof(WiFiNetwork));
    }
    displayedNetworks = copyCount;
}

void OLEDDisplay::setSelectedNetwork(int index) {
    selectedNetwork = index;
}

void OLEDDisplay::addLogLine(const char* line) {
    strncpy(logLines[logLineIndex], line, 31);
    logLines[logLineIndex][31] = '\0';
    logLineIndex = (logLineIndex + 1) % 4;
}

void OLEDDisplay::clearLog() {
    memset(logLines, 0, sizeof(logLines));
    logLineIndex = 0;
}

// ==================== 动画 ====================
void OLEDDisplay::showBootAnimation() {
    if (!ready) return;
    
    clear();
    
    // 显示标题
    display->setTextSize(1);
    display->setCursor(20, 20);
    display->print("ESP32 Sniffer");
    
    display->setCursor(35, 35);
    display->print("Starting...");
    
    // 进度条动画
    for (int i = 0; i <= 100; i += 5) {
        drawProgressBar(14, 50, 100, 6, i);
        display->display();
        delay(50);
    }
    
    delay(200);
}

void OLEDDisplay::showScanAnimation() {
    // 简单的扫描动画
    static const char* frames[] = {"|", "/", "-", "\\"};
    animationFrame = (animationFrame + 1) % 4;
    
    display->setCursor(120, 0);
    display->print(frames[animationFrame]);
}

void OLEDDisplay::showSuccessAnimation() {
    clear();
    display->setCursor(30, 30);
    display->print("Success!");
    display->display();
    delay(1000);
}

void OLEDDisplay::showErrorAnimation() {
    clear();
    display->setCursor(35, 30);
    display->print("Error!");
    display->display();
    delay(1000);
}

// ==================== 屏幕保护 ====================
void OLEDDisplay::enableScreensaver(bool enable) {
    screensaverEnabled = enable;
}

void OLEDDisplay::resetScreensaverTimer() {
    lastActivity = millis();
    sleep(false);
}

// ==================== 内部方法 ====================
void OLEDDisplay::drawHeader() {
    display->drawLine(0, 12, 128, 12, SSD1306_WHITE);
    
    display->setCursor(0, 0);
    display->print("ESP32 Sniffer");
    
    // 显示当前信道
    display->setCursor(100, 0);
    display->print("CH");
    display->print(currentChannel);
}

void OLEDDisplay::drawFooter() {
    display->drawLine(0, 63, 128, 63, SSD1306_WHITE);
    
    // 显示页码
    display->setCursor(0, 56);
    display->print("P");
    display->print(currentPage + 1);
    display->print("/");
    display->print(PAGE_COUNT);
}

void OLEDDisplay::drawProgressBar(uint8_t x, uint8_t y, uint8_t width, 
                                   uint8_t height, uint8_t percent) {
    display->drawRect(x, y, width, height, SSD1306_WHITE);
    
    uint8_t fillWidth = (width - 2) * percent / 100;
    display->fillRect(x + 1, y + 1, fillWidth, height - 2, SSD1306_WHITE);
}

void OLEDDisplay::drawSignalBars(uint8_t x, uint8_t y, int8_t rssiVal) {
    // 根据 RSSI 绘制信号条
    int bars = 0;
    if (rssiVal > -50) bars = 4;
    else if (rssiVal > -60) bars = 3;
    else if (rssiVal > -70) bars = 2;
    else if (rssiVal > -80) bars = 1;
    
    for (int i = 0; i < 4; i++) {
        uint8_t h = 3 + i * 2;
        if (i < bars) {
            display->fillRect(x + i * 4, y + 8 - h, 3, h, SSD1306_WHITE);
        } else {
            display->drawRect(x + i * 4, y + 8 - h, 3, h, SSD1306_WHITE);
        }
    }
}

void OLEDDisplay::drawScrollingText(const char* text, uint8_t x, uint8_t y, uint8_t width) {
    // 简单实现：截断显示
    char buf[32];
    strncpy(buf, text, 31);
    buf[31] = '\0';
    display->setCursor(x, y);
    display->print(buf);
}

void OLEDDisplay::wrapText(const char* text, char* output, size_t outputLen, 
                            uint8_t maxChars) {
    // 文本换行处理
    size_t len = strlen(text);
    if (len <= maxChars) {
        strncpy(output, text, outputLen - 1);
        output[outputLen - 1] = '\0';
        return;
    }
    
    // 截断并添加省略号
    strncpy(output, text, maxChars - 3);
    strcpy(output + maxChars - 3, "...");
}

void OLEDDisplay::drawWiFiIcon(uint8_t x, uint8_t y, bool connected) {
    display->drawBitmap(x, y, ICON_WIFI, 8, 8, SSD1306_WHITE);
}

void OLEDDisplay::drawLockIcon(uint8_t x, uint8_t y, bool locked) {
    if (locked) {
        display->drawBitmap(x, y, ICON_LOCK, 8, 8, SSD1306_WHITE);
    }
}

void OLEDDisplay::drawPacketIcon(uint8_t x, uint8_t y) {
    display->drawBitmap(x, y, ICON_PACKET, 8, 8, SSD1306_WHITE);
}

void OLEDDisplay::drawAttackIcon(uint8_t x, uint8_t y) {
    display->drawBitmap(x, y, ICON_ATTACK, 8, 8, SSD1306_WHITE);
}

const char* OLEDDisplay::getModeString(DeviceMode mode) {
    switch (mode) {
        case MODE_IDLE: return "Idle";
        case MODE_SCANNING: return "Scanning";
        case MODE_SNIFFING: return "Sniffing";
        case MODE_HANDSHAKE_CAPTURE: return "Handshake";
        case MODE_DEAUTH_ATTACK: return "Deauth";
        case MODE_DICT_ATTACK: return "Attack";
        case MODE_WEB_SERVER: return "Web";
        default: return "Unknown";
    }
}

const char* OLEDDisplay::getShortStatus() {
    if (statusText[0] != '\0') {
        return statusText;
    }
    
    switch (currentMode) {
        case MODE_IDLE: return "Ready";
        case MODE_SCANNING: return "Scanning...";
        case MODE_SNIFFING: return "Capturing...";
        case MODE_HANDSHAKE_CAPTURE: return "Handshake...";
        case MODE_DEAUTH_ATTACK: return "Attacking...";
        case MODE_DICT_ATTACK: return "Cracking...";
        default: return "";
    }
}

#else
// 空实现
OLEDDisplay Display;
#endif // ENABLE_OLED
