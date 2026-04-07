/**
 * @file oled_display.h
 * @brief OLED Display Module
 * 
 * OLED 显示屏模块
 * 提供状态显示和用户界面
 */

#ifndef OLED_DISPLAY_H
#define OLED_DISPLAY_H

#include "config.h"

#if ENABLE_OLED
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

// ==================== 显示页面定义 ====================

enum DisplayPage {
    PAGE_MAIN = 0,      // 主页面 - 基本状态
    PAGE_NETWORKS,      // 网络列表
    PAGE_PACKETS,       // 数据包统计
    PAGE_HANDSHAKE,     // 握手包状态
    PAGE_ATTACK,        // 攻击进度
    PAGE_LOG,           // 日志
    PAGE_COUNT
};

// ==================== 显示模式 ====================

enum DisplayMode {
    MODE_NORMAL = 0,
    MODE_INVERSE,
    MODE_BLINK
};

// ==================== 类定义 ====================

class OLEDDisplay {
public:
    OLEDDisplay();
    ~OLEDDisplay();

    // 初始化和清理
    bool begin(uint8_t sda = OLED_SDA, uint8_t scl = OLED_SCL, 
               uint8_t addr = OLED_ADDR);
    void end();
    bool isReady() const { return ready; }

    // 基本控制
    void clear();
    void refresh();
    void setContrast(uint8_t contrast);
    void invert(bool invert);
    void sleep(bool sleep);

    // 页面导航
    void nextPage();
    void prevPage();
    void setPage(DisplayPage page);
    DisplayPage getCurrentPage() const { return currentPage; }

    // 更新显示 (根据当前页面)
    void update();
    void updatePage(DisplayPage page);

    // 特定页面更新
    void showMainPage();
    void showNetworksPage();
    void showPacketsPage();
    void showHandshakePage();
    void showAttackPage();
    void showLogPage();

    // 状态更新 (用于实时显示)
    void setMode(DeviceMode mode);
    void setChannel(uint8_t channel);
    void setPacketCount(uint32_t count);
    void setNetworkCount(int count);
    void setRSSI(int8_t rssi);
    void setProgress(uint8_t percent);
    void setStatus(const char* status);

    // 网络列表
    void setNetworkList(const WiFiNetwork* networks, int count);
    void setSelectedNetwork(int index);

    // 日志
    void addLogLine(const char* line);
    void clearLog();

    // 动画
    void showBootAnimation();
    void showScanAnimation();
    void showSuccessAnimation();
    void showErrorAnimation();

    // 屏幕保护
    void enableScreensaver(bool enable);
    void resetScreensaverTimer();

private:
    Adafruit_SSD1306* display;
    bool ready;
    
    DisplayPage currentPage;
    DeviceMode currentMode;
    
    // 状态数据
    uint8_t currentChannel;
    uint32_t packetCount;
    int networkCount;
    int8_t rssi;
    uint8_t progress;
    char statusText[32];
    
    // 网络列表
    WiFiNetwork networks[5];  // 显示前 5 个
    int displayedNetworks;
    int selectedNetwork;
    
    // 日志
    char logLines[4][32];     // 4 行日志
    int logLineIndex;
    
    // 屏幕保护
    bool screensaverEnabled;
    uint32_t lastActivity;
    static const uint32_t SCREENSAVER_TIMEOUT = 60000; // 1 分钟
    
    // 动画
    uint8_t animationFrame;
    uint32_t lastAnimationUpdate;
    
    // 内部方法
    void drawHeader();
    void drawFooter();
    void drawProgressBar(uint8_t x, uint8_t y, uint8_t width, uint8_t height, uint8_t percent);
    void drawSignalBars(uint8_t x, uint8_t y, int8_t rssi);
    void drawScrollingText(const char* text, uint8_t x, uint8_t y, uint8_t width);
    void wrapText(const char* text, char* output, size_t outputLen, uint8_t maxChars);
    
    // 图标绘制
    void drawWiFiIcon(uint8_t x, uint8_t y, bool connected);
    void drawLockIcon(uint8_t x, uint8_t y, bool locked);
    void drawPacketIcon(uint8_t x, uint8_t y);
    void drawAttackIcon(uint8_t x, uint8_t y);
    
    // 辅助函数
    const char* getModeString(DeviceMode mode);
    const char* getShortStatus();
};

// ==================== 全局实例 ====================
extern OLEDDisplay Display;

// ==================== 位图定义 (图标) ====================
extern const unsigned char ICON_WIFI[];
extern const unsigned char ICON_LOCK[];
extern const unsigned char ICON_PACKET[];
extern const unsigned char ICON_ATTACK[];

#else
// 当 OLED 禁用时提供空实现
class OLEDDisplay {
public:
    bool begin(uint8_t sda = 0, uint8_t scl = 0, uint8_t addr = 0) { return false; }
    void end() {}
    bool isReady() const { return false; }
    void clear() {}
    void display() {}
    void update() {}
    void setMode(DeviceMode mode) {}
    void setChannel(uint8_t channel) {}
    void setPacketCount(uint32_t count) {}
    void setStatus(const char* status) {}
    void addLogLine(const char* line) {}
};
extern OLEDDisplay Display;
#endif // ENABLE_OLED

#endif // OLED_DISPLAY_H
