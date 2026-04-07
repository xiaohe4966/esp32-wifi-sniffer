# ESP32 WiFi Sniffer & Dictionary Attack Tool

基于 ESP32-S3 (支持 2.4GHz/5GHz 双频) 的 WiFi 抓包与字典攻击开源工具，用于无线安全研究。

## ⚠️ 免责声明

**本工具仅用于合法的安全研究和教育目的。使用本工具攻击未经授权的网络是违法的。请确保您只在自己拥有或获得明确授权的网络中使用此工具。**

## 功能特性

- 📡 **WiFi 抓包**: 捕获 802.11 数据帧、管理帧、控制帧
- 🔍 **信道扫描**: 自动扫描 2.4GHz 和 5GHz 频段的所有信道
- 📶 **信号强度分析**: 实时显示 RSSI、信道、加密类型等信息
- 🔐 **WPA/WPA2 握手包捕获**: 捕获 4-way handshake 用于离线破解
- 🎯 **字典攻击**: 对捕获的握手包进行 WPA/WPA2 密码破解
- 💾 **SD 卡存储**: 支持将抓包数据保存到 SD 卡 (PCAP 格式)
- 🌐 **Web 界面**: 内置 Web 服务器用于配置和查看结果
- 📊 **实时监控**: 通过串口或 WebSocket 实时查看抓包统计

## 硬件要求

- ESP32-S3-DevKitC-1 或兼容开发板
- SD 卡模块 (可选，用于数据存储)
- OLED 显示屏 128x64 (可选，用于状态显示)
- USB 数据线

## 软件依赖

- PlatformIO Core
- ESP-IDF v5.0+
- Python 3.7+

## 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/xiaohe4966/esp32-wifi-sniffer.git
cd esp32-wifi-sniffer
```

### 2. 使用 PlatformIO 构建

```bash
# 安装依赖
pio pkg install

# 构建项目
pio run

# 上传固件
pio run --target upload

# 监控串口输出
pio device monitor
```

### 3. 配置

编辑 `include/config.h` 文件来自定义设置：

```cpp
// WiFi 配置
#define DEFAULT_SSID "YourNetwork"
#define DEFAULT_PASSWORD "YourPassword"

// 抓包配置
#define MAX_CHANNEL_HOP_TIME 200  // 毫秒
#define ENABLE_SD_CARD true
#define PCAP_FILENAME "/sdcard/capture.pcap"

// 字典攻击配置
#define DICTIONARY_FILE "/sdcard/wordlist.txt"
#define MAX_PASSWORD_LENGTH 64
```

## 使用说明

### 模式 1: WiFi 抓包模式

```
1. 上电后设备进入抓包模式
2. 自动扫描所有信道
3. 捕获的数据包保存到 SD 卡 (PCAP 格式)
4. 可通过 Web 界面下载 PCAP 文件
```

### 模式 2: 握手包捕获

```
1. 选择目标网络
2. 发送 Deauth 帧强制客户端重新连接
3. 捕获 4-way handshake
4. 保存握手包用于离线破解
```

### 模式 3: 字典攻击

```
1. 加载字典文件到 SD 卡
2. 选择目标握手包
3. 开始字典攻击
4. 破解成功后在 OLED/串口显示密码
```

## Web 界面

设备启动后会创建一个 AP：
- **SSID**: ESP32-Sniffer
- **Password**: 12345678

连接后访问: `http://192.168.4.1`

### Web 界面功能
- 实时信道扫描结果
- 抓包统计信息
- 下载 PCAP 文件
- 配置攻击参数
- 查看破解进度

## API 接口

```
GET  /api/status          - 获取设备状态
GET  /api/scan            - 开始 WiFi 扫描
GET  /api/networks        - 获取扫描到的网络列表
POST /api/capture/start   - 开始抓包
POST /api/capture/stop    - 停止抓包
GET  /api/capture/download - 下载 PCAP 文件
POST /api/attack/start    - 开始字典攻击
GET  /api/attack/status   - 获取攻击状态
```

## 项目结构

```
esp32-wifi-sniffer/
├── include/
│   ├── config.h          # 配置文件
│   ├── wifi_sniffer.h    # WiFi 抓包核心
│   ├── packet_parser.h   # 数据包解析
│   ├── handshake.h       # 握手包处理
│   ├── dictionary.h      # 字典攻击
│   ├── web_server.h      # Web 服务器
│   └── sd_manager.h      # SD 卡管理
├── src/
│   ├── main.cpp          # 主程序入口
│   ├── wifi_sniffer.cpp  # WiFi 抓包实现
│   ├── packet_parser.cpp # 数据包解析实现
│   ├── handshake.cpp     # 握手包处理实现
│   ├── dictionary.cpp    # 字典攻击实现
│   ├── web_server.cpp    # Web 服务器实现
│   └── sd_manager.cpp    # SD 卡管理实现
├── data/                 # Web 静态文件
│   ├── index.html
│   ├── style.css
│   └── app.js
├── scripts/
│   └── generate_wordlist.py  # 字典生成工具
├── platformio.ini
└── README.md
```

## 安全研究用途

本工具可用于：
- 企业无线网络安全审计
- 渗透测试
- 安全培训和教育
- 802.11 协议研究
- 无线网络故障排查

## 技术细节

### 支持的帧类型
- Management Frames (Beacon, Probe, Association, Authentication, Deauthentication)
- Control Frames (RTS, CTS, ACK)
- Data Frames (Data, Null Data, QoS Data)

### 支持的加密类型
- OPEN
- WEP
- WPA-Personal (TKIP)
- WPA2-Personal (CCMP)
- WPA3-SAE (检测)

### 性能指标
- 最大抓包速率: ~1000 packets/second
- 信道切换时间: ~50ms
- 字典攻击速度: ~500 passwords/second (取决于密码复杂度)

## 故障排除

### 常见问题

**Q: 无法连接到目标网络进行抓包**
A: ESP32-S3 的 WiFi 处于混杂模式时无法同时作为 STA 连接。使用 Monitor 模式抓包。

**Q: SD 卡初始化失败**
A: 检查接线，确保使用 FAT32 格式化的 SD 卡。

**Q: Web 界面无法访问**
A: 确认已连接到 ESP32-Sniffer AP，检查 IP 地址是否为 192.168.4.x。

## 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 致谢

- ESP-IDF 开发团队
- PlatformIO 团队
- 无线安全研究社区

---

**再次提醒：请合法使用本工具，遵守当地法律法规。**
