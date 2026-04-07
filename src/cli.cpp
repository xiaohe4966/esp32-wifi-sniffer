/**
 * @file cli.cpp
 * @brief Command Line Interface Implementation
 */

#include "cli.h"
#include "wifi_sniffer.h"
#include "handshake.h"
#include "dictionary.h"
#include "deauth.h"
#include "sd_manager.h"

// ==================== 全局实例 ====================
CommandLineInterface CLI;

// ==================== 构造函数/析构函数 ====================
CommandLineInterface::CommandLineInterface()
    : stream(&Serial)
    , running(false)
    , commandCount(0)
    , historyCount(0)
    , historyIndex(0)
    , inputPos(0) {
    memset(prompt, 0, sizeof(prompt));
    memset(inputBuffer, 0, sizeof(inputBuffer));
    memset(history, 0, sizeof(history));
    
    // 注册内置命令
    registerCommand("help", "h", "Show help information", "help [command]", cmdHelp);
    registerCommand("status", "st", "Show device status", "status", cmdStatus);
    registerCommand("scan", "sc", "Start WiFi scan", "scan [start|stop]", cmdScan);
    registerCommand("sniff", "sn", "Start/Stop packet sniffing", "sniff [start|stop]", cmdSniff);
    registerCommand("capture", "cap", "Capture handshake", "capture <bssid>", cmdCapture);
    registerCommand("deauth", "de", "Send deauth frames", "deauth <bssid> [station]", cmdDeauth);
    registerCommand("attack", "at", "Start dictionary attack", "attack <handshake_file>", cmdAttack);
    registerCommand("channel", "ch", "Set/Get channel", "channel [1-14]", cmdChannel);
    registerCommand("list", "ls", "List networks or files", "list [networks|files]", cmdList);
    registerCommand("select", "sel", "Select target network", "select <index>", cmdSelect);
    registerCommand("info", "i", "Show network info", "info [bssid]", cmdInfo);
    registerCommand("save", "s", "Save data to file", "save <filename>", cmdSave);
    registerCommand("load", "ld", "Load data from file", "load <filename>", cmdLoad);
    registerCommand("reset", "rst", "Reset device state", "reset", cmdReset);
    registerCommand("reboot", "rb", "Reboot device", "reboot", cmdReboot);
    registerCommand("config", "cfg", "Show/Set configuration", "config [key] [value]", cmdConfig);
    registerCommand("clear", "cls", "Clear screen", "clear", cmdClear);
    registerCommand("history", "hist", "Show command history", "history", cmdHistory);
    registerCommand("exit", "quit", "Exit CLI", "exit", cmdExit);
}

CommandLineInterface::~CommandLineInterface() {
    end();
}

// ==================== 初始化 ====================
bool CommandLineInterface::begin(Stream* s) {
    stream = s;
    running = true;
    setPrompt("sniffer> ");
    
    LOG_INFO("CLI initialized");
    return true;
}

void CommandLineInterface::end() {
    running = false;
}

// ==================== 输入处理 ====================
void CommandLineInterface::handleInput() {
    if (!stream || !stream->available()) return;
    
    char c = stream->read();
    
    // 处理退格
    if (c == '\b' || c == 127) {
        if (inputPos > 0) {
            inputPos--;
            inputBuffer[inputPos] = '\0';
            stream->print("\b \b");
        }
        return;
    }
    
    // 处理回车
    if (c == '\r' || c == '\n') {
        stream->println();
        
        if (inputPos > 0) {
            inputBuffer[inputPos] = '\0';
            addHistory(inputBuffer);
            processCommand(inputBuffer);
            
            // 清空缓冲区
            memset(inputBuffer, 0, sizeof(inputBuffer));
            inputPos = 0;
        }
        
        showPrompt();
        return;
    }
    
    // 添加字符
    if (inputPos < sizeof(inputBuffer) - 1 && c >= 32 && c < 127) {
        inputBuffer[inputPos++] = c;
        stream->print(c);
    }
}

void CommandLineInterface::processCommand(const char* cmd) {
    // 解析命令和参数
    char buffer[256];
    strncpy(buffer, cmd, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    // 去除前导空格
    char* p = buffer;
    while (*p == ' ') p++;
    
    // 提取命令名
    char* name = p;
    char* args = strchr(p, ' ');
    
    if (args) {
        *args = '\0';
        args++;
        // 跳过后续空格
        while (*args == ' ') args++;
    } else {
        args = "";
    }
    
    // 执行命令
    executeCommand(name, args);
}

// ==================== 命令注册 ====================
void CommandLineInterface::registerCommand(const char* name, const char* alias,
                                            const char* description, const char* usage,
                                            CommandCallback callback) {
    if (commandCount >= MAX_COMMANDS) return;
    
    Command& cmd = commands[commandCount++];
    cmd.name = name;
    cmd.alias = alias;
    cmd.description = description;
    cmd.usage = usage;
    cmd.callback = callback;
}

void CommandLineInterface::unregisterCommand(const char* name) {
    // 查找并移除命令
    for (int i = 0; i < commandCount; i++) {
        if (strcmp(commands[i].name, name) == 0) {
            // 移动后续命令
            for (int j = i; j < commandCount - 1; j++) {
                commands[j] = commands[j + 1];
            }
            commandCount--;
            return;
        }
    }
}

// ==================== 输出 ====================
void CommandLineInterface::print(const char* text) {
    if (stream) stream->print(text);
}

void CommandLineInterface::println(const char* text) {
    if (stream) stream->println(text);
}

void CommandLineInterface::printf(const char* fmt, ...) {
    if (!stream) return;
    
    char buffer[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);
    
    stream->print(buffer);
}

void CommandLineInterface::printError(const char* text) {
    println("");
    print("[ERROR] ");
    println(text);
}

void CommandLineInterface::printSuccess(const char* text) {
    print("[OK] ");
    println(text);
}

void CommandLineInterface::printInfo(const char* text) {
    print("[INFO] ");
    println(text);
}

void CommandLineInterface::printWarning(const char* text) {
    print("[WARN] ");
    println(text);
}

// ==================== 提示符 ====================
void CommandLineInterface::setPrompt(const char* p) {
    strncpy(prompt, p, sizeof(prompt) - 1);
    prompt[sizeof(prompt) - 1] = '\0';
}

void CommandLineInterface::showPrompt() {
    print(prompt);
}

// ==================== 帮助 ====================
void CommandLineInterface::showHelp() {
    println("");
    println("Available commands:");
    println("-------------------");
    
    for (int i = 0; i < commandCount; i++) {
        printf("  %-12s %-4s %s\n", 
               commands[i].name, 
               commands[i].alias,
               commands[i].description);
    }
    
    println("");
    println("Type 'help <command>' for detailed usage.");
}

void CommandLineInterface::showCommandHelp(const char* cmd) {
    Command* command = findCommand(cmd);
    if (!command) {
        printError("Unknown command");
        return;
    }
    
    println("");
    printf("Command: %s (%s)\n", command->name, command->alias);
    printf("Description: %s\n", command->description);
    printf("Usage: %s\n", command->usage);
}

// ==================== 历史记录 ====================
void CommandLineInterface::addHistory(const char* cmd) {
    if (strlen(cmd) == 0) return;
    
    // 检查是否与最后一条重复
    if (historyCount > 0 && strcmp(history[historyCount - 1], cmd) == 0) {
        return;
    }
    
    // 添加新记录
    if (historyCount < HISTORY_SIZE) {
        strncpy(history[historyCount], cmd, sizeof(history[0]) - 1);
        history[historyCount][sizeof(history[0]) - 1] = '\0';
        historyCount++;
    } else {
        // 循环覆盖
        for (int i = 0; i < HISTORY_SIZE - 1; i++) {
            strcpy(history[i], history[i + 1]);
        }
        strncpy(history[HISTORY_SIZE - 1], cmd, sizeof(history[0]) - 1);
    }
    
    historyIndex = historyCount;
}

void CommandLineInterface::showHistory() {
    println("");
    println("Command history:");
    
    for (int i = 0; i < historyCount; i++) {
        printf("  %d: %s\n", i + 1, history[i]);
    }
}

void CommandLineInterface::clearHistory() {
    memset(history, 0, sizeof(history));
    historyCount = 0;
    historyIndex = 0;
}

// ==================== 内部方法 ====================
void CommandLineInterface::executeCommand(const char* name, const char* args) {
    Command* cmd = findCommand(name);
    if (!cmd) {
        printError("Unknown command. Type 'help' for available commands.");
        return;
    }
    
    cmd->callback(args);
}

Command* CommandLineInterface::findCommand(const char* name) {
    for (int i = 0; i < commandCount; i++) {
        if (strcmp(commands[i].name, name) == 0 ||
            strcmp(commands[i].alias, name) == 0) {
            return &commands[i];
        }
    }
    return nullptr;
}

// ==================== 内置命令实现 ====================
void CommandLineInterface::cmdHelp(const char* args) {
    if (args && strlen(args) > 0) {
        CLI.showCommandHelp(args);
    } else {
        CLI.showHelp();
    }
}

void CommandLineInterface::cmdStatus(const char* args) {
    CLI.println("");
    CLI.println("Device Status:");
    CLI.println("--------------");
    CLI.printf("Firmware: %s\n", FIRMWARE_VERSION);
    CLI.printf("Mode: %d\n", currentMode);
    CLI.printf("Channel: %d\n", currentChannel);
    CLI.printf("Packets: %d\n", Sniffer.getTotalPackets());
    CLI.printf("Networks: %d\n", Sniffer.getNetworkCount());
    CLI.printf("Uptime: %d seconds\n", millis() / 1000);
    
    if (SDMgr.isReady()) {
        char info[64];
        SDMgr.getInfoString(info, sizeof(info));
        CLI.printf("SD Card: %s\n", info);
    }
}

void CommandLineInterface::cmdScan(const char* args) {
    if (strstr(args, "stop")) {
        Sniffer.stopScan();
        CLI.printSuccess("Scan stopped");
    } else {
        Sniffer.startScan();
        CLI.printSuccess("Scan started");
    }
}

void CommandLineInterface::cmdSniff(const char* args) {
    if (strstr(args, "stop")) {
        Sniffer.stopSniffing();
        CLI.printSuccess("Sniffing stopped");
    } else {
        Sniffer.startSniffing();
        CLI.printSuccess("Sniffing started");
    }
}

void CommandLineInterface::cmdCapture(const char* args) {
    if (!args || strlen(args) == 0) {
        CLI.printError("Usage: capture <bssid>");
        return;
    }
    
    uint8_t bssid[6];
    if (!parseMAC(args, bssid)) {
        CLI.printError("Invalid BSSID format");
        return;
    }
    
    Handshake.setTargetBSSID(bssid);
    Handshake.resetHandshake();
    currentMode = MODE_HANDSHAKE_CAPTURE;
    
    CLI.printSuccess("Handshake capture started");
}

void CommandLineInterface::cmdDeauth(const char* args) {
    if (!args || strlen(args) == 0) {
        CLI.printError("Usage: deauth <bssid> [station]");
        return;
    }
    
    // 解析参数
    char buffer[128];
    strncpy(buffer, args, sizeof(buffer) - 1);
    
    char* bssidStr = strtok(buffer, " ");
    char* staStr = strtok(nullptr, " ");
    
    uint8_t bssid[6];
    if (!parseMAC(bssidStr, bssid)) {
        CLI.printError("Invalid BSSID format");
        return;
    }
    
    Deauth.setTargetBSSID(bssid);
    
    if (staStr) {
        uint8_t sta[6];
        if (parseMAC(staStr, sta)) {
            Deauth.setTargetStation(sta);
        }
    }
    
    Deauth.startAttack();
    CLI.printSuccess("Deauth attack started");
}

void CommandLineInterface::cmdAttack(const char* args) {
    if (!args || strlen(args) == 0) {
        CLI.printError("Usage: attack <handshake_file>");
        return;
    }
    
    // 加载握手包
    // 这里简化处理，实际应该从文件加载
    CLI.printSuccess("Dictionary attack started");
}

void CommandLineInterface::cmdChannel(const char* args) {
    if (!args || strlen(args) == 0) {
        CLI.printf("Current channel: %d\n", currentChannel);
        return;
    }
    
    int ch = atoi(args);
    if (ch < 1 || ch > 14) {
        CLI.printError("Invalid channel (1-14)");
        return;
    }
    
    Sniffer.setChannel(ch);
    CLI.printf("Channel set to %d\n", ch);
}

void CommandLineInterface::cmdList(const char* args) {
    if (strstr(args, "network")) {
        CLI.println("");
        CLI.println("Discovered Networks:");
        CLI.println("--------------------");
        
        int count = Sniffer.getNetworkCount();
        for (int i = 0; i < count; i++) {
            const WiFiNetwork* net = Sniffer.getNetwork(i);
            if (net) {
                char bssid[18];
                macToString(net->bssid, bssid, sizeof(bssid));
                CLI.printf("%2d. %-20s [%s] CH:%d RSSI:%d %s\n",
                          i, net->ssid, bssid, net->channel, 
                          net->rssi, getAuthModeString(net->authMode));
            }
        }
    } else if (strstr(args, "file")) {
        SDMgr.printDirectory("/sdcard");
    } else {
        CLI.printError("Usage: list [networks|files]");
    }
}

void CommandLineInterface::cmdSelect(const char* args) {
    if (!args || strlen(args) == 0) {
        CLI.printError("Usage: select <index>");
        return;
    }
    
    int index = atoi(args);
    const WiFiNetwork* net = Sniffer.getNetwork(index);
    
    if (!net) {
        CLI.printError("Invalid network index");
        return;
    }
    
    Handshake.setTargetBSSID(net->bssid);
    Sniffer.setChannel(net->channel);
    
    CLI.printf("Selected: %s (CH:%d)\n", net->ssid, net->channel);
}

void CommandLineInterface::cmdInfo(const char* args) {
    // 显示当前目标信息
    if (Handshake.hasTarget()) {
        char info[256];
        Handshake.getHandshakeInfo(info, sizeof(info));
        CLI.println(info);
    } else {
        CLI.printInfo("No target selected");
    }
}

void CommandLineInterface::cmdSave(const char* args) {
    if (!args || strlen(args) == 0) {
        CLI.printError("Usage: save <filename>");
        return;
    }
    
    if (Handshake.saveToHCCAPX(args)) {
        CLI.printSuccess("Handshake saved");
    } else {
        CLI.printError("Failed to save handshake");
    }
}

void CommandLineInterface::cmdLoad(const char* args) {
    CLI.printInfo("Load functionality not implemented");
}

void CommandLineInterface::cmdReset(const char* args) {
    Sniffer.stopSniffing();
    Sniffer.stopScan();
    Deauth.stopAttack();
    DictAttack.stopAttack();
    Handshake.resetHandshake();
    
    currentMode = MODE_IDLE;
    CLI.printSuccess("Device reset");
}

void CommandLineInterface::cmdReboot(const char* args) {
    CLI.printInfo("Rebooting...");
    delay(1000);
    ESP.restart();
}

void CommandLineInterface::cmdConfig(const char* args) {
    // 显示配置
    CLI.println("");
    CLI.println("Configuration:");
    CLI.printf("Channel Hop Interval: %d ms\n", CHANNEL_HOP_INTERVAL);
    CLI.printf("Deauth Burst: %d\n", DEAUTH_BURST_COUNT);
    CLI.printf("Deauth Interval: %d ms\n", DEAUTH_INTERVAL_MS);
    CLI.printf("Dict Batch Size: %d\n", DICT_BATCH_SIZE);
    CLI.printf("Max Password Len: %d\n", MAX_PASSWORD_LENGTH);
}

void CommandLineInterface::cmdClear(const char* args) {
    for (int i = 0; i < 50; i++) {
        CLI.println("");
    }
}

void CommandLineInterface::cmdHistory(const char* args) {
    CLI.showHistory();
}

void CommandLineInterface::cmdExit(const char* args) {
    CLI.println("Goodbye!");
    // 实际应用中可能需要关闭串口或其他清理
}
