/**
 * @file cli.h
 * @brief Command Line Interface Module
 * 
 * 命令行接口模块
 * 提供串口命令交互功能
 */

#ifndef CLI_H
#define CLI_H

#include "config.h"

// ==================== 命令回调类型 ====================

typedef void (*CommandCallback)(const char* args);

// ==================== 命令结构 ====================

struct Command {
    const char* name;
    const char* alias;
    const char* description;
    const char* usage;
    CommandCallback callback;
};

// ==================== 类定义 ====================

class CommandLineInterface {
public:
    CommandLineInterface();
    ~CommandLineInterface();

    // 初始化和清理
    bool begin(Stream* stream = &Serial);
    void end();
    bool isRunning() const { return running; }

    // 主循环处理
    void handleInput();
    void processCommand(const char* cmd);

    // 命令注册
    void registerCommand(const char* name, const char* alias, 
                         const char* description, const char* usage,
                         CommandCallback callback);
    void unregisterCommand(const char* name);

    // 输出
    void print(const char* text);
    void println(const char* text);
    void printf(const char* fmt, ...);
    void printError(const char* text);
    void printSuccess(const char* text);
    void printInfo(const char* text);
    void printWarning(const char* text);

    // 提示符
    void setPrompt(const char* prompt);
    void showPrompt();

    // 帮助
    void showHelp();
    void showCommandHelp(const char* cmd);

    // 历史记录
    void addHistory(const char* cmd);
    void showHistory();
    void clearHistory();

private:
    Stream* stream;
    bool running;
    char prompt[16];
    
    // 输入缓冲区
    char inputBuffer[256];
    uint8_t inputPos;
    
    // 命令列表
    static const int MAX_COMMANDS = 32;
    Command commands[MAX_COMMANDS];
    int commandCount;
    
    // 历史记录
    static const int HISTORY_SIZE = 10;
    char history[HISTORY_SIZE][256];
    int historyCount;
    int historyIndex;
    
    // 内部方法
    void executeCommand(const char* name, const char* args);
    Command* findCommand(const char* name);
    void parseArguments(const char* args, char** argv, int* argc, int maxArgs);
    
    // 内置命令
    static void cmdHelp(const char* args);
    static void cmdStatus(const char* args);
    static void cmdScan(const char* args);
    static void cmdSniff(const char* args);
    static void cmdCapture(const char* args);
    static void cmdDeauth(const char* args);
    static void cmdAttack(const char* args);
    static void cmdChannel(const char* args);
    static void cmdList(const char* args);
    static void cmdSelect(const char* args);
    static void cmdInfo(const char* args);
    static void cmdSave(const char* args);
    static void cmdLoad(const char* args);
    static void cmdReset(const char* args);
    static void cmdReboot(const char* args);
    static void cmdConfig(const char* args);
    static void cmdClear(const char* args);
    static void cmdHistory(const char* args);
    static void cmdExit(const char* args);
};

// ==================== 全局实例 ====================
extern CommandLineInterface CLI;

// ==================== 辅助宏 ====================
#define CLI_PRINT(fmt, ...) CLI.printf(fmt, ##__VA_ARGS__)
#define CLI_ERROR(fmt, ...) CLI.printError(fmt, ##__VA_ARGS__)
#define CLI_SUCCESS(fmt, ...) CLI.printSuccess(fmt, ##__VA_ARGS__)
#define CLI_INFO(fmt, ...) CLI.printInfo(fmt, ##__VA_ARGS__)
#define CLI_WARN(fmt, ...) CLI.printWarning(fmt, ##__VA_ARGS__)

#endif // CLI_H
