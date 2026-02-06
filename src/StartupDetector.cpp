/**
 * @file StartupDetector.cpp
 * @brief Startup Items and Scheduled Tasks Detection Implementation
 * @version 1.0.0
 */

#include "StartupDetector.h"
#include <QProcess>
#include <QDebug>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QSettings>
#include <WinReg/WinReg.hpp>
#include <shellapi.h>
#include <shlobj.h>

// 注册表启动项路径
const QStringList StartupDetector::REG_RUN_PATHS = {
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"
};

const QStringList StartupDetector::REG_RUN_ONCE_PATHS = {
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"
};

const QStringList StartupDetector::REG_USER_RUN_PATHS = {
    "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"
};

const QStringList StartupDetector::REG_POLICIES_PATHS = {
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"
};

// 启动文件夹路径
const QStringList StartupDetector::STARTUP_FOLDER_PATHS = {
    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    "C:\\Users\\All Users\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
};

// 可疑关键词
const QStringList StartupDetector::SUSPICIOUS_KEYWORDS = {
    "update", "patch", "crack", "keygen", "hack", "inject",
    "hook", "bot", "miner", " ransomware", "trojan", "backdoor",
    "rat", "stealer", "logger", "keylogger", "monitor"
};

const QStringList StartupDetector::SUSPICIOUS_PATHS = {
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\users\\public\\", "\\programdata\\temp\\",
    "\\windows\\temp\\", "\\临时"
};

const QStringList StartupDetector::KNOWN_GOOD_PUBLISHERS = {
    "Microsoft Corporation", "Google LLC", "Adobe Inc.",
    "Mozilla Corporation", "Apple Inc.", "Intel Corporation",
    "NVIDIA Corporation"
};

StartupDetector::StartupDetector(QObject *parent)
    : QObject(parent)
{
}

StartupDetector::~StartupDetector() {
}

// ========== 启动项检测 ==========

QList<StartupItem> StartupDetector::collectAllStartupItems() {
    QList<StartupItem> allItems;
    emit progressUpdated(0, "开始收集启动项...");

    // 收集注册表启动项
    emit progressUpdated(10, "正在扫描注册表启动项...");
    QList<StartupItem> registryItems = collectRegistryStartup();
    allItems.append(registryItems);

    // 收集服务启动项
    emit progressUpdated(30, "正在扫描服务启动项...");
    QList<StartupItem> serviceItems = collectServiceStartup();
    allItems.append(serviceItems);

    // 收集启动文件夹
    emit progressUpdated(50, "正在扫描启动文件夹...");
    QList<StartupItem> folderItems = collectFolderStartup();
    allItems.append(folderItems);

    // 收集WMI启动项
    emit progressUpdated(70, "正在扫描WMI启动项...");
    QList<StartupItem> wmiItems = collectWmiStartup();
    allItems.append(wmiItems);

    emit progressUpdated(100, QString("启动项收集完成，共发现 %1 个启动项").arg(allItems.size()));

    return allItems;
}

QList<StartupItem> StartupDetector::collectRegistryStartup() {
    QList<StartupItem> items;

    // 扫描系统级注册表启动项
    for (const QString& keyPath : REG_RUN_PATHS) {
        QList<StartupItem> keyItems = queryRegistryKey(keyPath, "Registry");
        items.append(keyItems);
    }

    // 扫描用户级注册表启动项
    for (const QString& keyPath : REG_USER_RUN_PATHS) {
        QList<StartupItem> keyItems = queryRegistryKey(keyPath, "Registry (User)");
        items.append(keyItems);
    }

    return items;
}

QList<StartupItem> StartupDetector::collectServiceStartup() {
    QList<StartupItem> items;

    QProcess process;
    process.start("cmd", QStringList() << "/c" << "sc query state= all");
    process.waitForFinished();

    QString output = process.readAllStandardOutput();
    QStringList lines = output.split("\n");

    QString currentService;
    StartupItem item;

    for (const QString& line : lines) {
        if (line.contains("SERVICE_NAME:")) {
            if (!currentService.isEmpty() && !item.path.isEmpty()) {
                item.type = "Service";
                item.isEnabled = (item.command.contains("demand") || item.command.contains("auto"));
                item.riskLevel = analyzeRiskLevel(item);
                items.append(item);
            }
            currentService = line.split(":")[1].trimmed();
            item = StartupItem();
            item.name = currentService;
            item.location = "Services";
        } else if (line.contains("DISPLAY_NAME:")) {
            item.description = line.split(":")[1].trimmed();
        } else if (line.contains("BINARY_PATH_NAME:")) {
            item.path = line.split(":")[1].trimmed();
            item.command = item.path;
        }
    }

    if (!currentService.isEmpty() && !item.path.isEmpty()) {
        item.type = "Service";
        items.append(item);
    }

    return items;
}

QList<StartupItem> StartupDetector::collectFolderStartup() {
    QList<StartupItem> items;

    // 获取当前用户的启动文件夹
    char appData[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, appData))) {
        QString userStartup = QString::fromLocal8Bit(appData);
        STARTUP_FOLDER_PATHS.append(userStartup);
    }

    // 扫描所有启动文件夹
    for (const QString& folderPath : STARTUP_FOLDER_PATHS) {
        QList<StartupItem> folderItems = queryStartupFolder(folderPath);
        items.append(folderItems);
    }

    return items;
}

QList<StartupItem> StartupDetector::collectWmiStartup() {
    QList<StartupItem> items;

    // 使用wmic检测WMI启动项
    QProcess process;
    process.start("cmd", QStringList() << "/c" << "wmic startup get Caption,Command,User");
    process.waitForFinished();

    QString output = process.readAllStandardOutput();
    QStringList lines = output.split("\n");

    for (const QString& line : lines) {
        if (line.contains("Caption") || line.isEmpty()) continue;

        StartupItem item;
        item.type = "WMI";

        QStringList parts = line.split(",");
        if (parts.size() >= 1) {
            item.name = parts[0].trimmed();
        }
        if (parts.size() >= 2) {
            item.command = parts[1].trimmed();
            item.path = item.command;
        }
        if (parts.size() >= 3) {
            item.user = parts[2].trimmed();
        }

        if (!item.name.isEmpty()) {
            item.riskLevel = analyzeRiskLevel(item);
            items.append(item);
        }
    }

    return items;
}

// ========== 计划任务检测 ==========

QList<ScheduledTask> StartupDetector::collectScheduledTasks() {
    QList<ScheduledTask> tasks;

    // 优先使用schtasks
    tasks = collectScheduledTasksSchtasks();

    // 如果schtasks结果为空，尝试PowerShell
    if (tasks.isEmpty()) {
        tasks = collectScheduledTasksPowerShell();
    }

    return tasks;
}

QList<ScheduledTask> StartupDetector::collectScheduledTasksSchtasks() {
    QList<ScheduledTask> tasks;

    QProcess process;
    process.start("cmd", QStringList() << "/c" << "schtasks /query /fo csv /v /nh");
    process.waitForFinished();

    QString output = process.readAllStandardOutput();
    QStringList lines = output.split("\n");

    for (const QString& line : lines) {
        if (line.isEmpty() || line.contains("TaskName")) continue;

        ScheduledTask task;

        // 解析CSV格式
        QStringList parts = line.split("\",\"");
        if (parts.size() > 0) {
            QString taskName = parts[0].remove("\"").trimmed();
            if (taskName.isEmpty()) continue;

            task.name = taskName;
            task.path = taskName;
        }
        if (parts.size() > 1) {
            task.status = parts[1].remove("\"").trimmed();
        }
        if (parts.size() > 2) {
            task.nextRunTime = parts[2].remove("\"").trimmed();
        }
        if (parts.size() > 3) {
            task.lastRunTime = parts[3].remove("\"").trimmed();
        }
        if (parts.size() > 4) {
            task.lastRunResult = parts[4].remove("\"").trimmed();
        }
        if (parts.size() > 5) {
            task.author = parts[5].remove("\"").trimmed();
        }
        if (parts.size() > 6) {
            task.description = parts[6].remove("\"").trimmed();
        }

        task.isEnabled = (task.status == "Ready" || task.status == "Running");

        if (!task.name.isEmpty()) {
            task.riskLevel = analyzeTaskRiskLevel(task);
            emit scheduledTaskFound(task);
            tasks.append(task);
        }
    }

    return tasks;
}

QList<ScheduledTask> StartupDetector::collectScheduledTasksPowerShell() {
    QList<ScheduledTask> tasks;

    QProcess process;
    QString psCmd = "Get-ScheduledTask | Select-Object TaskName,TaskPath,State,"
                   "NextRunTime,LastRunTime,Author,Description | ConvertTo-Csv -NoTypeInformation";
    process.start("powershell", QStringList() << "-Command" << psCmd);
    process.waitForFinished();

    QString output = process.readAllStandardOutput();
    QStringList lines = output.split("\n");

    for (const QString& line : lines) {
        if (line.isEmpty() || line.contains("TaskName")) continue;

        ScheduledTask task;
        task.type = "ScheduledTask";

        // 简单解析
        QStringList parts = line.split(",");
        if (parts.size() >= 1) {
            task.name = parts[0].remove("\"").trimmed();
        }

        if (!task.name.isEmpty()) {
            task.riskLevel = analyzeTaskRiskLevel(task);
            tasks.append(task);
        }
    }

    return tasks;
}

// ========== 可疑项检测 ==========

bool StartupDetector::isStartupItemSuspicious(const StartupItem& item) {
    return item.riskLevel >= 2;
}

bool StartupDetector::isScheduledTaskSuspicious(const ScheduledTask& task) {
    return task.riskLevel >= 2;
}

QList<StartupItem> StartupDetector::findSuspiciousStartupItems() {
    QList<StartupItem> allItems = collectAllStartupItems();
    QList<StartupItem> suspicious;

    for (const StartupItem& item : allItems) {
        if (isStartupItemSuspicious(item)) {
            suspicious.append(item);
            emit suspiciousItemFound(item);
        }
    }

    return suspicious;
}

QList<ScheduledTask> StartupDetector::findSuspiciousScheduledTasks() {
    QList<ScheduledTask> allTasks = collectScheduledTasks();
    QList<ScheduledTask> suspicious;

    for (const ScheduledTask& task : allTasks) {
        if (isScheduledTaskSuspicious(task)) {
            suspicious.append(task);
            emit suspiciousTaskFound(task);
        }
    }

    return suspicious;
}

// ========== 启动项管理 ==========

bool StartupDetector::disableStartupItem(const StartupItem& item) {
    Q_UNUSED(item)
    // 禁用启动项需要修改注册表或删除快捷方式
    return false;
}

bool StartupDetector::enableStartupItem(const StartupItem& item) {
    Q_UNUSED(item)
    return false;
}

bool StartupDetector::deleteStartupItem(const StartupItem& item) {
    Q_UNUSED(item)
    return false;
}

bool StartupDetector::deleteScheduledTask(const ScheduledTask& task) {
    QProcess process;
    QString cmd = QString("schtasks /Delete /TN \"%1\" /F").arg(task.name);
    process.start("cmd", QStringList() << "/c" << cmd);
    process.waitForFinished();

    return process.exitCode() == 0;
}

// ========== 辅助函数 ==========

QList<StartupItem> StartupDetector::queryRegistryKey(const QString& keyPath, const QString& location) {
    QList<StartupItem> items;

    // 解析注册表路径
    QString hiveStr = keyPath.section("\\", 0, 0);
    QString keyName = keyPath.section("\\", 1);

    HKEY hKey;
    if (hiveStr == "HKEY_LOCAL_MACHINE" || hiveStr == "HKLM") {
        hKey = HKEY_LOCAL_MACHINE;
    } else if (hiveStr == "HKEY_CURRENT_USER" || hiveStr == "HKCU") {
        hKey = HKEY_CURRENT_USER;
    } else if (hiveStr == "HKEY_CLASSES_ROOT" || hiveStr == "HKCR") {
        hKey = HKEY_CLASSES_ROOT;
    } else if (hiveStr == "HKEY_USERS" || hiveStr == "HKU") {
        hKey = HKEY_USERS;
    } else {
        return items;
    }

    // 打开注册表键
    HKEY hOpenedKey;
    std::wstring wKeyName = keyName.toStdWString();
    if (RegOpenKeyExW(hKey, wKeyName.c_str(), 0, KEY_READ, &hOpenedKey) != ERROR_SUCCESS) {
        return items;
    }

    // 枚举值
    wchar_t valueName[MAX_PATH];
    DWORD valueNameSize = MAX_PATH;
    DWORD index = 0;

    while (RegEnumValueW(hOpenedKey, index, valueName, &valueNameSize, NULL,
                         NULL, NULL, NULL) == ERROR_SUCCESS) {
        StartupItem item;
        item.type = location;
        item.location = keyPath;
        item.name = QString::fromStdWString(valueName);
        item.isEnabled = true;

        // 读取值数据
        BYTE data[MAX_PATH];
        DWORD dataSize = MAX_PATH;
        if (RegQueryValueExW(hOpenedKey, valueName, NULL, NULL, data, &dataSize) == ERROR_SUCCESS) {
            item.command = QString::fromLocal8Bit((char*)data, dataSize);
            item.path = item.command;
        }

        item.riskLevel = analyzeRiskLevel(item);
        emit startupItemFound(item);
        items.append(item);

        valueNameSize = MAX_PATH;
        index++;
    }

    RegCloseKey(hOpenedKey);
    return items;
}

QList<StartupItem> StartupDetector::queryStartupFolder(const QString& folderPath) {
    QList<StartupItem> items;

    QDir dir(folderPath);
    if (!dir.exists()) {
        return items;
    }

    // 获取文件夹中的所有文件
    QFileInfoList fileList = dir.entryInfoList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot);

    for (const QFileInfo& fileInfo : fileList) {
        StartupItem item;
        item.type = "StartupFolder";
        item.location = folderPath;
        item.name = fileInfo.fileName();
        item.path = fileInfo.absoluteFilePath();

        if (fileInfo.isSymLink()) {
            // 跳过快捷方式
            continue;
        }

        if (fileInfo.isDir()) {
            item.type = "StartupFolder";
        }

        // 获取文件发布者
        getFilePublisher(item.path, item.publisher);
        getFileDescription(item.path, item.description);

        item.isEnabled = true;
        item.lastModified = fileInfo.lastModified();

        item.riskLevel = analyzeRiskLevel(item);
        emit startupItemFound(item);
        items.append(item);
    }

    return items;
}

bool StartupDetector::readRegistryValue(HKEY hKey, const QString& valueName, QString& valueData) {
    Q_UNUSED(hKey)
    Q_UNUSED(valueName)
    Q_UNUSED(valueData)
    return false;
}

bool StartupDetector::getFilePublisher(const QString& path, QString& publisher) {
    Q_UNUSED(path)
    Q_UNUSED(publisher)
    return false;
}

bool StartupDetector::getFileDescription(const QString& path, QString& description) {
    Q_UNUSED(path)
    Q_UNUSED(description)
    return false;
}

bool StartupDetector::getFileVersion(const QString& path, QString& version) {
    Q_UNUSED(path)
    Q_UNUSED(version)
    return false;
}

int StartupDetector::analyzeRiskLevel(const StartupItem& item) {
    // 检查发布者
    for (const QString& goodPublisher : KNOWN_GOOD_PUBLISHERS) {
        if (item.publisher.contains(goodPublisher, Qt::CaseInsensitive)) {
            return 0; // 安全
        }
    }

    // 检查名称中的可疑关键词
    QString nameLower = item.name.toLower();
    for (const QString& keyword : SUSPICIOUS_KEYWORDS) {
        if (nameLower.contains(keyword.toLower())) {
            return 3; // 高风险
        }
    }

    // 检查路径中的可疑位置
    QString pathLower = item.path.toLower();
    for (const QString& susPath : SUSPICIOUS_PATHS) {
        if (pathLower.contains(susPath.toLower())) {
            return 3; // 高风险
        }
    }

    // 检查空名称或空路径
    if (item.name.isEmpty() || item.path.isEmpty()) {
        return 3;
    }

    // 检查系统路径
    if (pathLower.contains("windows\\system32") || pathLower.contains("program files")) {
        return 0; // 可能是系统组件
    }

    // 默认为中风险
    return 2;
}

int StartupDetector::analyzeTaskRiskLevel(const ScheduledTask& task) {
    // 检查作者
    for (const QString& goodPublisher : KNOWN_GOOD_PUBLISHERS) {
        if (task.author.contains(goodPublisher, Qt::CaseInsensitive)) {
            return 0; // 安全
        }
    }

    // 检查任务名称中的可疑关键词
    QString nameLower = task.name.toLower();
    for (const QString& keyword : SUSPICIOUS_KEYWORDS) {
        if (nameLower.contains(keyword.toLower())) {
            return 3; // 高风险
        }
    }

    // 检查操作中的可疑命令
    for (const QString& action : task.actions) {
        QString actionLower = action.toLower();
        for (const QString& keyword : SUSPICIOUS_KEYWORDS) {
            if (actionLower.contains(keyword.toLower())) {
                return 3; // 高风险
            }
        }
    }

    // 检查触发器中的可疑时间
    for (const QString& trigger : task.triggers) {
        QString triggerLower = trigger.toLower();
        if (triggerLower.contains("logon") || triggerLower.contains("startup")) {
            // 登录或启动时执行的任务需要检查
            if (task.author.isEmpty() || task.author == "N/A") {
                return 2; // 中风险
            }
        }
    }

    return 0; // 默认为安全
}

bool StartupDetector::executeCommand(const QString& command, QString& output) {
    QProcess process;
    process.start("cmd", QStringList() << "/c" << command);
    process.waitForFinished();

    output = process.readAllStandardOutput();
    return process.exitCode() == 0;
}
