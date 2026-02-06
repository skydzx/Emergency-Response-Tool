#include "SystemInfoCollector.h"
#include <QProcess>
#include <QJsonDocument>
#include <QJsonArray>
#include <QRegularExpression>
#include <QDebug>
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <userenv.h>
#include <sddl.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "userenv.lib")

SystemInfoCollector::SystemInfoCollector(QObject *parent)
    : QObject(parent)
{
}

SystemInfoCollector::~SystemInfoCollector() {
}

// ========== 系统信息收集 ==========

SystemInfo SystemInfoCollector::collectSystemInfo() {
    SystemInfo info;

    info.osVersion = collectOSVersion();
    info.computerName = collectComputerName();
    info.userName = collectUserName();
    info.processorCount = collectProcessorCount();
    info.memoryInfo = collectMemoryInfo();
    info.diskInfo = collectDiskInfo();
    info.systemTime = QDateTime::currentDateTime();

    // 获取系统根目录
    char systemDir[MAX_PATH];
    GetSystemDirectoryA(systemDir, MAX_PATH);
    info.systemRoot = QString::fromLocal8Bit(systemDir);

    // 获取系统架构
    SYSTEM_INFO sysInfo;
    GetNativeSystemInfo(&sysInfo);
    if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
        info.architecture = "x64 (64-bit)";
    } else if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
        info.architecture = "x86 (32-bit)";
    } else {
        info.architecture = "Unknown";
    }

    // 获取系统版本和构建号
    OSVERSIONINFOEX osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    GetVersionEx((OSVERSIONINFO*)&osvi);

    info.osBuild = QString("Build %1").arg(osvi.dwBuildNumber);

    emit infoCollected("system", QVariant::fromValue(info));

    return info;
}

QString SystemInfoCollector::collectOSVersion() {
    QProcess process;
    process.start("cmd", QStringList() << "/c" << "ver");
    process.waitForFinished();

    QString output = process.readAllStandardOutput().trimmed();
    if (output.isEmpty()) {
        // 备用方法：使用wmic
        process.start("cmd", QStringList() << "/c" << "wmic os get Caption,Version /value");
        process.waitForFinished();
        output = process.readAllStandardOutput().trimmed();
    }

    return output;
}

QString SystemInfoCollector::collectComputerName() {
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;

    if (GetComputerNameA(computerName, &size)) {
        return QString::fromLocal8Bit(computerName);
    }

    return "Unknown";
}

QString SystemInfoCollector::collectUserName() {
    char userName[MAX_PATH + 1];
    DWORD size = MAX_PATH + 1;

    if (GetUserNameA(userName, &size)) {
        return QString::fromLocal8Bit(userName);
    }

    return "Unknown";
}

int SystemInfoCollector::collectProcessorCount() {
    SYSTEM_INFO sysInfo;
    GetNativeSystemInfo(&sysInfo);
    return sysInfo.dwNumberOfProcessors;
}

QString SystemInfoCollector::collectMemoryInfo() {
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(MEMORYSTATUSEX);

    if (GlobalMemoryStatusEx(&memoryStatus)) {
        DWORD memoryLoad = memoryStatus.dwMemoryLoad;
        ULONGLONG totalPhys = memoryStatus.ullTotalPhys;
        ULONGLONG availPhys = memoryStatus.ullAvailPhys;
        ULONGLONG totalPageFile = memoryStatus.ullTotalPageFile;
        ULONGLONG availPageFile = memoryStatus.ullAvailPageFile;

        return QString("Memory Load: %1%%, Total: %2 GB, Available: %3 GB")
            .arg(memoryLoad)
            .arg(totalPhys / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2)
            .arg(availPhys / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
    }

    return "Unknown";
}

QString SystemInfoCollector::collectDiskInfo() {
    QString result;
    DWORD driveMask = GetLogicalDrives();

    for (int i = 0; i < 26; ++i) {
        if (driveMask & (1 << i)) {
            char driveLetter = 'A' + i;
            QString drivePath = QString("%1:").arg(driveLetter);

            UINT driveType = GetDriveTypeA(drivePath.toLocal8Bit().constData());

            if (driveType == DRIVE_FIXED || driveType == DRIVE_REMOTE) {
                ULARGE_INTEGER freeBytesAvailable;
                ULARGE_INTEGER totalBytes;
                ULARGE_INTEGER totalFreeBytes;

                if (GetDiskFreeSpaceExA(drivePath.toLocal8Bit().constData(),
                    &freeBytesAvailable, &totalBytes, &totalFreeBytes)) {
                    QString driveTypeStr;
                    switch (driveType) {
                    case DRIVE_FIXED: driveTypeStr = "Local Disk"; break;
                    case DRIVE_REMOTE: driveTypeStr = "Network Drive"; break;
                    default: driveTypeStr = "Other"; break;
                    }

                    result += QString("%1 (%2): Total: %3 GB, Free: %4 GB; ")
                        .arg(drivePath)
                        .arg(driveTypeStr)
                        .arg(totalBytes.QuadPart / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2)
                        .arg(totalFreeBytes.QuadPart / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
                }
            }
        }
    }

    return result;
}

// ========== 进程信息收集 ==========

QList<ProcessInfo> SystemInfoCollector::collectProcesses() {
    QList<ProcessInfo> processes;
    emit progressUpdated(0, "开始收集进程信息...");

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        emit errorOccurred("无法创建进程快照");
        return processes;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        emit errorOccurred("无法遍历进程列表");
        return processes;
    }

    int totalProcesses = 0;
    do {
        ProcessInfo info;
        info.pid = pe32.th32ProcessID;
        info.name = QString::fromLocal8Bit(pe32.szExeFile);
        info.parentPid = QString::number(pe32.th32ParentProcessID);
        info.isSuspended = false;

        // 获取进程详细信息
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
        if (hProcess != NULL) {
            // 获取进程路径
            char path[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, NULL, path, MAX_PATH)) {
                info.path = QString::fromLocal8Bit(path);
            }

            // 获取进程内存使用
            PROCESS_MEMORY_COUNTERS pmc;
            if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                info.memoryUsage = pmc.WorkingSetSize / 1024; // KB
            }

            // 获取进程用户名
            HANDLE hToken;
            if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
                DWORD tokenInfoLength = 0;
                GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoLength);

                if (tokenInfoLength > 0) {
                    TOKEN_USER* tokenUser = (TOKEN_USER*)malloc(tokenInfoLength);
                    if (GetTokenInformation(hToken, TokenUser, tokenUser, tokenInfoLength, &tokenInfoLength)) {
                        char* sidStr = NULL;
                        if (ConvertSidToStringSidA(tokenUser->User.Sid, &sidStr)) {
                            info.user = QString::fromLocal8Bit(sidStr);
                            LocalFree(sidStr);
                        }
                    }
                    free(tokenUser);
                }
                CloseHandle(hToken);
            }

            // 检查进程签名
            info.isSigned = false;
            info.isVerified = false;

            CloseHandle(hProcess);
        }

        // 收集命令行参数
        QProcess cmdProcess;
        cmdProcess.start("cmd", QStringList() << "/c" << QString("wmic process where \"ProcessID=%1\" get CommandLine").arg(info.pid));
        cmdProcess.waitForFinished(2000);
        QString cmdOutput = cmdProcess.readAllStandardOutput();
        QStringList lines = cmdOutput.split("\n");
        if (lines.size() > 1) {
            info.commandLine = lines[1].trimmed();
        }

        // 判断是否为可疑进程
        info.isSuspicious = isProcessSuspicious(info);

        emit progressUpdated(50, QString("正在分析进程: %1").arg(info.name));

        processes.append(info);
        totalProcesses++;

    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);

    emit progressUpdated(100, QString("进程收集完成，共发现 %1 个进程").arg(totalProcesses));

    return processes;
}

ProcessInfo SystemInfoCollector::parseProcessInfo(const QString& line) {
    Q_UNUSED(line)
    ProcessInfo info;
    return info;
}

bool SystemInfoCollector::isProcessSuspicious(const ProcessInfo& process) {
    // 可疑进程特征检查
    QString nameLower = process.name.toLower();

    // 检查进程名是否为空
    if (nameLower.isEmpty()) {
        process.suspiciousReason = "进程名为空";
        return true;
    }

    // 检查是否有隐藏进程特征
    if (nameLower.contains("rootkit") || nameLower.contains("hide") || nameLower.contains("inject")) {
        process.suspiciousReason = "包含可疑关键词";
        return true;
    }

    // 检查路径是否为空或可疑
    if (process.path.isEmpty()) {
        process.suspiciousReason = "进程路径为空";
        return true;
    }

    QString pathLower = process.path.toLower();
    if (pathLower.contains("temp\\") || pathLower.contains("appdata\\local\\temp\\")) {
        process.suspiciousReason = "进程位于临时目录";
        return true;
    }

    // 检查是否未签名
    if (!process.isSigned) {
        process.suspiciousReason = "进程未签名";
        return true;
    }

    return false;
}

// ========== 服务信息收集 ==========

QList<ServiceInfo> SystemInfoCollector::collectServices() {
    QList<ServiceInfo> services;
    emit progressUpdated(0, "开始收集服务信息...");

    QProcess process;
    process.start("cmd", QStringList() << "/c" << "sc query state= all");
    process.waitForFinished();

    QString output = process.readAllStandardOutput();
    QStringList lines = output.split("\n");

    ServiceInfo currentService;
    bool inService = false;

    for (const QString& line : lines) {
        if (line.contains("SERVICE_NAME:")) {
            if (inService) {
                services.append(currentService);
            }
            currentService = ServiceInfo();
            currentService.name = line.split(":")[1].trimmed();
            inService = true;
        } else if (line.contains("DISPLAY_NAME:")) {
            currentService.displayName = line.split(":")[1].trimmed();
        } else if (line.contains("TYPE:")) {
            currentService.status = line.split(":")[1].trimmed();
        } else if (line.contains("STATE:")) {
            QString state = line.split(":")[1].trimLeft().trimmed();
            if (state.contains("RUNNING")) {
                currentService.status = "Running";
            } else if (state.contains("STOPPED")) {
                currentService.status = "Stopped";
            }
        } else if (line.contains("BINARY_PATH_NAME:")) {
            currentService.path = line.split(":")[1].trimmed();
        }
    }

    if (inService) {
        services.append(currentService);
    }

    emit progressUpdated(100, QString("服务收集完成，共发现 %1 个服务").arg(services.size()));

    return services;
}

bool SystemInfoCollector::isServiceSuspicious(const ServiceInfo& service) {
    Q_UNUSED(service)
    // 服务可疑性检查逻辑
    return false;
}

// ========== 用户信息收集 ==========

QList<UserInfo> SystemInfoCollector::collectUsers() {
    QList<UserInfo> users;
    emit progressUpdated(0, "开始收集用户信息...");

    QProcess process;
    process.start("cmd", QStringList() << "/c" << "net user");
    process.waitForFinished();

    QString output = process.readAllStandardOutput();
    QStringList lines = output.split("\n");

    // 解析net user输出
    for (const QString& line : lines) {
        if (line.contains("----")) continue;

        QString username = line.trimmed();
        if (username.isEmpty()) continue;

        UserInfo user;
        user.name = username;

        // 获取用户详细信息
        QProcess detailProcess;
        detailProcess.start("cmd", QStringList() << "/c" << QString("net user \"%1\"").arg(username));
        detailProcess.waitForFinished();

        QString detailOutput = detailProcess.readAllStandardOutput();

        // 解析详细信息
        if (detailOutput.contains("Account active")) {
            if (detailOutput.contains("No")) {
                user.isDisabled = true;
            }
        }

        if (detailOutput.contains("Password last set")) {
            // 提取密码最后设置时间
        }

        if (detailOutput.contains("logon")) {
            QStringList parts = detailOutput.split("\n");
            for (const QString& part : parts) {
                if (part.contains("logon")) {
                    user.lastLogin = QDateTime::currentDateTime();
                    break;
                }
            }
        }

        users.append(user);
    }

    emit progressUpdated(100, QString("用户收集完成，共发现 %1 个用户").arg(users.size()));

    return users;
}

bool SystemInfoCollector::isUserSuspicious(const UserInfo& user) {
    Q_UNUSED(user)
    // 用户可疑性检查逻辑
    return false;
}

// ========== 启动项收集 ==========

QList<StartupInfo> SystemInfoCollector::collectStartupItems() {
    QList<StartupInfo> startupItems;
    emit progressUpdated(0, "开始收集启动项信息...");

    // 1. 检查注册表启动项
    QStringList registryPaths = {
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"
    };

    QProcess regProcess;
    for (const QString& regPath : registryPaths) {
        regProcess.start("cmd", QStringList() << "/c" << QString("reg query \"%1\"").arg(regPath));
        regProcess.waitForFinished();

        QString output = regProcess.readAllStandardOutput();
        QStringList lines = output.split("\n");

        for (const QString& line : lines) {
            if (line.contains(regPath)) continue;

            StartupInfo info;
            info.location = regPath;
            info.type = "Registry";

            QStringList parts = line.trimmed().split("    ");
            if (parts.size() >= 2) {
                info.name = parts[0].simplified();
                info.path = parts[1].simplified();
            }

            if (!info.name.isEmpty() && !info.path.isEmpty()) {
                startupItems.append(info);
            }
        }
    }

    // 2. 检查启动文件夹
    QStringList startupFolders = {
        QString::fromLocal8Bit(getenv("APPDATA")) + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        QString::fromLocal8Bit(getenv("USERPROFILE")) + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    };

    for (const QString& folder : startupFolders) {
        QDir dir(folder);
        if (dir.exists()) {
            QFileInfoList files = dir.entryInfoList(QDir::Files | QDir::Dirs | QDir::NoDotAndDotDot);

            for (const QFileInfo& fileInfo : files) {
                StartupInfo info;
                info.name = fileInfo.fileName();
                info.path = fileInfo.absoluteFilePath();
                info.location = folder;
                info.type = "StartupFolder";

                startupItems.append(info);
            }
        }
    }

    emit progressUpdated(100, QString("启动项收集完成，共发现 %1 个启动项").arg(startupItems.size()));

    return startupItems;
}

bool SystemInfoCollector::isStartupItemSuspicious(const StartupInfo& item) {
    Q_UNUSED(item)
    // 启动项可疑性检查逻辑
    return false;
}

// ========== 计划任务收集 ==========

QList<QMap<QString, QVariant>> SystemInfoCollector::collectScheduledTasks() {
    QList<QMap<QString, QVariant>> tasks;
    emit progressUpdated(0, "开始收集计划任务...");

    QProcess process;
    process.start("cmd", QStringList() << "/c" << "schtasks /query /fo csv /v");
    process.waitForFinished();

    QString output = process.readAllStandardOutput();
    QStringList lines = output.split("\n");

    for (const QString& line : lines) {
        if (line.contains("TaskName") || line.isEmpty()) continue;

        QMap<QString, QVariant> task;
        QStringList parts = line.split("\",\"");

        if (parts.size() > 0) {
            task["TaskName"] = parts[0].remove("\"").trimmed();
        }
        if (parts.size() > 1) {
            task["Status"] = parts[1].remove("\"").trimmed();
        }
        if (parts.size() > 2) {
            task["NextRunTime"] = parts[2].remove("\"").trimmed();
        }

        if (!task["TaskName"].toString().isEmpty()) {
            tasks.append(task);
        }
    }

    emit progressUpdated(100, QString("计划任务收集完成，共发现 %1 个任务").arg(tasks.size()));

    return tasks;
}

// ========== 网络连接收集 ==========

QList<QMap<QString, QVariant>> SystemInfoCollector::collectNetworkConnections() {
    QList<QMap<QString, QVariant>> connections;
    emit progressUpdated(0, "开始收集网络连接...");

    // 使用netstat收集网络连接
    QProcess process;
    process.start("cmd", QStringList() << "/c" << "netstat -ano");
    process.waitForFinished();

    QString output = process.readAllStandardOutput();
    QStringList lines = output.split("\n");

    QRegularExpression ipRegex(R"((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+))");
    QRegularExpressionMatch match;

    for (const QString& line : lines) {
        if (line.contains("Proto") || line.isEmpty()) continue;

        QStringList parts = line.simplified().split(" ");

        if (parts.size() >= 4) {
            QMap<QString, QVariant> conn;
            conn["protocol"] = parts[0];
            conn["localAddress"] = parts[1];
            conn["remoteAddress"] = parts[2];
            conn["state"] = parts[3];

            if (parts.size() >= 5) {
                conn["processId"] = parts[4];
            }

            // 解析本地地址和端口
            match = ipRegex.match(parts[1]);
            if (match.hasMatch()) {
                conn["localAddress"] = match.captured(1);
                conn["localPort"] = match.captured(2).toInt();
            }

            // 解析远程地址和端口
            match = ipRegex.match(parts[2]);
            if (match.hasMatch()) {
                conn["remoteAddress"] = match.captured(1);
                conn["remotePort"] = match.captured(2).toInt();
            }

            connections.append(conn);
        }
    }

    emit progressUpdated(100, QString("网络连接收集完成，共发现 %1 个连接").arg(connections.size()));

    return connections;
}

// ========== 辅助函数 ==========

bool SystemInfoCollector::executeCommand(const QString& command, QString& output) {
    QProcess process;
    process.start("cmd", QStringList() << "/c" << command);
    process.waitForFinished();

    output = process.readAllStandardOutput();
    return process.exitCode() == 0;
}

QStringList SystemInfoCollector::splitLines(const QString& output) {
    return output.split("\n", Qt::SkipEmptyParts);
}

QString SystemInfoCollector::extractValue(const QString& line, const QString& key) {
    Q_UNUSED(line)
    Q_UNUSED(key)
    return QString();
}
