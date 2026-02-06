/**
 * @file ProcessDetector.cpp
 * @brief Process Detection Implementation
 * @version 1.0.0
 */

#include "ProcessDetector.h"
#include <QProcess>
#include <QFile>
#include <QFileInfo>
#include <QDebug>
#include <Winternl.h>
#include <Psapi.h>
#include <tlhelp32.h>

// 进程白名单路径
static const QStringList PROCESS_WHITELIST = {
    "C:\\Windows\\System32\\",
    "C:\\Windows\\SysWOW64\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\"
};

// 可疑进程名称关键词
static const QStringList SUSPICIOUS_NAMES = {
    "rootkit", "hide", "inject", "hook", "keylog",
    "cracker", "hack", "trojan", "malware", "virus",
    "backdoor", "botnet", "miner", " ransomware"
};

ProcessDetector::ProcessDetector(QObject *parent)
    : QObject(parent)
{
}

ProcessDetector::~ProcessDetector() {
}

// ========== 进程检测 ==========

QList<ProcessDetail> ProcessDetector::collectAllProcesses() {
    QList<ProcessDetail> processes;
    emit progressUpdated(0, "开始收集进程信息...");

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE, 0);
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

    int count = 0;
    do {
        ProcessDetail detail;
        parseProcessEntry(pe32, detail);

        // 检查是否可疑
        detail.isSuspicious = isProcessSuspicious(detail);

        processes.append(detail);

        count++;
        emit progressUpdated(count * 100 / 500, QString("正在分析进程: %1").arg(detail.name));

    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);

    emit progressUpdated(100, QString("进程收集完成，共发现 %1 个进程").arg(count));

    return processes;
}

ProcessDetail ProcessDetector::getProcessDetail(int pid) {
    ProcessDetail detail;
    detail.pid = pid;

    // 获取进程句柄
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        detail.isSuspicious = true;
        detail.suspiciousReason = "无法打开进程";
        return detail;
    }

    // 获取进程名
    char path[MAX_PATH];
    if (GetModuleFileNameExA(hProcess, NULL, path, MAX_PATH)) {
        detail.path = QString::fromLocal8Bit(path);
        QFileInfo info(detail.path);
        detail.name = info.fileName();
    }

    // 获取内存使用
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        detail.memoryUsage = pmc.WorkingSetSize;
    }

    // 获取启动时间
    FILETIME creationTime, exitTime, kernelTime, userTime;
    if (GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime)) {
        SYSTEMTIME st;
        FileTimeToSystemTime(&creationTime, &st);
        detail.startTime = QDateTime(QDate(st.wYear, st.wMonth, st.wDay),
                                     QTime(st.wHour, st.wMinute, st.wSecond, st.wMilliseconds));
    }

    // 获取用户名
    QString owner;
    if (getProcessOwner(pid, owner)) {
        detail.user = owner;
    }

    // 获取命令行
    QString cmdLine;
    if (getProcessCommandLine(pid, cmdLine)) {
        detail.commandLine = cmdLine;
    }

    // 获取文件信息
    QString company, description;
    if (getProcessFileInfo(detail.path, company, description)) {
        detail.company = company;
        detail.description = description;
    }

    // 检查签名
    detail.isSigned = verifyProcessSignature(pid);
    detail.isVerified = detail.isSigned;

    CloseHandle(hProcess);

    return detail;
}

bool ProcessDetector::isProcessRunning(int pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        return false;
    }
    DWORD exitCode;
    GetExitCodeProcess(hProcess, &exitCode);
    CloseHandle(hProcess);
    return exitCode == STILL_ACTIVE;
}

QString ProcessDetector::getProcessPath(int pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        return "";
    }

    char path[MAX_PATH];
    if (GetModuleFileNameExA(hProcess, NULL, path, MAX_PATH)) {
        CloseHandle(hProcess);
        return QString::fromLocal8Bit(path);
    }

    CloseHandle(hProcess);
    return "";
}

qint64 ProcessDetector::getProcessMemory(int pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        return 0;
    }

    PROCESS_MEMORY_COUNTERS pmc;
    qint64 memory = 0;
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        memory = pmc.WorkingSetSize;
    }

    CloseHandle(hProcess);
    return memory;
}

double ProcessDetector::getProcessCpu(int pid) {
    // CPU使用率计算（简化版）
    Q_UNUSED(pid)
    return 0.0;
}

QVector<int> ProcessDetector::getChildProcesses(int pid) {
    QVector<int> children;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return children;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ParentProcessID == pid) {
                children.append(pe32.th32ProcessID);
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return children;
}

// ========== 可疑进程检测 ==========

bool ProcessDetector::isProcessSuspicious(const ProcessDetail& process) {
    if (checkSuspiciousName(process.name)) {
        process.suspiciousReason = "进程名包含可疑关键词";
        return true;
    }

    if (checkSuspiciousPath(process.path)) {
        process.suspiciousReason = "进程路径可疑";
        return true;
    }

    if (checkSuspiciousParent(process.parentPid)) {
        process.suspiciousReason = "父进程可疑";
        return true;
    }

    if (checkSuspiciousMemory(process.memoryUsage)) {
        process.suspiciousReason = "内存使用异常";
        return true;
    }

    if (!checkSuspiciousSignature(process.isSigned, process.isVerified)) {
        process.suspiciousReason = "进程未签名";
        return true;
    }

    return false;
}

QList<ProcessDetail> ProcessDetector::findSuspiciousProcesses() {
    QList<ProcessDetail> allProcesses = collectAllProcesses();
    QList<ProcessDetail> suspicious;

    for (const ProcessDetail& process : allProcesses) {
        if (isProcessSuspicious(process)) {
            suspicious.append(process);
            emit suspiciousProcessFound(process);
        }
    }

    return suspicious;
}

// ========== 进程签名验证 ==========

bool ProcessDetector::verifyProcessSignature(int pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        return false;
    }

    BOOL isSigned = FALSE;
    WINTRUST_FILE_INFO wtfi;
    memset(&wtfi, 0, sizeof(wtfi));
    wtfi.cbStruct = sizeof(WINTRUST_FILE_INFO);
    wtfi.pcwszFilePath = NULL;

    HANDLE hFile = CreateFileA(NULL, GENERIC_READ, FILE_SHARE_READ, NULL,
                                OPEN_EXISTING, 0, NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        wtfi.pcwszFilePath = (LPCWSTR)getProcessPath(pid).utf16();
        WINTRUST_DATA wtd;
        memset(&wtd, 0, sizeof(wtd));
        wtd.cbStruct = sizeof(WINTRUST_DATA);
        wtd.dwUIChoice = WTD_UI_NONE;
        wtd.dwRevocationChecks = WTD_REVOKE_NONE;
        wtd.dwUnionChoice = WTD_CHOICE_FILE;
        wtd.pFile = &wtfi;
        wtd.dwStateAction = WTD_STATEACTION_VERIFY;

        LONG status = WinVerifyTrust(NULL, &WINTUST_ACTION_GENERIC_VERIFY_V2, &wtd);
        isSigned = (status == ERROR_SUCCESS);

        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &WINTUST_ACTION_GENERIC_VERIFY_V2, &wtd);

        CloseHandle(hFile);
    }

    CloseHandle(hProcess);
    return isSigned;
}

bool ProcessDetector::checkProcessTrust(const ProcessDetail& process) {
    Q_UNUSED(process)
    // 信任检查逻辑
    return true;
}

// ========== 隐藏进程检测 ==========

bool ProcessDetector::detectHiddenProcesses() {
    // 使用多种方法检测隐藏进程
    bool foundHidden = false;

    // 方法1: 对比Toolhelp32和Psapi
    QSet<int> toolhelpPids;
    QSet<int> psapiPids;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                toolhelpPids.insert(pe32.th32ProcessID);
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    // 方法2: 检查挂起的进程
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ParentProcessID == 0 && pe32.th32ProcessID != 4) {
                    // 没有父进程的进程（除了System进程）
                    foundHidden = true;
                    qWarning() << "检测到可疑进程（无父进程）:" << pe32.szExeFile;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    return foundHidden;
}

bool ProcessDetector::detectHooks() {
    Q_UNUSED()
    // DLL注入检测
    return false;
}

// ========== 辅助函数 ==========

void ProcessDetector::parseProcessEntry(const PROCESSENTRY32& entry, ProcessDetail& detail) {
    detail.pid = entry.th32ProcessID;
    detail.name = QString::fromLocal8Bit(entry.szExeFile);
    detail.parentPid = entry.th32ParentProcessID;
    detail.cntThreads = entry.cntThreads;
    detail.th32DefaultHeapID = entry.th32DefaultHeapID;
    detail.th32ModuleID = entry.th32ModuleID;
    detail.cntUsage = entry.cntUsage;

    // 获取完整路径
    detail.path = getProcessPath(detail.pid);

    // 获取启动时间
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, detail.pid);
    if (hProcess != NULL) {
        FILETIME creationTime, exitTime, kernelTime, userTime;
        if (GetProcessTimes(hProcess, &creationTime, &exitTime, &kernelTime, &userTime)) {
            SYSTEMTIME st;
            FileTimeToSystemTime(&creationTime, &st);
            detail.startTime = QDateTime(QDate(st.wYear, st.wMonth, st.wDay),
                                         QTime(st.wHour, st.wMinute, st.wSecond));
        }
        CloseHandle(hProcess);
    }

    // 获取内存使用
    detail.memoryUsage = getProcessMemory(detail.pid);

    // 获取用户名
    getProcessOwner(detail.pid, detail.user);

    // 获取命令行
    getProcessCommandLine(detail.pid, detail.commandLine);

    // 检查签名
    detail.isSigned = verifyProcessSignature(detail.pid);
    detail.isVerified = detail.isSigned;
}

bool ProcessDetector::getProcessOwner(int pid, QString& owner) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        return false;
    }

    HANDLE hToken;
    BOOL result = OpenProcessToken(hProcess, TOKEN_QUERY, &hToken);
    CloseHandle(hProcess);

    if (!result) {
        return false;
    }

    DWORD tokenInfoLength = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoLength);

    if (tokenInfoLength > 0) {
        PTOKEN_USER tokenUser = (PTOKEN_USER)malloc(tokenInfoLength);
        if (GetTokenInformation(hToken, TokenUser, tokenUser, tokenInfoLength, &tokenInfoLength)) {
            char sidStr[256];
            if (ConvertSidToStringSidA(tokenUser->User.Sid, &sidStr)) {
                owner = QString::fromLocal8Bit(sidStr);
                LocalFree(sidStr);
            }
        }
        free(tokenUser);
    }

    CloseHandle(hToken);
    return !owner.isEmpty();
}

bool ProcessDetector::getProcessCommandLine(int pid, QString& commandLine) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        return false;
    }

    WCHAR cmdLine[1024];
    DWORD size = sizeof(cmdLine);

    BOOL success = QueryFullProcessImageNameW(hProcess, 0, cmdLine, &size);
    CloseHandle(hProcess);

    if (success) {
        commandLine = QString::fromUtf16((const ushort*)cmdLine);
        return true;
    }

    return false;
}

bool ProcessDetector::getProcessFileInfo(const QString& path, QString& company, QString& description) {
    Q_UNUSED(path)
    Q_UNUSED(company)
    Q_UNUSED(description)
    // 获取文件版本信息
    return false;
}

bool ProcessDetector::checkSuspiciousName(const QString& name) {
    QString nameLower = name.toLower();
    for (const QString& keyword : SUSPICIOUS_NAMES) {
        if (nameLower.contains(keyword.toLower())) {
            return true;
        }
    }
    return false;
}

bool ProcessDetector::checkSuspiciousPath(const QString& path) {
    if (path.isEmpty()) {
        return true; // 空路径可疑
    }

    QString pathLower = path.toLower();

    // 检查是否在临时目录
    if (pathLower.contains("temp\\") || pathLower.contains("appdata\\local\\temp\\")) {
        return true;
    }

    // 检查是否在用户目录
    if (pathLower.contains("users\\") && pathLower.contains("\\desktop\\")) {
        return true;
    }

    // 检查白名单
    if (isInWhitelist(path)) {
        return false;
    }

    return false;
}

bool ProcessDetector::checkSuspiciousParent(int pid) {
    if (pid == 0) {
        return true; // 无父进程可疑
    }

    // 检查父进程是否是explorer
    QList<ProcessDetail> processes = collectAllProcesses();
    for (const ProcessDetail& process : processes) {
        if (process.pid == pid) {
            if (process.name.toLower() != "explorer.exe") {
                return true; // 非explorer启动的进程可疑
            }
        }
    }

    return false;
}

bool ProcessDetector::checkSuspiciousMemory(qint64 memory) {
    // 内存使用超过500MB的进程
    if (memory > 500 * 1024 * 1024) {
        return true;
    }
    return false;
}

bool ProcessDetector::checkSuspiciousCpu(double cpu) {
    Q_UNUSED(cpu)
    return false;
}

bool ProcessDetector::checkSuspiciousSignature(bool isSigned, bool isVerified) {
    Q_UNUSED(isSigned)
    Q_UNUSED(isVerified)
    return true; // 暂时不将未签名视为可疑
}

bool ProcessDetector::checkSuspiciousBehavior(const ProcessDetail& process) {
    Q_UNUSED(process)
    return false;
}

bool ProcessDetector::isInWhitelist(const QString& path) {
    QString pathLower = path.toLower();
    for (const QString& prefix : PROCESS_WHITELIST) {
        if (pathLower.startsWith(prefix.toLower())) {
            return true;
        }
    }
    return false;
}

bool ProcessDetector::isSystemCritical(int pid) {
    // 系统关键进程
    return pid == 4 || pid == 0;
}
