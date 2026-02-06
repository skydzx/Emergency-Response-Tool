/**
 * @file LogAnalyzer.cpp
 * @brief Log Analysis Implementation
 * @version 1.0.0
 */

#include "LogAnalyzer.h"
#include <QFile>
#include <QTextStream>
#include <QDebug>
#include <QDir>
#include <QDateTime>
#include <QCryptographicHash>

// 关键安全事件ID
const QMap<int, QString> LogAnalyzer::CRITICAL_EVENT_IDS = {
    {4624, "账户登录成功"},
    {4625, "账户登录失败"},
    {4634, "账户注销"},
    {4647, "用户启动注销"},
    {4648, "使用显式凭据尝试登录"},
    {4672, "特权分配"},
    {4673, "特权服务调用"},
    {4674, "管理特权操作"},
    {4688, "新进程已创建"},
    {4689, "进程已退出"},
    {4697, "系统中已安装服务"},
    {4719, "系统审计策略已更改"},
    {4720, "已创建用户账户"},
    {4722, "已启用用户账户"},
    {4723, "尝试更改账户密码"},
    {4724, "尝试重置账户密码"},
    {4725, "已禁用用户账户"},
    {4726, "已删除用户账户"},
    {4738, "已更改用户账户"},
    {4740, "用户账户被锁定"},
    {4767, "尝试重置账户密码"},
    {4964, "特别指定组已添加到登录"},
    {5145, "网络共享对象检查"}
};

// 常见安全事件ID
const QMap<int, QString> LogAnalyzer::SECURITY_EVENT_IDS = {
    {4624, "登录成功"},
    {4625, "登录失败"},
    {4634, "注销"},
    {4648, "凭据登录"},
    {4672, "特权登录"},
    {4688, "进程创建"},
    {4689, "进程退出"},
    {4697, "服务安装"},
    {4719, "策略更改"},
    {4720, "用户创建"},
    {4722, "用户启用"},
    {4723, "密码更改"},
    {4724, "密码重置"},
    {4725, "用户禁用"},
    {4726, "用户删除"},
    {4738, "用户更改"},
    {4740, "账户锁定"}
};

// 暴力破解相关事件ID
const QVector<int> LogAnalyzer::BRUTE_FORCE_EVENT_IDS = {
    4625,  // 登录失败
    4767,  // 密码重置失败
    4740   // 账户锁定
};

// 可疑IP模式
const QRegularExpression LogAnalyzer::SUSPICIOUS_IP_PATTERN =
    QRegularExpression(R"((?:\d{1,3}\.){3}\d{1,3})");

// 危险URL模式
const QVector<QRegularExpression> LogAnalyzer::DANGEROUS_URL_PATTERNS = {
    QRegularExpression(R"(\.\./)", QRegularExpression::CaseInsensitiveOption),
    QRegularExpression(R"(%00)", QRegularExpression::CaseInsensitiveOption),
    QRegularExpression(R"(<script)", QRegularExpression::CaseInsensitiveOption),
    QRegularExpression(R"('.*OR.*'.*=)", QRegularExpression::CaseInsensitiveOption),
    QRegularExpression(R"(UNION\s+SELECT)", QRegularExpression::CaseInsensitiveOption),
    QRegularExpression(R"(DROP\s+TABLE)", QRegularExpression::CaseInsensitiveOption),
    QRegularExpression(R"(xp_cmdshell)", QRegularExpression::CaseInsensitiveOption),
    QRegularExpression(R"(eval\s*\()", QRegularExpression::CaseInsensitiveOption),
    QRegularExpression(R"(base64_decode\s*\()", QRegularExpression::CaseInsensitiveOption)
};

LogAnalyzer::LogAnalyzer(QObject *parent)
    : QObject(parent)
{
}

LogAnalyzer::~LogAnalyzer() {
}

// ========== 日志扫描 ==========

LogScanResult LogAnalyzer::scanAllLogs() {
    LogScanResult result;
    result.startTime = QDateTime::currentDateTime();
    result.totalEntries = 0;
    result.errorCount = 0;
    result.warningCount = 0;
    result.infoCount = 0;
    result.anomalyCount = 0;

    emit progressUpdated(0, "开始扫描所有日志...");

    // 扫描Windows安全日志
    emit progressUpdated(20, "正在扫描安全日志...");
    LogScanResult securityResult = scanWindowsEventLog("Security");
    result.totalEntries += securityResult.totalEntries;
    result.securityEvents = securityResult.entries;
    result.errorCount += securityResult.errorCount;

    // 扫描系统日志
    emit progressUpdated(50, "正在扫描系统日志...");
    LogScanResult systemResult = scanWindowsEventLog("System");
    result.totalEntries += systemResult.totalEntries;
    result.recentErrors = systemResult.recentErrors;
    result.errorCount += systemResult.errorCount;

    // 扫描应用程序日志
    emit progressUpdated(80, "正在扫描应用程序日志...");
    LogScanResult appResult = scanWindowsEventLog("Application");
    result.totalEntries += appResult.totalEntries;

    result.endTime = QDateTime::currentDateTime();

    emit progressUpdated(100, QString("日志扫描完成，共发现 %1 条记录").arg(result.totalEntries));
    emit scanCompleted(result);

    return result;
}

LogScanResult LogAnalyzer::scanWindowsEventLog(const QString& channel) {
    LogScanResult result;
    result.scanSource = channel;
    result.startTime = QDateTime::currentDateTime();

    QList<WindowsEventLog> events = getWindowsEvents(channel, 5000);

    for (const WindowsEventLog& event : events) {
        LogEntry entry;
        entry.type = "Windows";
        entry.source = channel;
        entry.timestamp = event.timeCreated;
        entry.eventId = event.eventId;
        entry.level = event.level;
        entry.message = event.description;

        // 统计
        result.totalEntries++;
        if (event.level == "Error") result.errorCount++;
        else if (event.level == "Warning") result.warningCount++;
        else result.infoCount++;

        // 检测异常
        if (isWindowsEventSuspicious(event)) {
            result.anomalyCount++;
            result.anomalies.append(entry);
            emit anomalyDetected(entry);
        }

        // 保存最近的错误
        if (event.level == "Error" && result.recentErrors.size() < 100) {
            result.recentErrors.append(entry);
        }

        emit logEntryFound(entry);
    }

    result.endTime = QDateTime::currentDateTime();
    return result;
}

LogScanResult LogAnalyzer::scanWebLog(const QString& logPath) {
    LogScanResult result;
    result.scanSource = logPath;
    result.startTime = QDateTime::currentDateTime();

    QFile file(logPath);
    if (!file.open(QIODevice::ReadOnly)) {
        emit errorOccurred(QString("无法打开日志文件: %1").arg(logPath));
        return result;
    }

    QTextStream in(&file);
    int lineCount = 0;
    int totalLines = 0;

    // 计算总行数
    while (!in.atEnd()) {
        in.readLine();
        totalLines++;
    }
    in.seek(0);

    int progress = 0;
    while (!in.atEnd()) {
        QString line = in.readLine().trimmed();
        if (line.isEmpty() || line.startsWith("#")) continue;

        WebLogEntry webEntry;
        QString format = "common";

        // 检测日志格式
        if (line.contains("Mozilla/")) {
            format = "combined";
        } else if (line.contains("\"GET") || line.contains("\"POST")) {
            format = "common";
        }

        if (format == "combined") {
            webEntry = parseCombinedLogFormat(line);
        } else {
            webEntry = parseCommonLogFormat(line);
        }

        if (isWebLogSuspicious(webEntry)) {
            result.anomalyCount++;
            LogEntry entry;
            entry.type = "Web";
            entry.timestamp = webEntry.timestamp;
            entry.ipAddress = webEntry.clientIp;
            entry.message = webEntry.url;
            entry.isAnomaly = true;
            entry.anomalyReason = webEntry.suspiciousReason;
            result.anomalies.append(entry);
            emit anomalyDetected(entry);
        }

        result.totalEntries++;
        emit logEntryFound(entry);

        lineCount++;
        int newProgress = (lineCount * 100 / totalLines);
        if (newProgress != progress) {
            emit progressUpdated(newProgress, QString("已扫描 %1 行").arg(lineCount));
            progress = newProgress;
        }
    }

    file.close();
    result.endTime = QDateTime::currentDateTime();

    emit progressUpdated(100, QString("Web日志扫描完成，共发现 %1 条记录").arg(result.totalEntries));
    emit scanCompleted(result);

    return result;
}

LogScanResult LogAnalyzer::scanCustomLog(const QString& logPath, const QString& format) {
    Q_UNUSED(logPath)
    Q_UNUSED(format)
    LogScanResult result;
    return result;
}

// ========== Windows事件日志 ==========

QList<WindowsEventLog> LogAnalyzer::getWindowsEvents(const QString& channel, int maxEvents) {
    QList<WindowsEventLog> events;

    QString query = QString("*[System[Channel(\"%1\")] and EventID]");
    QList<WindowsEventLog> result = queryWindowsEventLog(channel, query, maxEvents);

    return result;
}

QList<WindowsEventLog> LogAnalyzer::getSecurityEvents(const QString& eventId, int hours) {
    QList<WindowsEventLog> events;
    Q_UNUSED(hours)

    QString query = "*[System[Channel(\"Security\")]";
    if (!eventId.isEmpty()) {
        query = QString("*[System[Channel(\"Security\") and EventID(%1)]]").arg(eventId);
    }

    events = queryWindowsEventLog("Security", query, 1000);

    return events;
}

QList<WindowsEventLog> LogAnalyzer::getSystemErrors(int hours) {
    Q_UNUSED(hours)
    QList<WindowsEventLog> events;

    QString query = "*[System[Channel(\"System\") and Level=2]]"; // Level 2 = Error
    events = queryWindowsEventLog("System", query, 500);

    return events;
}

QList<WindowsEventLog> LogAnalyzer::getApplicationErrors(int hours) {
    Q_UNUSED(hours)
    QList<WindowsEventLog> events;

    QString query = "*[System[Channel(\"Application\") and Level=2]]"; // Level 2 = Error
    events = queryWindowsEventLog("Application", query, 500);

    return events;
}

// ========== Web日志解析 ==========

QList<WebLogEntry> LogAnalyzer::parseIisLog(const QString& logPath) {
    QList<WebLogEntry> entries;

    QFile file(logPath);
    if (!file.open(QIODevice::ReadOnly)) {
        return entries;
    }

    QTextStream in(&file);
    while (!in.atEnd()) {
        QString line = in.readLine().trimmed();
        if (line.isEmpty() || line.startsWith("#")) continue;

        entries.append(parseIisLogFormat(line));
    }

    file.close();
    return entries;
}

QList<WebLogEntry> LogAnalyzer::parseApacheLog(const QString& logPath) {
    QList<WebLogEntry> entries;

    QFile file(logPath);
    if (!file.open(QIODevice::ReadOnly)) {
        return entries;
    }

    QTextStream in(&file);
    while (!in.atEnd()) {
        QString line = in.readLine().trimmed();
        if (line.isEmpty() || line.startsWith("#")) continue;

        entries.append(parseCombinedLogFormat(line));
    }

    file.close();
    return entries;
}

QList<WebLogEntry> LogAnalyzer::parseNginxLog(const QString& logPath) {
    QList<WebLogEntry> entries;

    QFile file(logPath);
    if (!file.open(QIODevice::ReadOnly)) {
        return entries;
    }

    QTextStream in(&file);
    while (!in.atEnd()) {
        QString line = in.readLine().trimmed();
        if (line.isEmpty() || line.startsWith("#")) continue;

        entries.append(parseNginxLogFormat(line));
    }

    file.close();
    return entries;
}

// ========== 异常检测 ==========

bool LogAnalyzer::isEntrySuspicious(const LogEntry& entry) {
    // 检查是否为关键安全事件
    if (CRITICAL_EVENT_IDS.contains(entry.eventId)) {
        // 检查是否异常频繁
        return checkBruteForceAttack(entry) ||
               checkPrivilegeEscalation(entry) ||
               checkUnauthorizedAccess(entry);
    }
    return false;
}

bool LogAnalyzer::isWindowsEventSuspicious(const WindowsEventLog& event) {
    // 检查是否关键事件
    if (CRITICAL_EVENT_IDS.contains(event.eventId)) {
        // 检查特权分配
        if (event.eventId == 4672) {
            return true; // 特权分配通常是可疑的
        }

        // 检查进程创建
        if (event.eventId == 4688) {
            return true; // 新进程可能需要审查
        }
    }

    // 检查事件级别
    if (event.level == "Error") {
        return true; // 错误可能表示问题
    }

    return false;
}

bool LogAnalyzer::isWebLogSuspicious(const WebLogEntry& entry) {
    return checkSqlInjection(entry) ||
           checkXssAttack(entry) ||
           checkDirectoryTraversal(entry);
}

// ========== 关键字搜索 ==========

QList<LogEntry> LogAnalyzer::searchByKeyword(const QString& keyword) {
    QList<LogEntry> results;

    // 搜索Windows安全日志
    QList<WindowsEventLog> events = getWindowsEvents("Security", 5000);
    for (const WindowsEventLog& event : events) {
        if (event.description.contains(keyword, Qt::CaseInsensitive)) {
            LogEntry entry;
            entry.type = "Windows";
            entry.source = "Security";
            entry.eventId = event.eventId;
            entry.message = event.description;
            entry.timestamp = event.timeCreated;
            results.append(entry);
        }
    }

    return results;
}

QList<LogEntry> LogAnalyzer::searchByTimeRange(const QDateTime& start, const QDateTime& end) {
    QList<LogEntry> results;

    // 搜索所有日志通道
    QStringList channels = {"Security", "System", "Application"};
    for (const QString& channel : channels) {
        QList<WindowsEventLog> events = getWindowsEvents(channel, 5000);
        for (const WindowsEventLog& event : events) {
            if (event.timeCreated >= start && event.timeCreated <= end) {
                LogEntry entry;
                entry.type = "Windows";
                entry.source = channel;
                entry.timestamp = event.timeCreated;
                entry.message = event.description;
                results.append(entry);
            }
        }
    }

    return results;
}

QList<LogEntry> LogAnalyzer::searchByEventId(const QString& eventId) {
    QList<LogEntry> results;

    bool ok;
    int id = eventId.toInt(&ok);
    if (!ok) return results;

    QList<WindowsEventLog> events = getSecurityEvents(eventId, 24);
    for (const WindowsEventLog& event : events) {
        LogEntry entry;
        entry.type = "Windows";
        entry.source = "Security";
        entry.eventId = event.eventId;
        entry.message = event.description;
        entry.timestamp = event.timeCreated;
        results.append(entry);
    }

    return results;
}

QList<LogEntry> LogAnalyzer::searchByIp(const QString& ipAddress) {
    QList<LogEntry> results;
    Q_UNUSED(ipAddress)
    // 需要实现IP关联分析
    return results;
}

// ========== 日志分析统计 ==========

int LogAnalyzer::countEventsByType(const QString& channel, const QString& level) {
    QList<WindowsEventLog> events = getWindowsEvents(channel, 5000);
    int count = 0;

    for (const WindowsEventLog& event : events) {
        if (event.level == level) {
            count++;
        }
    }

    return count;
}

QList<QString> LogAnalyzer::getTopEventSources(const QString& channel, int topN) {
    QList<QString> sources;
    Q_UNUSED(channel)
    Q_UNUSED(topN)
    return sources;
}

QList<QString> LogAnalyzer::getTopIpAddresses(const QString& channel, int topN) {
    QList<QString> ips;
    Q_UNUSED(channel)
    Q_UNUSED(topN)
    return ips;
}

// ========== 辅助方法 ==========

QList<WindowsEventLog> LogAnalyzer::queryWindowsEventLog(const QString& channel, const QString& query, int maxEvents) {
    QList<WindowsEventLog> events;

    EVT_HANDLE hResults = NULL;
    EVT_HANDLE hChannel = NULL;

    // 打开日志通道
    hChannel = EvtOpenChannelEnum(NULL, NULL);
    if (hChannel == NULL) {
        // 尝试直接打开
        hChannel = EvtOpenChannel(NULL, NULL, (LPCWSTR)channel.utf16());
    }

    if (hChannel == NULL) {
        // 使用备用方法：通过wevtutil查询
        QProcess process;
        QString cmd = QString("wevtutil qe \"%1\" /q:\"%2\" /c:%3 /rd:true /f:text")
                          .arg(channel)
                          .arg(query)
                          .arg(maxEvents);
        process.start("cmd", QStringList() << "/c" << cmd);
        process.waitForFinished();

        QString output = process.readAllStandardOutput();
        // 解析输出...
        return events;
    }

    EvtClose(hChannel);
    return events;
}

QString LogAnalyzer::getWindowsEventLevel(DWORD level) {
    switch (level) {
    case 1: return "Critical";
    case 2: return "Error";
    case 3: return "Warning";
    case 4: return "Info";
    case 5: return "Verbose";
    default: return "Unknown";
    }
}

// ========== Web日志解析辅助方法 ==========

WebLogEntry LogAnalyzer::parseCommonLogFormat(const QString& line) {
    WebLogEntry entry;

    // 格式: IP - User [Date] "Method URL Protocol" Status Bytes
    QRegularExpression re(R"((?:\d{1,3}\.){3}\d{1,3}\s+\S+\s+\S+\s+\[(.+?)\]\s+"(\w+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+))");
    QRegularExpressionMatch match = re.match(line);

    if (match.hasMatch()) {
        entry.timestamp = QDateTime::fromString(match.captured(1), "dd/MMM/yyyy:HH:mm:ss Z");
        entry.clientIp = match.captured(0).section(" ", 0, 0);
        entry.method = match.captured(2);
        entry.url = match.captured(3);
        entry.protocol = match.captured(4);
        entry.statusCode = match.captured(5).toInt();
        entry.bytesSent = match.captured(6).toLongLong();
    }

    return entry;
}

WebLogEntry LogAnalyzer::parseCombinedLogFormat(const QString& line) {
    WebLogEntry entry = parseCommonLogFormat(line);

    // 提取额外信息
    QRegularExpression re(R"("([^"]+)"\s+"([^"]+)"\s+(\d+))");
    QRegularExpressionMatch match = re.match(line);

    if (match.hasMatch()) {
        entry.userAgent = match.captured(1);
        entry.referer = match.captured(2);
    }

    return entry;
}

WebLogEntry LogAnalyzer::parseIisLogFormat(const QString& line) {
    WebLogEntry entry;

    // IIS日志字段
    QStringList fields = line.split(" ");
    if (fields.size() >= 10) {
        entry.timestamp = QDateTime::fromString(fields[0] + " " + fields[1], "yyyy-MM-dd HH:mm:ss");
        entry.clientIp = fields[2];
        entry.method = fields[3];
        entry.url = fields[4];
        entry.protocol = fields[5];
        entry.statusCode = fields[6].toInt();
    }

    return entry;
}

WebLogEntry LogAnalyzer::parseNginxLogFormat(const QString& line) {
    return parseCombinedLogFormat(line);
}

// ========== 异常检测规则 ==========

bool LogAnalyzer::checkBruteForceAttack(const LogEntry& entry) {
    Q_UNUSED(entry)
    // 需要实现基于频率的检测
    return false;
}

bool LogAnalyzer::checkPrivilegeEscalation(const LogEntry& entry) {
    return entry.eventId == 4672 || entry.eventId == 4673 || entry.eventId == 4674;
}

bool LogAnalyzer::checkSuspiciousProcess(const LogEntry& entry) {
    Q_UNUSED(entry)
    return false;
}

bool LogAnalyzer::checkUnauthorizedAccess(const LogEntry& entry) {
    return entry.eventId == 4625 || entry.eventId == 4767;
}

bool LogAnalyzer::checkSqlInjection(const WebLogEntry& entry) {
    QString urlLower = entry.url.toLower();

    for (const QRegularExpression& pattern : DANGEROUS_URL_PATTERNS) {
        if (pattern.match(urlLower).hasMatch()) {
            entry.suspiciousReason = QString("检测到SQL注入尝试: %1").arg(pattern.pattern());
            return true;
        }
    }

    return false;
}

bool LogAnalyzer::checkXssAttack(const WebLogEntry& entry) {
    QString urlLower = entry.url.toLower();

    if (urlLower.contains("<script") || urlLower.contains("javascript:")) {
        entry.suspiciousReason = "检测到XSS攻击尝试";
        return true;
    }

    return false;
}

bool LogAnalyzer::checkDirectoryTraversal(const WebLogEntry& entry) {
    QString urlLower = entry.url.toLower();

    if (urlLower.contains("../") || urlLower.contains("..\\")) {
        entry.suspiciousReason = "检测到目录遍历尝试";
        return true;
    }

    return false;
}

bool LogAnalyzer::checkPortScan(const LogEntry& entry) {
    Q_UNUSED(entry)
    return false;
}
