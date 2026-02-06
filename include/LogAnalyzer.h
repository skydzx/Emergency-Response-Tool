#ifndef LOGANALYZER_H
#define LOGANALYZER_H

#include <QObject>
#include <QString>
#include <QList>
#include <QMap>
#include <QVector>
#include <QDateTime>
#include <QFile>
#include <QRegularExpression>
#include <windows.h>
#include <winevt.h>

#pragma comment(lib, "wevtapi.lib")

struct LogEntry {
    int id;
    QString type;           // "Windows", "Web", "Firewall", "Custom"
    QString source;
    QDateTime timestamp;
    int eventId;
    QString level;          // "Error", "Warning", "Info", "SuccessAudit", "FailureAudit"
    QString message;
    QString computer;
    QString user;
    QString process;
    QString ipAddress;
    bool isAnomaly;
    QString anomalyReason;
    QMap<QString, QString> rawData;
    QString rawText;
};

struct LogScanResult {
    int totalEntries;
    int errorCount;
    int warningCount;
    int infoCount;
    int anomalyCount;
    QList<LogEntry> anomalies;
    QList<LogEntry> recentErrors;
    QList<LogEntry> securityEvents;
    QDateTime startTime;
    QDateTime endTime;
    QString scanSource;
};

struct WindowsEventLog {
    QString channel;         // "Application", "System", "Security"
    int eventId;
    QString level;
    QString provider;
    QDateTime timeCreated;
    QString description;
    QMap<QString, QString> eventData;
};

struct WebLogEntry {
    QDateTime timestamp;
    QString method;         // GET, POST, etc.
    QString url;
    QString protocol;
    int statusCode;
    int responseTime;
    QString clientIp;
    QString userAgent;
    QString referer;
    qint64 bytesSent;
    qint64 bytesReceived;
    bool isSuspicious;
    QString suspiciousReason;
};

class LogAnalyzer : public QObject {
    Q_OBJECT

public:
    explicit LogAnalyzer(QObject *parent = nullptr);
    ~LogAnalyzer();

    // 日志扫描
    LogScanResult scanAllLogs();
    LogScanResult scanWindowsEventLog(const QString& channel = "Security");
    LogScanResult scanWebLog(const QString& logPath);
    LogScanResult scanCustomLog(const QString& logPath, const QString& format);

    // Windows事件日志
    QList<WindowsEventLog> getWindowsEvents(const QString& channel, int maxEvents = 1000);
    QList<WindowsEventLog> getSecurityEvents(const QString& eventId = "", int hours = 24);
    QList<WindowsEventLog> getSystemErrors(int hours = 24);
    QList<WindowsEventLog> getApplicationErrors(int hours = 24);

    // Web日志解析
    QList<WebLogEntry> parseIisLog(const QString& logPath);
    QList<WebLogEntry> parseApacheLog(const QString& logPath);
    QList<WebLogEntry> parseNginxLog(const QString& logPath);

    // 异常检测
    bool isEntrySuspicious(const LogEntry& entry);
    bool isWindowsEventSuspicious(const WindowsEventLog& event);
    bool isWebLogSuspicious(const WebLogEntry& entry);

    // 关键字搜索
    QList<LogEntry> searchByKeyword(const QString& keyword);
    QList<LogEntry> searchByTimeRange(const QDateTime& start, const QDateTime& end);
    QList<LogEntry> searchByEventId(const QString& eventId);
    QList<LogEntry> searchByIp(const QString& ipAddress);

    // 日志分析
    int countEventsByType(const QString& channel, const QString& level);
    QList<QString> getTopEventSources(const QString& channel, int topN = 10);
    QList<QString> getTopIpAddresses(const QString& channel, int topN = 10);

signals:
    void progressUpdated(int percentage, const QString& status);
    void logEntryFound(const LogEntry& entry);
    void anomalyDetected(const LogEntry& entry);
    void scanCompleted(const LogScanResult& result);
    void errorOccurred(const QString& error);

private:
    // Windows事件日志
    QList<WindowsEventLog> queryWindowsEventLog(const QString& channel, const QString& query,
                                                int maxEvents);
    QString getWindowsEventLevel(DWORD level);

    // Web日志解析辅助方法
    WebLogEntry parseCommonLogFormat(const QString& line);
    WebLogEntry parseCombinedLogFormat(const QString& line);
    WebLogEntry parseIisLogFormat(const QString& line);
    WebLogEntry parseNginxLogFormat(const QString& line);

    // 异常检测规则
    bool checkBruteForceAttack(const LogEntry& entry);
    bool checkPrivilegeEscalation(const LogEntry& entry);
    bool checkSuspiciousProcess(const LogEntry& entry);
    bool checkUnauthorizedAccess(const LogEntry& entry);
    bool checkSqlInjection(const WebLogEntry& entry);
    bool checkXssAttack(const WebLogEntry& entry);
    bool checkDirectoryTraversal(const WebLogEntry& entry);
    bool checkPortScan(const LogEntry& entry);

    // 危险事件ID列表
    static const QMap<int, QString> CRITICAL_EVENT_IDS;
    static const QMap<int, QString> SECURITY_EVENT_IDS;
    static const QVector<int> BRUTE_FORCE_EVENT_IDS;

    // 可疑IP模式
    static const QRegularExpression SUSPICIOUS_IP_PATTERN;

    // 危险URL模式
    static const QVector<QRegularExpression> DANGEROUS_URL_PATTERNS;
};

#endif // LOGANALYZER_H
