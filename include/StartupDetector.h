#ifndef STARTUPDETECTOR_H
#define STARTUPDETECTOR_H

#include <QObject>
#include <QString>
#include <QList>
#include <QMap>
#include <QVector>
#include <QDateTime>
#include <windows.h>

struct StartupItem {
    QString name;
    QString type;           // "Registry", "Service", "ScheduledTask", "StartupFolder", "WMI"
    QString path;
    QString command;
    QString location;
    QString publisher;
    QString description;
    QString trigger;         // 触发条件
    QString user;
    bool isEnabled;
    bool isSuspicious;
    QString suspiciousReason;
    QStringList tags;
    QDateTime lastModified;
    int riskLevel;          // 0=安全, 1=低, 2=中, 3=高
};

struct ScheduledTask {
    QString name;
    QString path;
    QString status;
    QString nextRunTime;
    QString lastRunTime;
    QString lastRunResult;
    QString author;
    QString description;
    QString taskType;
    QString action;
    QString trigger;
    bool isEnabled;
    bool isHidden;
    bool isSuspicious;
    QString suspiciousReason;
    QVector<QString> actions;
    QVector<QString> triggers;
    QDateTime createdDate;
};

class StartupDetector : public QObject {
    Q_OBJECT

public:
    explicit StartupDetector(QObject *parent = nullptr);
    ~StartupDetector();

    // 启动项检测
    QList<StartupItem> collectAllStartupItems();
    QList<StartupItem> collectRegistryStartup();
    QList<StartupItem> collectServiceStartup();
    QList<StartupItem> collectFolderStartup();
    QList<StartupItem> collectWmiStartup();

    // 计划任务检测
    QList<ScheduledTask> collectScheduledTasks();
    QList<ScheduledTask> collectScheduledTasksSchtasks();
    QList<ScheduledTask> collectScheduledTasksPowerShell();

    // 可疑项检测
    bool isStartupItemSuspicious(const StartupItem& item);
    bool isScheduledTaskSuspicious(const ScheduledTask& task);
    QList<StartupItem> findSuspiciousStartupItems();
    QList<ScheduledTask> findSuspiciousScheduledTasks();

    // 启动项管理
    bool disableStartupItem(const StartupItem& item);
    bool enableStartupItem(const StartupItem& item);
    bool deleteStartupItem(const StartupItem& item);
    bool deleteScheduledTask(const ScheduledTask& task);

signals:
    void progressUpdated(int percentage, const QString& status);
    void startupItemFound(const StartupItem& item);
    void scheduledTaskFound(const ScheduledTask& task);
    void suspiciousItemFound(const StartupItem& item);
    void suspiciousTaskFound(const ScheduledTask& task);
    void errorOccurred(const QString& error);

private:
    // 注册表启动项路径
    static const QStringList REG_RUN_PATHS;
    static const QStringList REG_RUN_ONCE_PATHS;
    static const QStringList REG_USER_RUN_PATHS;
    static const QStringList REG_POLICIES_PATHS;

    // 启动文件夹路径
    static const QStringList STARTUP_FOLDER_PATHS;

    // 可疑关键词
    static const QStringList SUSPICIOUS_KEYWORDS;
    static const QStringList SUSPICIOUS_PATHS;
    static const QStringList KNOWN_GOOD_PUBLISHERS;

    // 注册表检测
    QList<StartupItem> queryRegistryKey(const QString& keyPath, const QString& location);

    // 文件夹检测
    QList<StartupItem> queryStartupFolder(const QString& folderPath);

    // 服务检测
    QList<StartupItem> queryServices();

    // WMI检测
    QList<StartupItem> queryWmiStartup();

    // 辅助函数
    bool readRegistryValue(HKEY hKey, const QString& valueName, QString& valueData);
    bool getFilePublisher(const QString& path, QString& publisher);
    bool getFileDescription(const QString& path, QString& description);
    bool getFileVersion(const QString& path, QString& version);

    // 可疑性分析
    int analyzeRiskLevel(const StartupItem& item);
    int analyzeTaskRiskLevel(const ScheduledTask& task);

    // 执行命令
    bool executeCommand(const QString& command, QString& output);
};

#endif // STARTUPDETECTOR_H
