#ifndef SYSTEMINFOCOLLECTOR_H
#define SYSTEMINFOCOLLECTOR_H

#include <QObject>
#include <QString>
#include <QList>
#include <QMap>
#include <QDateTime>

struct SystemInfo {
    QString osVersion;
    QString osBuild;
    QString architecture;
    QString computerName;
    QString userName;
    QString systemRoot;
    int processorCount;
    QString memoryInfo;
    QString diskInfo;
    QDateTime systemTime;
};

struct ProcessInfo {
    int pid;
    QString name;
    QString path;
    QString commandLine;
    QString user;
    QString sessionId;
    int memoryUsage;
    int cpuUsage;
    QDateTime startTime;
    bool isSuspended;
    QString parentPid;
    QString description;
    QString company;
    QString fileHash;
    bool isSigned;
    bool isVerified;
    bool isSuspicious;
    QString suspiciousReason;
};

struct ServiceInfo {
    QString name;
    QString displayName;
    QString path;
    QString startType;
    QString status;
    QString description;
    QString user;
    QString dependencies;
    QString triggeredBy;
    bool isSuspicious;
    QString suspiciousReason;
};

struct UserInfo {
    QString name;
    QString fullName;
    QString sid;
    QString domain;
    QString userType;
    bool isDisabled;
    bool isLocked;
    bool isPasswordExpired;
    QDateTime lastLogin;
    int logonCount;
    QStringList groups;
    QString profilePath;
    QString homeDirectory;
    QString comment;
    QString description;
};

struct StartupInfo {
    QString name;
    QString type;
    QString path;
    QString command;
    QString location;
    QString publisher;
    bool isEnabled;
    bool isSuspicious;
    QString suspiciousReason;
};

class SystemInfoCollector : public QObject {
    Q_OBJECT

public:
    explicit SystemInfoCollector(QObject *parent = nullptr);

    // 系统信息收集
    SystemInfo collectSystemInfo();
    QString collectOSVersion();
    QString collectComputerName();
    QString collectUserName();
    int collectProcessorCount();
    QString collectMemoryInfo();
    QString collectDiskInfo();

    // 进程信息
    QList<ProcessInfo> collectProcesses();
    ProcessInfo parseProcessInfo(const QString& line);
    bool isProcessSuspicious(const ProcessInfo& process);

    // 服务信息
    QList<ServiceInfo> collectServices();
    bool isServiceSuspicious(const ServiceInfo& service);

    // 用户信息
    QList<UserInfo> collectUsers();
    bool isUserSuspicious(const UserInfo& user);

    // 启动项信息
    QList<StartupInfo> collectStartupItems();
    bool isStartupItemSuspicious(const StartupInfo& item);

    // 计划任务
    QList<QMap<QString, QVariant>> collectScheduledTasks();

    // 网络连接
    QList<QMap<QString, QVariant>> collectNetworkConnections();

signals:
    void progressUpdated(int percentage, const QString& status);
    void infoCollected(const QString& infoType, const QVariant& data);
    void errorOccurred(const QString& error);

private:
    bool executeCommand(const QString& command, QString& output);
    QStringList splitLines(const QString& output);
    QString extractValue(const QString& line, const QString& key);
};

#endif // SYSTEMINFOCOLLECTOR_H
