#ifndef PROCESSDETECTOR_H
#define PROCESSDETECTOR_H

#include <QObject>
#include <QString>
#include <QList>
#include <QMap>
#include <QVector>
#include <QDateTime>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winsock2.h>
#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")

struct ProcessDetail {
    int pid;
    QString name;
    QString path;
    QString commandLine;
    QString user;
    QString sessionId;
    qint64 memoryUsage;
    double cpuUsage;
    QDateTime startTime;
    bool isSuspended;
    int parentPid;
    QString description;
    QString company;
    QString fileHash;
    bool isSigned;
    bool isVerified;
    bool isSuspicious;
    QString suspiciousReason;
    QVector<int> childPids;
};

struct PortInfo {
    int localPort;
    QString localAddress;
    int remotePort;
    QString remoteAddress;
    QString protocol;
    QString state;
    int processId;
    QString processName;
    QString owner;
    bool isListening;
    bool isEstablished;
    bool isSuspicious;
    QString suspiciousReason;
};

struct PortMapping {
    int localPort;
    QString localAddress;
    QString processName;
    int processId;
    QString protocol;
};

class ProcessDetector : public QObject {
    Q_OBJECT

public:
    explicit ProcessDetector(QObject *parent = nullptr);
    ~ProcessDetector();

    // 进程检测
    QList<ProcessDetail> collectAllProcesses();
    ProcessDetail getProcessDetail(int pid);
    bool isProcessRunning(int pid);
    QString getProcessPath(int pid);
    qint64 getProcessMemory(int pid);
    double getProcessCpu(int pid);
    QVector<int> getChildProcesses(int pid);

    // 可疑进程检测
    bool isProcessSuspicious(const ProcessDetail& process);
    QList<ProcessDetail> findSuspiciousProcesses();

    // 进程签名验证
    bool verifyProcessSignature(int pid);
    bool checkProcessTrust(const ProcessDetail& process);

    // 隐藏进程检测
    bool detectHiddenProcesses();
    bool detectHooks();

signals:
    void progressUpdated(int percentage, const QString& status);
    void processFound(const ProcessDetail& process);
    void suspiciousProcessFound(const ProcessDetail& process);
    void errorOccurred(const QString& error);

private:
    bool updateProcessList();
    void parseProcessEntry(const PROCESSENTRY32& entry, ProcessDetail& detail);
    bool getProcessOwner(int pid, QString& owner);
    bool getProcessCommandLine(int pid, QString& commandLine);
    bool getProcessFileInfo(const QString& path, QString& company, QString& description);

    // 可疑特征检测
    bool checkSuspiciousName(const QString& name);
    bool checkSuspiciousPath(const QString& path);
    bool checkSuspiciousParent(int pid);
    bool checkSuspiciousMemory(qint64 memory);
    bool checkSuspiciousCpu(double cpu);
    bool checkSuspiciousSignature(bool isSigned, bool isVerified);
    bool checkSuspiciousBehavior(const ProcessDetail& process);

    // 进程白名单
    bool isInWhitelist(const QString& path);

    // 系统关键进程（不应该终止）
    bool isSystemCritical(int pid);
};

#endif // PROCESSDETECTOR_H
