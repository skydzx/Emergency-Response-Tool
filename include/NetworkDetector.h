#ifndef NETWORKDETECTOR_H
#define NETWORKDETECTOR_H

#include <QObject>
#include <QString>
#include <QList>
#include <QMap>
#include <QVector>
#include <QDateTime>
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <tcpmib.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

struct NetworkConnection {
    int localPort;
    QString localAddress;
    int remotePort;
    QString remoteAddress;
    QString protocol;
    QString state;
    int processId;
    QString processName;
    QString owner;
    QDateTime connectionTime;
    bool isListening;
    bool isEstablished;
    bool isOutgoing;
    bool isIncoming;
    bool isSuspicious;
    QString suspiciousReason;
    int64_t bytesSent;
    int64_t bytesReceived;
};

struct PortInfo {
    int port;
    QString protocol;
    QString service;
    QString description;
    bool isCommonPort;
    QString riskLevel;
    QString recommendations;
};

class NetworkDetector : public QObject {
    Q_OBJECT

public:
    explicit NetworkDetector(QObject *parent = nullptr);
    ~NetworkDetector();

    // 网络连接检测
    QList<NetworkConnection> collectAllConnections();
    QList<NetworkConnection> collectTcpConnections();
    QList<NetworkConnection> collectUdpConnections();
    QList<NetworkConnection> collectListeningPorts();

    // 端口分析
    QList<PortInfo> analyzePorts(const QList<NetworkConnection>& connections);
    QString getServiceName(int port, const QString& protocol);
    bool isCommonPort(int port);

    // 可疑连接检测
    bool isConnectionSuspicious(const NetworkConnection& connection);
    QList<NetworkConnection> findSuspiciousConnections();

    // 外连分析
    QList<NetworkConnection> findOutgoingConnections();
    QList<NetworkConnection> findConnectionsToCountry(const QString& countryCode);
    QList<NetworkConnection> findConnectionsToKnownBadIPs();

    // 端口扫描检测
    bool detectPortScanning();
    int countConnectionsFromSingleSource();

    // DNS查询分析
    QList<QString> getRecentDnsQueries();

signals:
    void progressUpdated(int percentage, const QString& status);
    void connectionFound(const NetworkConnection& connection);
    void suspiciousConnectionFound(const NetworkConnection& connection);
    void portScanDetected(const QString& sourceIp, int portCount);
    void errorOccurred(const QString& error);

private:
    bool getTcpTable(PMIB_TCPTABLE& table, DWORD& size);
    bool getUdpTable(PMIB_UDPTABLE& table, DWORD& size);
    bool getExtendedTcpTable(PMIB_TCPEXTROW*& table, DWORD& size);

    NetworkConnection parseTcpConnection(const MIB_TCPROW& row);
    NetworkConnection parseTcpConnectionEx(const MIB_TCPEXTROW& row);
    NetworkConnection parseUdpConnection(const MIB_UDPROW& row);

    bool getProcessNameById(int pid, QString& processName);
    bool getProcessOwnerById(int pid, QString& owner);

    // 可疑特征检测
    bool checkSuspiciousPort(int port);
    bool checkSuspiciousAddress(const QString& address);
    bool checkSuspiciousState(const QString& state);
    bool checkSuspiciousProcess(const QString& processName);

    // 危险端口列表
    static const QMap<int, PortInfo> COMMON_PORTS;
    static const QMap<int, QString> SUSPICIOUS_PORTS;
    static const QStringList KNOWN_BAD_DOMAINS;
};

#endif // NETWORKDETECTOR_H
