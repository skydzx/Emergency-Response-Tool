/**
 * @file NetworkDetector.cpp
 * @brief Network Detection Implementation
 * @version 1.0.0
 */

#include "NetworkDetector.h"
#include <QProcess>
#include <QDebug>
#include <QRegExp>
#include <QFile>
#include <QTextStream>

// 常见端口定义
const QMap<int, PortInfo> NetworkDetector::COMMON_PORTS = {
    {20, {20, "FTP-DATA", "FTP Data Transfer", true, "低", "仅用于数据传输"}},
    {21, {21, "FTP", "File Transfer Protocol", true, "中", "建议使用SFTP替代"}},
    {22, {22, "SSH", "Secure Shell", true, "低", "安全的远程管理"}},
    {23, {23, "TELNET", "Telnet", true, "高", "明文传输，建议禁用"}},
    {25, {25, "SMTP", "Simple Mail Transfer", true, "中", "邮件发送端口"}},
    {53, {53, "DNS", "Domain Name System", true, "低", "域名解析服务"}},
    {80, {80, "HTTP", "Web Server", true, "中", "建议使用HTTPS"}},
    {110, {110, "POP3", "Post Office Protocol", true, "中", "建议使用POP3S"}},
    {119, {119, "NNTP", "Network News Transfer", true, "低", "新闻组协议"}},
    {123, {123, "NTP", "Network Time Protocol", true, "低", "时间同步服务"}},
    {135, {135, "MSRPC", "Microsoft RPC", true, "高", "远程过程调用"}},
    {137, {137, "NetBIOS-NS", "NetBIOS Name Service", true, "高", "建议禁用"}},
    {138, {138, "NetBIOS-DGM", "NetBIOS Datagram", true, "高", "建议禁用"}},
    {139, {139, "NetBIOS-SSN", "NetBIOS Session", true, "高", "建议禁用"}},
    {143, {143, "IMAP", "Internet Message Access", true, "中", "建议使用IMAPS"}},
    {161, {161, "SNMP", "Simple Network Management", true, "高", "社区字符串可能泄露信息"}},
    {194, {194, "IRC", "Internet Relay Chat", true, "中", "聊天协议"}},
    {389, {389, "LDAP", "Lightweight Directory", true, "高", "目录服务"}},
    {443, {443, "HTTPS", "Secure Web Server", true, "低", "加密Web服务"}},
    {445, {445, "SMB", "Server Message Block", true, "高", "永恒之蓝漏洞相关"}},
    {465, {465, "SMTPS", "Secure SMTP", true, "低", "加密邮件发送"}},
    {514, {514, "SYSLOG", "System Log", true, "中", "日志服务"}},
    {515, {515, "LPD", "Line Printer Daemon", true, "高", "打印服务"}},
    {587, {587, "Submission", "Mail Submission", true, "低", "邮件提交"}},
    {636, {636, "LDAPS", "Secure LDAP", true, "低", "加密目录服务"}},
    {993, {993, "IMAPS", "Secure IMAP", true, "低", "加密邮件访问"}},
    {995, {995, "POP3S", "Secure POP3", true, "低", "加密邮件接收"}},
    {1080, {1080, "SOCKS", "SOCKS Proxy", true, "高", "代理服务"}},
    {1433, {1433, "MSSQL", "MS SQL Server", true, "高", "数据库服务"}},
    {1434, {1434, "MSSQL-NS", "MS SQL Browser", true, "高", "数据库浏览"}},
    {1521, {1521, "Oracle", "Oracle Database", true, "高", "数据库服务"}},
    {1723, {1723, "PPTP", "VPN Tunnel", true, "高", "VPN协议"}},
    {2049, {2049, "NFS", "Network File System", true, "高", "文件共享"}},
    {3306, {3306, "MySQL", "MySQL Database", true, "高", "数据库服务"}},
    {3389, {3389, "RDP", "Remote Desktop", true, "高", "远程桌面"}},
    {5432, {5432, "PostgreSQL", "PostgreSQL Database", true, "高", "数据库服务"}},
    {5900, {5900, "VNC", "Virtual Network Computing", true, "高", "远程控制"}},
    {6379, {6379, "Redis", "Redis Database", true, "高", "缓存服务"}},
    {8080, {8080, "HTTP-Proxy", "Web Proxy", true, "中", "HTTP代理"}},
    {8443, {8443, "HTTPS-Alt", "Alternate HTTPS", true, "中", "备用HTTPS"}},
    {27017, {27017, "MongoDB", "MongoDB Database", true, "高", "数据库服务"}}
};

// 可疑端口
const QMap<int, QString> NetworkDetector::SUSPICIOUS_PORTS = {
    {4444, "Metasploit默认端口"},
    {5555, "恶意软件常用端口"},
    {6666, "恶意软件常用端口"},
    {6667, "IRC僵尸网络"},
    {7777, "恶意软件常用端口"},
    {8888, "恶意软件常用端口"},
    {9999, "恶意软件常用端口"}
};

// 已知恶意域名
const QStringList NetworkDetector::KNOWN_BAD_DOMAINS = {
    // 这个列表应该由威胁情报持续更新
};

NetworkDetector::NetworkDetector(QObject *parent)
    : QObject(parent)
{
}

NetworkDetector::~NetworkDetector() {
}

// ========== 网络连接检测 ==========

QList<NetworkConnection> NetworkDetector::collectAllConnections() {
    QList<NetworkConnection> connections;
    emit progressUpdated(0, "开始收集网络连接...");

    // 收集TCP连接
    QList<NetworkConnection> tcpConnections = collectTcpConnections();
    connections.append(tcpConnections);

    // 收集UDP连接
    QList<NetworkConnection> udpConnections = collectUdpConnections();
    connections.append(udpConnections);

    emit progressUpdated(100, QString("网络连接收集完成，共发现 %1 个连接").arg(connections.size()));

    return connections;
}

QList<NetworkConnection> NetworkDetector::collectTcpConnections() {
    QList<NetworkConnection> connections;

    PMIB_TCPTABLE tcpTable = NULL;
    DWORD size = 0;

    // 获取TCP表大小
    if (GetTcpTable(tcpTable, size) == ERROR_INSUFFICIENT_BUFFER) {
        tcpTable = (PMIB_TCPTABLE)malloc(size);
        if (tcpTable == NULL) {
            return connections;
        }
    }

    // 获取TCP连接表
    if (GetTcpTable(tcpTable, size) == NO_ERROR) {
        for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
            NetworkConnection conn = parseTcpConnection(tcpTable->table[i]);
            connections.append(conn);
        }
    }

    free(tcpTable);
    return connections;
}

QList<NetworkConnection> NetworkDetector::collectUdpConnections() {
    QList<NetworkConnection> connections;

    PMIB_UDPTABLE udpTable = NULL;
    DWORD size = 0;

    if (GetUdpTable(udpTable, size) == ERROR_INSUFFICIENT_BUFFER) {
        udpTable = (PMIB_UDPTABLE)malloc(size);
        if (udpTable == NULL) {
            return connections;
        }
    }

    if (GetUdpTable(udpTable, size) == NO_ERROR) {
        for (DWORD i = 0; i < udpTable->dwNumEntries; i++) {
            NetworkConnection conn = parseUdpConnection(udpTable->table[i]);
            connections.append(conn);
        }
    }

    free(udpTable);
    return connections;
}

QList<NetworkConnection> NetworkDetector::collectListeningPorts() {
    QList<NetworkConnection> connections;
    QList<NetworkConnection> all = collectAllConnections();

    for (const NetworkConnection& conn : all) {
        if (conn.isListening) {
            connections.append(conn);
        }
    }

    return connections;
}

// ========== 端口分析 ==========

QList<PortInfo> NetworkDetector::analyzePorts(const QList<NetworkConnection>& connections) {
    QList<PortInfo> analyzed;

    for (const NetworkConnection& conn : connections) {
        PortInfo info;
        info.port = conn.localPort;
        info.protocol = conn.protocol;
        info = COMMON_PORTS.value(info.port, info);

        if (!info.isCommonPort) {
            // 检查是否为可疑端口
            if (SUSPICIOUS_PORTS.contains(info.port)) {
                info.riskLevel = "高";
                info.description = SUSPICIOUS_PORTS.value(info.port);
            }
        }

        analyzed.append(info);
    }

    return analyzed;
}

QString NetworkDetector::getServiceName(int port, const QString& protocol) {
    PortInfo info = COMMON_PORTS.value(port);
    if (!info.service.isEmpty()) {
        return info.service;
    }
    return "Unknown";
}

bool NetworkDetector::isCommonPort(int port) {
    return COMMON_PORTS.contains(port);
}

// ========== 可疑连接检测 ==========

bool NetworkDetector::isConnectionSuspicious(const NetworkConnection& connection) {
    if (checkSuspiciousPort(connection.localPort)) {
        connection.suspiciousReason = QString("本地端口 %1 可疑").arg(connection.localPort);
        return true;
    }

    if (checkSuspiciousPort(connection.remotePort)) {
        connection.suspiciousReason = QString("远程端口 %1 可疑").arg(connection.remotePort);
        return true;
    }

    if (checkSuspiciousAddress(connection.remoteAddress)) {
        connection.suspiciousReason = QString("远程地址 %1 可疑").arg(connection.remoteAddress);
        return true;
    }

    if (checkSuspiciousProcess(connection.processName)) {
        connection.suspiciousReason = QString("进程 %1 可疑").arg(connection.processName);
        return true;
    }

    return false;
}

QList<NetworkConnection> NetworkDetector::findSuspiciousConnections() {
    QList<NetworkConnection> allConnections = collectAllConnections();
    QList<NetworkConnection> suspicious;

    for (const NetworkConnection& conn : allConnections) {
        if (isConnectionSuspicious(conn)) {
            suspicious.append(conn);
            emit suspiciousConnectionFound(conn);
        }
    }

    return suspicious;
}

// ========== 外连分析 ==========

QList<NetworkConnection> NetworkDetector::findOutgoingConnections() {
    QList<NetworkConnection> connections;
    QList<NetworkConnection> all = collectAllConnections();

    for (const NetworkConnection& conn : all) {
        if (conn.isEstablished && conn.isOutgoing) {
            connections.append(conn);
        }
    }

    return connections;
}

QList<NetworkConnection> NetworkDetector::findConnectionsToCountry(const QString& countryCode) {
    Q_UNUSED(countryCode)
    // 需要IP地理位置数据库支持
    return QList<NetworkConnection>();
}

QList<NetworkConnection> NetworkDetector::findConnectionsToKnownBadIPs() {
    QList<NetworkConnection> connections;
    QList<NetworkConnection> all = collectAllConnections();

    for (const NetworkConnection& conn : all) {
        if (isConnectionSuspicious(conn)) {
            connections.append(conn);
        }
    }

    return connections;
}

// ========== 端口扫描检测 ==========

bool NetworkDetector::detectPortScanning() {
    // 检测短时间内大量的SYN_SENT连接
    int synCount = 0;

    QList<NetworkConnection> all = collectAllConnections();
    for (const NetworkConnection& conn : all) {
        if (conn.state == "SYN_SENT" || conn.state == "SYN_RECEIVED") {
            synCount++;
        }
    }

    if (synCount > 100) {
        emit portScanDetected("unknown", synCount);
        return true;
    }

    return false;
}

int NetworkDetector::countConnectionsFromSingleSource() {
    QMap<QString, int> sourceCount;
    QList<NetworkConnection> all = collectAllConnections();

    for (const NetworkConnection& conn : all) {
        if (!conn.remoteAddress.isEmpty() && conn.remoteAddress != "0.0.0.0") {
            sourceCount[conn.remoteAddress]++;
        }
    }

    int maxCount = 0;
    for (const QString& source : sourceCount.keys()) {
        if (sourceCount[source] > maxCount) {
            maxCount = sourceCount[source];
        }
    }

    return maxCount;
}

// ========== DNS查询分析 ==========

QList<QString> NetworkDetector::getRecentDnsQueries() {
    QList<QString> queries;

    // 从DNS缓存获取查询历史
    QProcess process;
    process.start("cmd", QStringList() << "/c" << "ipconfig /displaydns");
    process.waitForFinished();

    QString output = process.readAllStandardOutput();
    QStringList lines = output.split("\n");

    QString currentEntry;
    for (const QString& line : lines) {
        if (line.contains("Record Name")) {
            if (!currentEntry.isEmpty()) {
                queries.append(currentEntry);
            }
            currentEntry = line.split(":")[1].trimmed();
        }
    }

    return queries;
}

// ========== 辅助函数 ==========

bool NetworkDetector::getTcpTable(PMIB_TCPTABLE& table, DWORD& size) {
    return GetTcpTable(table, &size);
}

bool NetworkDetector::getUdpTable(PMIB_UDPTABLE& table, DWORD& size) {
    return GetUdpTable(table, &size);
}

bool NetworkDetector::getExtendedTcpTable(PMIB_TCPEXTROW*& table, DWORD& size) {
    return GetExtendedTcpTable(NULL, &size, FALSE, AF_INET) == ERROR_INSUFFICIENT_BUFFER;
}

NetworkConnection NetworkDetector::parseTcpConnection(const MIB_TCPROW& row) {
    NetworkConnection conn;
    conn.protocol = "TCP";

    // 解析状态
    switch (row.dwState) {
    case MIB_TCP_STATE_CLOSED:
        conn.state = "CLOSED";
        break;
    case MIB_TCP_STATE_LISTENING:
        conn.state = "LISTENING";
        conn.isListening = true;
        break;
    case MIB_TCP_STATE_SYN_SENT:
        conn.state = "SYN_SENT";
        break;
    case MIB_TCP_STATE_SYN_RCVD:
        conn.state = "SYN_RECEIVED";
        break;
    case MIB_TCP_STATE_ESTAB:
        conn.state = "ESTABLISHED";
        conn.isEstablished = true;
        conn.isOutgoing = true;
        break;
    case MIB_TCP_STATE_FIN_WAIT1:
        conn.state = "FIN_WAIT1";
        break;
    case MIB_TCP_STATE_FIN_WAIT2:
        conn.state = "FIN_WAIT2";
        break;
    case MIB_TCP_STATE_CLOSE_WAIT:
        conn.state = "CLOSE_WAIT";
        break;
    case MIB_TCP_STATE_CLOSING:
        conn.state = "CLOSING";
        break;
    case MIB_TCP_STATE_LAST_ACK:
        conn.state = "LAST_ACK";
        break;
    case MIB_TCP_STATE_TIME_WAIT:
        conn.state = "TIME_WAIT";
        break;
    case MIB_TCP_STATE_DELETE_TCB:
        conn.state = "DELETE_TCB";
        break;
    default:
        conn.state = "UNKNOWN";
        break;
    }

    // 解析地址
    BYTE* localIp = (BYTE*)&row.localAddr;
    conn.localAddress = QString("%1.%2.%3.%4").arg(localIp[0]).arg(localIp[1]).arg(localIp[2]).arg(localIp[3]);
    conn.localPort = ntohs(row.dwLocalPort);

    BYTE* remoteIp = (BYTE*)&row.remoteAddr;
    conn.remoteAddress = QString("%1.%2.%3.%4").arg(remoteIp[0]).arg(remoteIp[1]).arg(remoteIp[2]).arg(remoteIp[3]);
    conn.remotePort = ntohs(row.dwRemotePort);

    // 获取进程信息
    conn.processId = 0; // MIB_TCPROW不包含进程ID

    return conn;
}

NetworkConnection NetworkDetector::parseTcpConnectionEx(const MIB_TCPEXTROW& row) {
    NetworkConnection conn = parseTcpConnection((const MIB_TCPROW&)row);
    conn.processId = row.dwOwningPid;

    // 获取进程名
    getProcessNameById(conn.processId, conn.processName);
    getProcessOwnerById(conn.processId, conn.owner);

    return conn;
}

NetworkConnection NetworkDetector::parseUdpConnection(const MIB_UDPROW& row) {
    NetworkConnection conn;
    conn.protocol = "UDP";
    conn.state = "UDP";
    conn.isListening = true;

    // 解析地址
    BYTE* localIp = (BYTE*)&row.dwLocalAddr;
    conn.localAddress = QString("%1.%2.%3.%4").arg(localIp[0]).arg(localIp[1]).arg(localIp[2]).arg(localIp[3]);
    conn.localPort = ntohs(row.dwLocalPort);

    conn.processId = 0;

    return conn;
}

bool NetworkDetector::getProcessNameById(int pid, QString& processName) {
    if (pid == 0) {
        processName = "System";
        return true;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        return false;
    }

    char path[MAX_PATH];
    if (GetModuleFileNameExA(hProcess, NULL, path, MAX_PATH)) {
        QFileInfo info(QString::fromLocal8Bit(path));
        processName = info.fileName();
    }

    CloseHandle(hProcess);
    return !processName.isEmpty();
}

bool NetworkDetector::getProcessOwnerById(int pid, QString& owner) {
    if (pid == 0) {
        owner = "NT AUTHORITY\\SYSTEM";
        return true;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        return false;
    }

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
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
    CloseHandle(hProcess);
    return !owner.isEmpty();
}

bool NetworkDetector::checkSuspiciousPort(int port) {
    // 检查是否为可疑端口
    if (SUSPICIOUS_PORTS.contains(port)) {
        return true;
    }

    // 检查是否为非标准高位端口（大于49152）
    if (port > 49152) {
        return true; // 临时端口通常不可疑，但可能表示后门
    }

    return false;
}

bool NetworkDetector::checkSuspiciousAddress(const QString& address) {
    if (address.isEmpty() || address == "0.0.0.0" || address == "127.0.0.1") {
        return false; // 本地地址
    }

    // 检查是否为私有地址
    if (address.startsWith("10.") ||
        address.startsWith("172.16.") ||
        address.startsWith("172.17.") ||
        address.startsWith("172.18.") ||
        address.startsWith("172.19.") ||
        address.startsWith("172.2") ||
        address.startsWith("172.30.") ||
        address.startsWith("172.31.") ||
        address.startsWith("192.168.")) {
        return false; // 私有地址
    }

    return false;
}

bool NetworkDetector::checkSuspiciousState(const QString& state) {
    // TIME_WAIT、CLOSE_WAIT等状态通常是正常的
    return false;
}

bool NetworkDetector::checkSuspiciousProcess(const QString& processName) {
    QString name = processName.toLower();

    // 检查可疑进程名
    if (name.isEmpty()) {
        return true;
    }

    return false;
}
