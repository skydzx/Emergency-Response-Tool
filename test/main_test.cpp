#include "DatabaseManager.h"
#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QSqlQuery>
#include <QSqlError>
#include <QDateTime>

bool testDatabaseInitialization() {
    qDebug() << "========== Testing Database Initialization ==========";

    // Get database instance
    DatabaseManager* db = DatabaseManager::instance();

    // Initialize database
    bool result = db->initialize("data/emergency_response.db");
    if (!result) {
        qCritical() << "Failed to initialize database!";
        return false;
    }

    qDebug() << "Database initialized successfully!";

    // Test session creation
    int sessionId = db->createSession("Test Session");
    if (sessionId == -1) {
        qCritical() << "Failed to create session!";
        return false;
    }
    qDebug() << "Session created with ID:" << sessionId;

    // Test adding a process
    QMap<QString, QVariant> process;
    process["pid"] = 1234;
    process["name"] = "test.exe";
    process["path"] = "C:\\test\\test.exe";
    process["commandLine"] = "C:\\test\\test.exe --test";
    process["user"] = "TEST\\User";
    process["memoryUsage"] = 1024;
    process["cpuUsage"] = 5.5;
    process["description"] = "Test process";
    process["company"] = "Test Company";
    process["fileHash"] = "abc123def456";
    process["isSigned"] = true;
    process["isVerified"] = true;
    process["isSuspicious"] = false;
    process["suspiciousReason"] = "";

    if (!db->addProcess(sessionId, process)) {
        qCritical() << "Failed to add process!";
        return false;
    }
    qDebug() << "Process added successfully!";

    // Test adding a network connection
    QMap<QString, QVariant> conn;
    conn["localAddress"] = "192.168.1.100";
    conn["localPort"] = 8080;
    conn["remoteAddress"] = "192.168.1.200";
    conn["remotePort"] = 443;
    conn["protocol"] = "TCP";
    conn["state"] = "ESTABLISHED";
    conn["processId"] = 1234;
    conn["processName"] = "test.exe";
    conn["owner"] = "TEST\\User";
    conn["isSuspicious"] = false;
    conn["suspiciousReason"] = "";

    if (!db->addNetworkConnection(sessionId, conn)) {
        qCritical() << "Failed to add network connection!";
        return false;
    }
    qDebug() << "Network connection added successfully!";

    // Test adding a threat
    QMap<QString, QVariant> threat;
    threat["threatType"] = "WebShell";
    threat["threatName"] = "PHP一句话木马";
    threat["description"] = "检测到可疑PHP WebShell脚本";
    threat["severity"] = "high";
    threat["filePath"] = "C:\\inetpub\\wwwroot\\shell.php";
    threat["processId"] = 0;
    threat["status"] = "detected";
    threat["remediation"] = "删除可疑文件并检查日志";
    threat["reference"] = "CVE-2021-1234";

    if (!db->addThreat(sessionId, threat)) {
        qCritical() << "Failed to add threat!";
        return false;
    }
    qDebug() << "Threat added successfully!";

    // Test querying processes
    auto processes = db->getProcesses(sessionId);
    qDebug() << "Retrieved" << processes.size() << "processes";
    for (const auto& p : processes) {
        qDebug() << "  - PID:" << p["pid"] << "Name:" << p["name"];
    }

    // Test querying network connections
    auto connections = db->getNetworkConnections(sessionId);
    qDebug() << "Retrieved" << connections.size() << "network connections";
    for (const auto& c : connections) {
        qDebug() << "  - Local:" << c["localAddress"] << ":" << c["localPort"]
                 << "Remote:" << c["remoteAddress"] << ":" << c["remotePort"];
    }

    // Test querying threats
    auto threats = db->getThreats(sessionId);
    qDebug() << "Retrieved" << threats.size() << "threats";
    for (const auto& t : threats) {
        qDebug() << "  - Type:" << t["threatType"] << "Name:" << t["threatName"]
                 << "Severity:" << t["severity"];
    }

    // Test session closure
    if (!db->closeSession(sessionId)) {
        qWarning() << "Failed to close session!";
        return false;
    }
    qDebug() << "Session closed successfully!";

    return true;
}

bool testDictionaryLoad() {
    qDebug() << "\n========== Testing Dictionary Load ==========";

    DatabaseManager* db = DatabaseManager::instance();

    // Load WebShell dictionary
    QList<QMap<QString, QVariant>> webshellItems;

    QMap<QString, QVariant> item1;
    item1["name"] = "中国菜刀一句话PHP";
    item1["type"] = "php";
    item1["pattern"] = "eval\\(\\$_POST\\['[^']+'\\]\\);";
    item1["description"] = "中国菜刀一句话木马";
    item1["severity"] = "high";
    item1["tags"] = "[\"菜刀\", \"一句话\", \"eval\"]";
    webshellItems.append(item1);

    QMap<QString, QVariant> item2;
    item2["name"] = "冰蝎Java";
    item2["type"] = "jsp";
    item2["pattern"] = "Class\\.forName\\(\"java\\.lang\\.Runtime\"\\)";
    item2["description"] = "冰蝎JSP WebShell";
    item2["severity"] = "high";
    item2["tags"] = "[\"冰蝎\", \"jsp\", \"Runtime\"]";
    webshellItems.append(item2);

    if (!db->loadDictionary("webshell", webshellItems)) {
        qCritical() << "Failed to load dictionary!";
        return false;
    }

    qDebug() << "Dictionary loaded successfully!";

    // Query dictionary
    auto dictItems = db->getDictionary("webshell");
    qDebug() << "Retrieved" << dictItems.size() << "dictionary items";
    for (const auto& item : dictItems) {
        qDebug() << "  - Name:" << item["name"] << "Pattern:" << item["pattern"]
                 << "Severity:" << item["severity"];
    }

    return true;
}

bool testCleanup() {
    qDebug() << "\n========== Testing Cleanup ==========";

    DatabaseManager* db = DatabaseManager::instance();

    // Test cleanup (should not fail even if no old data)
    bool result = db->cleanupOldData(30);
    if (!result) {
        qWarning() << "Cleanup failed!";
        return false;
    }

    qDebug() << "Cleanup completed successfully!";
    return true;
}

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);

    qDebug() << "========================================";
    qDebug() << "Emergency Response Tool - Database Test";
    qDebug() << "========================================";

    bool allPassed = true;

    // Run tests
    if (!testDatabaseInitialization()) {
        allPassed = false;
        qCritical() << "Database initialization test FAILED!";
    } else {
        qDebug() << "Database initialization test PASSED!";
    }

    if (!testDictionaryLoad()) {
        allPassed = false;
        qCritical() << "Dictionary load test FAILED!";
    } else {
        qDebug() << "Dictionary load test PASSED!";
    }

    if (!testCleanup()) {
        allPassed = false;
        qCritical() << "Cleanup test FAILED!";
    } else {
        qDebug() << "Cleanup test PASSED!";
    }

    qDebug() << "\n========================================";
    if (allPassed) {
        qDebug() << "ALL TESTS PASSED!";
        return 0;
    } else {
        qDebug() << "SOME TESTS FAILED!";
        return 1;
    }
}
