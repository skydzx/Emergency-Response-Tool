#include "test_database.h"
#include "DatabaseManager.h"
#include <QDebug>
#include <QDir>
#include <QTemporaryDir>

int test_count = 0;
int test_passed = 0;
int test_failed = 0;

void test(const QString& name, bool result) {
    test_count++;
    if (result) {
        test_passed++;
        qDebug() << "[PASS]" << name;
    } else {
        test_failed++;
        qDebug() << "[FAIL]" << name;
    }
}

std::tuple<int, int, int> runDatabaseTests(bool verbose) {
    Q_UNUSED(verbose)
    test_count = 0;
    test_passed = 0;
    test_failed = 0;

    qDebug() << "\n========== Database Tests ==========";

    // Create temporary database
    QTemporaryDir tempDir;
    QString dbPath = tempDir.filePath("test_emergency.db");

    // Test database initialization
    DatabaseManager* db = DatabaseManager::instance();
    bool init = db->initialize(dbPath);
    test("Database Initialization", init);

    if (init) {
        // Test session creation
        int sessionId = db->createSession("Test Session");
        test("Session Creation", sessionId > 0);

        if (sessionId > 0) {
            // Test adding a process
            QMap<QString, QVariant> process;
            process["pid"] = 1234;
            process["name"] = "test.exe";
            process["path"] = "C:\\test\\test.exe";

            bool addProcess = db->addProcess(sessionId, process);
            test("Add Process", addProcess);

            // Test querying processes
            auto processes = db->getProcesses(sessionId);
            test("Query Processes", !processes.isEmpty());

            // Test adding a threat
            QMap<QString, QVariant> threat;
            threat["threatType"] = "TestThreat";
            threat["threatName"] = "Test Malware";
            threat["severity"] = "high";

            bool addThreat = db->addThreat(sessionId, threat);
            test("Add Threat", addThreat);

            // Test session closure
            bool closeSession = db->closeSession(sessionId);
            test("Close Session", closeSession);
        }
    }

    qDebug() << "\nDatabase Tests Results:";
    qDebug() << "Total:" << test_count;
    qDebug() << "Passed:" << test_passed;
    qDebug() << "Failed:" << test_failed;

    return {test_count, test_passed, test_failed};
}
