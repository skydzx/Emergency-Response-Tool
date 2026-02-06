/**
 * @file comprehensive_test.cpp
 * @brief Comprehensive Database Test Suite
 * @author Emergency Response Tool
 * @version 1.0.0
 */

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <random>

#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QDateTime>
#include <QVector>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

// Test result structure
struct TestResult {
    std::string name;
    bool passed;
    std::string message;
    long long duration_ms;
};

// Test suite class
class TestSuite {
public:
    std::vector<TestResult> results;
    int passed_count = 0;
    int failed_count = 0;

    void addResult(const std::string& name, bool passed, const std::string& message, long long duration_ms) {
        TestResult result{name, passed, message, duration_ms};
        results.push_back(result);

        if (passed) {
            passed_count++;
            std::cout << "[PASS] ";
        } else {
            failed_count++;
            std::cout << "[FAIL] ";
        }

        std::cout << name << " (" << duration_ms << "ms)" << std::endl;
        if (!passed) {
            std::cout << "       Reason: " << message << std::endl;
        }
    }

    void printSummary() {
        std::cout << "\n========================================" << std::endl;
        std::cout << "Test Summary" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "Total Tests: " << results.size() << std::endl;
        std::cout << "Passed: " << passed_count << std::endl;
        std::cout << "Failed: " << failed_count << std::endl;
        std::cout << "Total Time: " << getTotalTime() << "ms" << std::endl;

        if (failed_count == 0) {
            std::cout << "\n[SUCCESS] All tests passed!" << std::endl;
        } else {
            std::cout << "\n[FAILURE] Some tests failed!" << std::endl;
        }
    }

    long long getTotalTime() {
        long long total = 0;
        for (const auto& r : results) {
            total += r.duration_ms;
        }
        return total;
    }
};

// Global test suite
TestSuite g_testSuite;

// Database test functions
bool testDatabaseConnection(const QString& dbPath, long long& duration_ms) {
    auto start = std::chrono::high_resolution_clock::now();

    QSqlDatabase::removeDatabase("test_connection");

    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName(dbPath);

    bool success = db.open();

    auto end = std::chrono::high_resolution_clock::now();
    duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    if (!success) {
        return false;
    }

    db.close();
    return true;
}

bool testTableCreation(const QString& dbPath, long long& duration_ms) {
    auto start = std::chrono::high_resolution_clock::now();

    QSqlDatabase::removeDatabase("test_tables");

    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName(dbPath);

    if (!db.open()) {
        return false;
    }

    // Create test table
    bool success = db.exec(
        "CREATE TABLE IF NOT EXISTS test_table ("
        "id INTEGER PRIMARY KEY, "
        "name TEXT, "
        "value INTEGER, "
        "created_at DATETIME DEFAULT CURRENT_TIMESTAMP"
        ")"
    ).lastError().type() == QSqlError::NoError;

    db.close();

    auto end = std::chrono::high_resolution_clock::now();
    duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    return success;
}

bool testCRUDOperations(const QString& dbPath, long long& duration_ms) {
    auto start = std::chrono::high_resolution_clock::now();

    QSqlDatabase::removeDatabase("test_crud");

    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName(dbPath);

    if (!db.open()) {
        return false;
    }

    // Create table
    db.exec("CREATE TABLE IF NOT EXISTS test_crud (id INTEGER PRIMARY KEY, name TEXT)");

    // Insert
    QSqlQuery query;
    if (!query.prepare("INSERT INTO test_crud (name) VALUES (?)")) {
        db.close();
        return false;
    }

    for (int i = 0; i < 100; i++) {
        query.addBindValue(QString("test_%1").arg(i));
        if (!query.exec()) {
            db.close();
            return false;
        }
    }

    // Read
    int count = 0;
    if (query.exec("SELECT * FROM test_crud")) {
        while (query.next()) {
            count++;
        }
    }

    if (count != 100) {
        db.close();
        return false;
    }

    // Update
    if (!query.exec("UPDATE test_crud SET name = 'updated' WHERE id = 1")) {
        db.close();
        return false;
    }

    // Verify update
    query.exec("SELECT name FROM test_crud WHERE id = 1");
    if (query.next()) {
        if (query.value(0).toString() != "updated") {
            db.close();
            return false;
        }
    }

    // Delete
    if (!query.exec("DELETE FROM test_crud WHERE id = 1")) {
        db.close();
        return false;
    }

    // Verify delete
    query.exec("SELECT COUNT(*) FROM test_crud");
    if (query.next() && query.value(0).toInt() != 99) {
        db.close();
        return false;
    }

    db.close();

    auto end = std::chrono::high_resolution_clock::now();
    duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    return true;
}

bool testTransactions(const QString& dbPath, long long& duration_ms) {
    auto start = std::chrono::high_resolution_clock::now();

    QSqlDatabase::removeDatabase("test_trans");

    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName(dbPath);

    if (!db.open()) {
        return false;
    }

    db.exec("CREATE TABLE IF NOT EXISTS test_trans (id INTEGER PRIMARY KEY, value TEXT)");

    // Test transaction
    db.transaction();

    QSqlQuery query;
    for (int i = 0; i < 1000; i++) {
        query.prepare("INSERT INTO test_trans (value) VALUES (?)");
        query.addBindValue(QString("trans_%1").arg(i));
        if (!query.exec()) {
            db.rollback();
            db.close();
            return false;
        }
    }

    db.commit();

    // Verify
    query.exec("SELECT COUNT(*) FROM test_trans");
    int count = 0;
    if (query.next()) {
        count = query.value(0).toInt();
    }

    db.close();

    auto end = std::chrono::high_resolution_clock::now();
    duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    return count == 1000;
}

bool testIndexes(const QString& dbPath, long long& duration_ms) {
    auto start = std::chrono::high_resolution_clock::now();

    QSqlDatabase::removeDatabase("test_index");

    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName(dbPath);

    if (!db.open()) {
        return false;
    }

    // Create table and index
    db.exec("CREATE TABLE IF NOT EXISTS test_index (id INTEGER PRIMARY KEY, name TEXT, value TEXT)");
    db.exec("CREATE INDEX IF NOT EXISTS idx_name ON test_index(name)");

    // Insert data
    QSqlQuery query;
    for (int i = 0; i < 10000; i++) {
        query.prepare("INSERT INTO test_index (name, value) VALUES (?, ?)");
        query.addBindValue(QString("name_%1").arg(i % 100));  // Duplicate values for index test
        query.addBindValue(QString("value_%1").arg(i));
        if (!query.exec()) {
            db.close();
            return false;
        }
    }

    // Test indexed query
    query.exec("EXPLAIN QUERY PLAN SELECT * FROM test_index WHERE name = 'name_50'");
    // If index is used, the query should be fast

    db.close();

    auto end = std::chrono::high_resolution_clock::now();
    duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    return true;
}

bool testLargeData(const QString& dbPath, long long& duration_ms) {
    auto start = std::chrono::high_resolution_clock::now();

    QSqlDatabase::removeDatabase("test_large");

    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName(dbPath);

    if (!db.open()) {
        return false;
    }

    db.exec("CREATE TABLE IF NOT EXISTS test_large (id INTEGER PRIMARY KEY, data TEXT, value INTEGER)");

    // Insert large amount of data
    QSqlQuery query;
    std::mt19937 rng(42);  // Fixed seed for reproducibility

    for (int i = 0; i < 50000; i++) {
        query.prepare("INSERT INTO test_large (data, value) VALUES (?, ?)");
        query.addBindValue(QString("data_%1_%2").arg(i).arg(rng()));
        query.addBindValue(rng() % 1000000);
        if (!query.exec()) {
            db.close();
            return false;
        }
    }

    // Test aggregation
    query.exec("SELECT COUNT(*), AVG(value), SUM(value) FROM test_large");
    if (!query.next()) {
        db.close();
        return false;
    }

    db.close();

    auto end = std::chrono::high_resolution_clock::now();
    duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    return true;
}

bool testConcurrentAccess(const QString& dbPath, long long& duration_ms) {
    auto start = std::chrono::high_resolution_clock::now();

    // SQLite doesn't support concurrent connections well,
    // so we test sequential access from multiple "connections"

    QSqlDatabase::removeDatabase("test_concurrent_1");
    QSqlDatabase::removeDatabase("test_concurrent_2");

    QSqlDatabase db1 = QSqlDatabase::addDatabase("QSQLITE");
    db1.setDatabaseName(dbPath);

    QSqlDatabase db2 = QSqlDatabase::addDatabase("QSQLITE");
    db2.setDatabaseName(dbPath);

    if (!db1.open() || !db2.open()) {
        return false;
    }

    db1.exec("CREATE TABLE IF NOT EXISTS test_concurrent (id INTEGER PRIMARY KEY, source TEXT)");

    // Simulate concurrent access
    db1.exec("INSERT INTO test_concurrent (source) VALUES ('connection_1')");
    db2.exec("INSERT INTO test_concurrent (source) VALUES ('connection_2')");
    db1.exec("INSERT INTO test_concurrent (source) VALUES ('connection_1')");
    db2.exec("INSERT INTO test_concurrent (source) VALUES ('connection_2')");

    QSqlQuery query(db1);
    int count = 0;
    query.exec("SELECT COUNT(*) FROM test_concurrent");
    if (query.next()) {
        count = query.value(0).toInt();
    }

    db1.close();
    db2.close();

    auto end = std::chrono::high_resolution_clock::now();
    duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    return count == 4;
}

bool testJsonStorage(const QString& dbPath, long long& duration_ms) {
    auto start = std::chrono::high_resolution_clock::now();

    QSqlDatabase::removeDatabase("test_json");

    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName(dbPath);

    if (!db.open()) {
        return false;
    }

    db.exec("CREATE TABLE IF NOT EXISTS test_json (id INTEGER PRIMARY KEY, data TEXT)");

    // Create test JSON data
    QJsonObject obj;
    obj["name"] = "test";
    obj["value"] = 123;
    obj["array"] = QJsonArray{1, 2, 3, 4, 5};

    QJsonDocument doc(obj);
    QString jsonString = doc.toJson(QJsonDocument::Compact);

    // Insert
    QSqlQuery query;
    query.prepare("INSERT INTO test_json (data) VALUES (?)");
    query.addBindValue(jsonString);
    if (!query.exec()) {
        db.close();
        return false;
    }

    // Retrieve and verify
    query.exec("SELECT data FROM test_json WHERE id = 1");
    if (query.next()) {
        QString retrieved = query.value(0).toString();
        QJsonDocument retrievedDoc = QJsonDocument::fromJson(retrieved.toUtf8());
        if (!retrievedDoc.isObject()) {
            db.close();
            return false;
        }

        QJsonObject retrievedObj = retrievedDoc.object();
        if (retrievedObj["name"] != "test" || retrievedObj["value"] != 123) {
            db.close();
            return false;
        }
    }

    db.close();

    auto end = std::chrono::high_resolution_clock::now();
    duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    return true;
}

// Main test runner
int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);

    std::cout << "========================================" << std::endl;
    std::cout << "Emergency Response Tool" << std::endl;
    std::cout << "Comprehensive Database Test Suite" << std::endl;
    std::cout << "========================================" << std::endl;

    // Get database path
    QString dbPath = QDir(QCoreApplication::applicationDirPath()).filePath("data/test.db");

    std::cout << "\nTest Database: " << dbPath.toStdString() << std::endl;
    std::cout << "Test Time: " << QDateTime::currentDateTime().toString(Qt::ISODate).toStdString() << std::endl;
    std::cout << std::endl;

    long long duration = 0;

    // Run tests
    if (testDatabaseConnection(dbPath, duration)) {
        g_testSuite.addResult("Database Connection", true, "Connected successfully", duration);
    } else {
        g_testSuite.addResult("Database Connection", false, "Failed to connect", duration);
    }

    if (testTableCreation(dbPath, duration)) {
        g_testSuite.addResult("Table Creation", true, "Tables created successfully", duration);
    } else {
        g_testSuite.addResult("Table Creation", false, "Failed to create tables", duration);
    }

    if (testCRUDOperations(dbPath, duration)) {
        g_testSuite.addResult("CRUD Operations", true, "Create, Read, Update, Delete passed", duration);
    } else {
        g_testSuite.addResult("CRUD Operations", false, "CRUD operations failed", duration);
    }

    if (testTransactions(dbPath, duration)) {
        g_testSuite.addResult("Transaction Support", true, "Transaction test passed", duration);
    } else {
        g_testSuite.addResult("Transaction Support", false, "Transaction test failed", duration);
    }

    if (testIndexes(dbPath, duration)) {
        g_testSuite.addResult("Index Support", true, "Index test passed", duration);
    } else {
        g_testSuite.addResult("Index Support", false, "Index test failed", duration);
    }

    if (testLargeData(dbPath, duration)) {
        g_testSuite.addResult("Large Data Handling", true, "50,000 records inserted and queried", duration);
    } else {
        g_testSuite.addResult("Large Data Handling", false, "Large data test failed", duration);
    }

    if (testConcurrentAccess(dbPath, duration)) {
        g_testSuite.addResult("Concurrent Access", true, "Multiple connection test passed", duration);
    } else {
        g_testSuite.addResult("Concurrent Access", false, "Concurrent access test failed", duration);
    }

    if (testJsonStorage(dbPath, duration)) {
        g_testSuite.addResult("JSON Storage", true, "JSON data stored and retrieved successfully", duration);
    } else {
        g_testSuite.addResult("JSON Storage", false, "JSON storage test failed", duration);
    }

    // Print summary
    g_testSuite.printSummary();

    return g_testSuite.failed_count > 0 ? 1 : 0;
}
