#include "DatabaseSchemaValidator.h"
#include <QSqlQuery>
#include <QSqlRecord>
#include <QDebug>
#include <QDateTime>

DatabaseSchemaValidator::DatabaseSchemaValidator(QObject *parent)
    : QObject(parent)
{
}

DatabaseSchemaValidator::~DatabaseSchemaValidator() {
    closeDatabase();
}

bool DatabaseSchemaValidator::openDatabase(const QString& dbPath) {
    m_database = QSqlDatabase::addDatabase("QSQLITE");
    m_database.setDatabaseName(dbPath);

    if (!m_database.open()) {
        m_lastError = "无法打开数据库: " + m_database.lastError().text();
        return false;
    }

    return true;
}

void DatabaseSchemaValidator::closeDatabase() {
    if (m_database.isOpen()) {
        m_database.close();
    }
}

QStringList DatabaseSchemaValidator::getTableNames() {
    return m_database.tables();
}

QStringList DatabaseSchemaValidator::getColumnNames(const QString& tableName) {
    QStringList columns;

    QSqlQuery query(m_database);
    query.prepare("PRAGMA table_info(" + tableName + ")");

    if (query.exec()) {
        while (query.next()) {
            columns.append(query.value("name").toString());
        }
    }

    return columns;
}

bool DatabaseSchemaValidator::validateTable(const QString& tableName,
                                             const QMap<QString, QString>& expectedColumns) {
    QStringList actualColumns = getColumnNames(tableName);

    if (actualColumns.isEmpty()) {
        appendToReport(QString("[FAIL] 表 '%1' 不存在或为空").arg(tableName));
        return false;
    }

    appendToReport(QString("[PASS] 表 '%1' 存在, 包含 %2 个字段")
                      .arg(tableName).arg(actualColumns.size()));

    // 检查必要的字段
    bool allColumnsFound = true;
    for (auto it = expectedColumns.begin(); it != expectedColumns.end(); ++it) {
        QString columnName = it.key();
        QString expectedType = it.value();

        if (actualColumns.contains(columnName)) {
            appendToReport(QString("  [PASS] 字段 '%1' 存在").arg(columnName));
        } else {
            appendToReport(QString("  [FAIL] 缺少字段 '%1' (期望类型: %2)").arg(columnName).arg(expectedType));
            allColumnsFound = false;
        }
    }

    return allColumnsFound;
}

int DatabaseSchemaValidator::getRowCount(const QString& tableName) {
    QSqlQuery query(m_database);
    query.prepare("SELECT COUNT(*) FROM " + tableName);

    if (query.exec() && query.next()) {
        return query.value(0).toInt();
    }

    return -1;
}

void DatabaseSchemaValidator::appendToReport(const QString& message) {
    m_validationReport += message + "\n";
}

QString DatabaseSchemaValidator::getValidationReport() {
    return m_validationReport;
}

bool DatabaseSchemaValidator::validateDatabase(const QString& dbPath) {
    m_validationReport.clear();
    appendToReport("========== 数据库架构验证报告 ==========");
    appendToReport(QString("验证时间: %1").arg(QDateTime::currentDateTime().toString(Qt::ISODate)));
    appendToReport(QString("数据库路径: %1").arg(dbPath));
    appendToReport("");

    if (!openDatabase(dbPath)) {
        appendToReport("[FAIL] 无法打开数据库: " + m_lastError);
        emit validationComplete(false, m_validationReport);
        return false;
    }

    appendToReport("[INFO] 数据库连接成功");
    appendToReport("");

    bool result = validateAllTables();
    appendToReport("");
    appendToReport("========== 验证结束 ==========");

    emit validationComplete(result, m_validationReport);

    return result;
}

bool DatabaseSchemaValidator::validateAllTables() {
    bool allPassed = true;

    // 定义所有需要验证的表及其必要字段
    QMap<QString, QMap<QString, QString>> tablesToValidate = {
        {"scan_sessions", {
            {"id", "INTEGER PRIMARY KEY"},
            {"session_name", "TEXT"},
            {"start_time", "DATETIME"},
            {"end_time", "DATETIME"},
            {"status", "TEXT"}
        }},
        {"processes", {
            {"id", "INTEGER PRIMARY KEY"},
            {"session_id", "INTEGER"},
            {"pid", "INTEGER"},
            {"name", "TEXT"},
            {"path", "TEXT"},
            {"command_line", "TEXT"},
            {"user", "TEXT"},
            {"is_suspicious", "BOOLEAN"},
            {"suspicious_reason", "TEXT"}
        }},
        {"network_connections", {
            {"id", "INTEGER PRIMARY KEY"},
            {"session_id", "INTEGER"},
            {"local_address", "TEXT"},
            {"local_port", "INTEGER"},
            {"remote_address", "TEXT"},
            {"remote_port", "INTEGER"},
            {"protocol", "TEXT"},
            {"state", "TEXT"},
            {"is_suspicious", "BOOLEAN"}
        }},
        {"files", {
            {"id", "INTEGER PRIMARY KEY"},
            {"session_id", "INTEGER"},
            {"path", "TEXT"},
            {"name", "TEXT"},
            {"size", "INTEGER"},
            {"hash_md5", "TEXT"},
            {"hash_sha256", "TEXT"},
            {"is_suspicious", "BOOLEAN"}
        }},
        {"threats", {
            {"id", "INTEGER PRIMARY KEY"},
            {"session_id", "INTEGER"},
            {"threat_type", "TEXT"},
            {"threat_name", "TEXT"},
            {"description", "TEXT"},
            {"severity", "TEXT"},
            {"file_path", "TEXT"},
            {"detection_time", "DATETIME"}
        }},
        {"log_entries", {
            {"id", "INTEGER PRIMARY KEY"},
            {"session_id", "INTEGER"},
            {"log_type", "TEXT"},
            {"timestamp", "DATETIME"},
            {"source", "TEXT"},
            {"event_id", "INTEGER"},
            {"level", "TEXT"},
            {"message", "TEXT"},
            {"is_anomaly", "BOOLEAN"}
        }},
        {"webshell_threats", {
            {"id", "INTEGER PRIMARY KEY"},
            {"session_id", "INTEGER"},
            {"file_path", "TEXT"},
            {"threat_type", "TEXT"},
            {"severity", "TEXT"},
            {"detection_tool", "TEXT"},
            {"signature", "TEXT"},
            {"file_hash", "TEXT"}
        }},
        {"webshell_rules", {
            {"id", "INTEGER PRIMARY KEY"},
            {"rule_name", "TEXT"},
            {"rule_pattern", "TEXT"},
            {"rule_type", "TEXT"},
            {"severity", "TEXT"},
            {"is_enabled", "BOOLEAN"}
        }},
        {"webshell_tools", {
            {"id", "INTEGER PRIMARY KEY"},
            {"tool_name", "TEXT"},
            {"tool_path", "TEXT"},
            {"is_available", "BOOLEAN"}
        }},
        {"builtin_dictionary", {
            {"id", "INTEGER PRIMARY KEY"},
            {"category", "TEXT"},
            {"name", "TEXT"},
            {"pattern", "TEXT"},
            {"description", "TEXT"},
            {"severity", "TEXT"}
        }}
    };

    // 验证每个表
    for (auto it = tablesToValidate.begin(); it != tablesToValidate.end(); ++it) {
        QString tableName = it.key();
        QMap<QString, QString> columns = it.value();

        appendToReport(QString("--- 验证表: %1 ---").arg(tableName));

        if (!validateTable(tableName, columns)) {
            allPassed = false;
        }

        // 显示行数
        int rowCount = getRowCount(tableName);
        appendToReport(QString("  [INFO] 表 '%1' 包含 %2 行数据").arg(tableName).arg(rowCount));
        appendToReport("");
    }

    // 检查是否有意外的表
    QStringList actualTables = getTableNames();
    appendToReport("--- 数据库中的所有表 ---");
    for (const QString& table : actualTables) {
        appendToReport(QString("  - %1").arg(table));
    }
    appendToReport("");

    // 统计结果
    appendToReport("========== 验证结果统计 ==========");
    int passedTables = 0;
    int failedTables = 0;

    for (auto it = tablesToValidate.begin(); it != tablesToValidate.end(); ++it) {
        QString tableName = it.key();
        if (actualTables.contains(tableName)) {
            passedTables++;
        } else {
            failedTables++;
        }
    }

    appendToReport(QString("通过验证的表: %1/%2").arg(passedTables).arg(tablesToValidate.size()));
    if (failedTables > 0) {
        appendToReport(QString("未通过的表: %1").arg(failedTables));
    }

    if (allPassed) {
        appendToReport("[SUCCESS] 所有表结构验证通过!");
    } else {
        appendToReport("[FAIL] 部分表结构验证失败!");
    }

    return allPassed;
}
