#include "DatabaseManager.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QSqlQuery>
#include <QSqlError>
#include <QDebug>
#include <QJsonDocument>
#include <QJsonArray>

DatabaseManager* DatabaseManager::m_instance = nullptr;

DatabaseManager::DatabaseManager(QObject *parent)
    : QObject(parent)
    , m_initialized(false)
{
}

DatabaseManager::~DatabaseManager() {
    if (m_database.isOpen()) {
        m_database.close();
    }
}

DatabaseManager* DatabaseManager::instance() {
    if (!m_instance) {
        m_instance = new DatabaseManager();
    }
    return m_instance;
}

bool DatabaseManager::initialize(const QString& dbPath) {
    m_dbPath = dbPath;

    // 确保数据目录存在
    QDir dataDir(QCoreApplication::applicationDirPath());
    QString absoluteDbPath = dataDir.filePath(dbPath);

    QFile dbFile(absoluteDbPath);
    if (!dbFile.exists()) {
        qDebug() << "Database does not exist, will be created at:" << absoluteDbPath;
    }

    // 添加数据库连接
    m_database = QSqlDatabase::addDatabase("QSQLITE");
    m_database.setDatabaseName(absoluteDbPath);

    if (!m_database.open()) {
        qCritical() << "Failed to open database:" << m_database.lastError().text();
        emit errorOccurred("无法打开数据库: " + m_database.lastError().text());
        return false;
    }

    qDebug() << "Database opened successfully at:" << absoluteDbPath;

    // 创建表结构
    if (!createTables()) {
        qCritical() << "Failed to create database tables";
        return false;
    }

    m_initialized = true;
    emit databaseInitialized();

    return true;
}

bool DatabaseManager::isInitialized() const {
    return m_initialized;
}

bool DatabaseManager::createTables() {
    if (!createSessionTable()) return false;
    if (!createProcessTable()) return false;
    if (!createNetworkConnectionTable()) return false;
    if (!createFileTable()) return false;
    if (!createThreatTable()) return false;
    if (!createLogEntryTable()) return false;
    if (!createWebShellThreatTable()) return false;
    if (!createWebShellRulesTable()) return false;
    if (!createWebShellToolsTable()) return false;
    if (!createDictionaryTable()) return false;

    qDebug() << "All database tables created successfully";
    return true;
}

bool DatabaseManager::createSessionTable() {
    QSqlQuery query(m_database);
    return query.exec(
        "CREATE TABLE IF NOT EXISTS scan_sessions ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "session_name TEXT NOT NULL, "
        "start_time DATETIME NOT NULL, "
        "end_time DATETIME, "
        "status TEXT DEFAULT 'running', "
        "description TEXT, "
        "created_at DATETIME DEFAULT CURRENT_TIMESTAMP"
        ")"
    );
}

bool DatabaseManager::createProcessTable() {
    QSqlQuery query(m_database);
    return query.exec(
        "CREATE TABLE IF NOT EXISTS processes ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "session_id INTEGER, "
        "pid INTEGER, "
        "name TEXT, "
        "path TEXT, "
        "command_line TEXT, "
        "user TEXT, "
        "session_id_str TEXT, "
        "memory_usage INTEGER, "
        "cpu_usage REAL, "
        "start_time DATETIME, "
        "is_suspended BOOLEAN DEFAULT FALSE, "
        "parent_pid TEXT, "
        "description TEXT, "
        "company TEXT, "
        "file_hash TEXT, "
        "is_signed BOOLEAN, "
        "is_verified BOOLEAN, "
        "is_suspicious BOOLEAN DEFAULT FALSE, "
        "suspicious_reason TEXT, "
        "FOREIGN KEY (session_id) REFERENCES scan_sessions(id)"
        ")"
    );
}

bool DatabaseManager::createNetworkConnectionTable() {
    QSqlQuery query(m_database);
    return query.exec(
        "CREATE TABLE IF NOT EXISTS network_connections ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "session_id INTEGER, "
        "local_address TEXT, "
        "local_port INTEGER, "
        "remote_address TEXT, "
        "remote_port INTEGER, "
        "protocol TEXT, "
        "state TEXT, "
        "process_id INTEGER, "
        "process_name TEXT, "
        "owner TEXT, "
        "is_suspicious BOOLEAN DEFAULT FALSE, "
        "suspicious_reason TEXT, "
        "FOREIGN KEY (session_id) REFERENCES scan_sessions(id)"
        ")"
    );
}

bool DatabaseManager::createFileTable() {
    QSqlQuery query(m_database);
    return query.exec(
        "CREATE TABLE IF NOT EXISTS files ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "session_id INTEGER, "
        "path TEXT, "
        "name TEXT, "
        "size INTEGER, "
        "hash_md5 TEXT, "
        "hash_sha256 TEXT, "
        "hash_sha1 TEXT, "
        "create_time DATETIME, "
        "modify_time DATETIME, "
        "access_time DATETIME, "
        "attributes TEXT, "
        "owner TEXT, "
        "is_suspicious BOOLEAN DEFAULT FALSE, "
        "suspicious_reason TEXT, "
        "file_type TEXT, "
        "description TEXT, "
        "FOREIGN KEY (session_id) REFERENCES scan_sessions(id)"
        ")"
    );
}

bool DatabaseManager::createThreatTable() {
    QSqlQuery query(m_database);
    return query.exec(
        "CREATE TABLE IF NOT EXISTS threats ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "session_id INTEGER, "
        "threat_type TEXT, "
        "threat_name TEXT, "
        "description TEXT, "
        "severity TEXT, "
        "file_path TEXT, "
        "process_id INTEGER, "
        "detection_time DATETIME, "
        "status TEXT DEFAULT 'detected', "
        "remediation TEXT, "
        "reference TEXT, "
        "FOREIGN KEY (session_id) REFERENCES scan_sessions(id)"
        ")"
    );
}

bool DatabaseManager::createLogEntryTable() {
    QSqlQuery query(m_database);
    return query.exec(
        "CREATE TABLE IF NOT EXISTS log_entries ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "session_id INTEGER, "
        "log_type TEXT, "
        "timestamp DATETIME, "
        "source TEXT, "
        "event_id INTEGER, "
        "level TEXT, "
        "message TEXT, "
        "raw_data TEXT, "
        "is_anomaly BOOLEAN DEFAULT FALSE, "
        "anomaly_reason TEXT, "
        "FOREIGN KEY (session_id) REFERENCES scan_sessions(id)"
        ")"
    );
}

bool DatabaseManager::createWebShellThreatTable() {
    QSqlQuery query(m_database);
    return query.exec(
        "CREATE TABLE IF NOT EXISTS webshell_threats ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "session_id INTEGER, "
        "file_path TEXT NOT NULL, "
        "threat_type TEXT, "
        "description TEXT, "
        "severity TEXT, "
        "detection_tool TEXT, "
        "signature TEXT, "
        "file_hash TEXT, "
        "file_content TEXT, "
        "is_confirmed BOOLEAN DEFAULT FALSE, "
        "detection_time DATETIME, "
        "tags TEXT, "
        "scan_options TEXT, "
        "recommendation TEXT, "
        "FOREIGN KEY (session_id) REFERENCES scan_sessions(id)"
        ")"
    );
}

bool DatabaseManager::createWebShellRulesTable() {
    QSqlQuery query(m_database);
    return query.exec(
        "CREATE TABLE IF NOT EXISTS webshell_rules ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "rule_name TEXT NOT NULL, "
        "rule_pattern TEXT NOT NULL, "
        "rule_type TEXT, "
        "severity TEXT, "
        "description TEXT, "
        "category TEXT, "
        "is_enabled BOOLEAN DEFAULT TRUE, "
        "match_count INTEGER DEFAULT 0, "
        "created_time DATETIME, "
        "updated_time DATETIME"
        ")"
    );
}

bool DatabaseManager::createWebShellToolsTable() {
    QSqlQuery query(m_database);
    return query.exec(
        "CREATE TABLE IF NOT EXISTS webshell_tools ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "tool_name TEXT NOT NULL, "
        "tool_path TEXT, "
        "tool_version TEXT, "
        "is_available BOOLEAN DEFAULT FALSE, "
        "last_check_time DATETIME, "
        "scan_options TEXT, "
        "supported_extensions TEXT, "
        "description TEXT"
        ")"
    );
}

bool DatabaseManager::createDictionaryTable() {
    QSqlQuery query(m_database);
    return query.exec(
        "CREATE TABLE IF NOT EXISTS builtin_dictionary ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "category TEXT, "
        "name TEXT, "
        "pattern TEXT, "
        "type TEXT, "
        "description TEXT, "
        "hash TEXT, "
        "suffix TEXT, "
        "process_name TEXT, "
        "file_name TEXT, "
        "severity TEXT, "
        "tags TEXT, "
        "update_time DATETIME, "
        "is_enabled BOOLEAN DEFAULT TRUE"
        ")"
    );
}

int DatabaseManager::createSession(const QString& sessionName) {
    QSqlQuery query(m_database);
    query.prepare(
        "INSERT INTO scan_sessions (session_name, start_time, status) "
        "VALUES (:name, :time, :status)"
    );
    query.bindValue(":name", sessionName);
    query.bindValue(":time", QDateTime::currentDateTime());
    query.bindValue(":status", "running");

    if (!query.exec()) {
        qCritical() << "Failed to create session:" << query.lastError().text();
        return -1;
    }

    return query.lastInsertId().toInt();
}

bool DatabaseManager::closeSession(int sessionId) {
    QSqlQuery query(m_database);
    query.prepare(
        "UPDATE scan_sessions SET end_time = :end_time, status = :status "
        "WHERE id = :id"
    );
    query.bindValue(":end_time", QDateTime::currentDateTime());
    query.bindValue(":status", "completed");
    query.bindValue(":id", sessionId);

    return query.exec();
}

QList<QMap<QString, QVariant>> DatabaseManager::getSessions() {
    QList<QMap<QString, QVariant>> result;
    QSqlQuery query(m_database);

    if (!query.exec("SELECT * FROM scan_sessions ORDER BY start_time DESC")) {
        qWarning() << "Failed to get sessions:" << query.lastError().text();
        return result;
    }

    while (query.next()) {
        QMap<QString, QVariant> row;
        for (int i = 0; i < query.record().count(); ++i) {
            row[query.record().fieldName(i)] = query.value(i);
        }
        result.append(row);
    }

    return result;
}

bool DatabaseManager::addProcess(int sessionId, const QMap<QString, QVariant>& process) {
    QSqlQuery query(m_database);
    query.prepare(
        "INSERT INTO processes (session_id, pid, name, path, command_line, user, "
        "memory_usage, cpu_usage, description, company, file_hash, is_signed, "
        "is_verified, is_suspicious, suspicious_reason) "
        "VALUES (:session_id, :pid, :name, :path, :cmd, :user, "
        ":memory, :cpu, :desc, :company, :hash, :signed, "
        ":verified, :suspicious, :reason)"
    );

    query.bindValue(":session_id", sessionId);
    query.bindValue(":pid", process["pid"]);
    query.bindValue(":name", process["name"]);
    query.bindValue(":path", process["path"]);
    query.bindValue(":cmd", process["commandLine"]);
    query.bindValue(":user", process["user"]);
    query.bindValue(":memory", process["memoryUsage"]);
    query.bindValue(":cpu", process["cpuUsage"]);
    query.bindValue(":desc", process["description"]);
    query.bindValue(":company", process["company"]);
    query.bindValue(":hash", process["fileHash"]);
    query.bindValue(":signed", process["isSigned"]);
    query.bindValue(":verified", process["isVerified"]);
    query.bindValue(":suspicious", process["isSuspicious"]);
    query.bindValue(":reason", process["suspiciousReason"]);

    return query.exec();
}

QList<QMap<QString, QVariant>> DatabaseManager::getProcesses(int sessionId) {
    QList<QMap<QString, QVariant>> result;
    QSqlQuery query(m_database);

    query.prepare("SELECT * FROM processes WHERE session_id = :session_id");
    query.bindValue(":session_id", sessionId);

    if (!query.exec()) {
        qWarning() << "Failed to get processes:" << query.lastError().text();
        return result;
    }

    while (query.next()) {
        QMap<QString, QVariant> row;
        for (int i = 0; i < query.record().count(); ++i) {
            row[query.record().fieldName(i)] = query.value(i);
        }
        result.append(row);
    }

    return result;
}

bool DatabaseManager::addNetworkConnection(int sessionId, const QMap<QString, QVariant>& conn) {
    QSqlQuery query(m_database);
    query.prepare(
        "INSERT INTO network_connections (session_id, local_address, local_port, "
        "remote_address, remote_port, protocol, state, process_id, process_name, "
        "owner, is_suspicious, suspicious_reason) "
        "VALUES (:session_id, :local_addr, :local_port, "
        ":remote_addr, :remote_port, :protocol, :state, :pid, :pname, "
        ":owner, :suspicious, :reason)"
    );

    query.bindValue(":session_id", sessionId);
    query.bindValue(":local_addr", conn["localAddress"]);
    query.bindValue(":local_port", conn["localPort"]);
    query.bindValue(":remote_addr", conn["remoteAddress"]);
    query.bindValue(":remote_port", conn["remotePort"]);
    query.bindValue(":protocol", conn["protocol"]);
    query.bindValue(":state", conn["state"]);
    query.bindValue(":pid", conn["processId"]);
    query.bindValue(":pname", conn["processName"]);
    query.bindValue(":owner", conn["owner"]);
    query.bindValue(":suspicious", conn["isSuspicious"]);
    query.bindValue(":reason", conn["suspiciousReason"]);

    return query.exec();
}

QList<QMap<QString, QVariant>> DatabaseManager::getNetworkConnections(int sessionId) {
    QList<QMap<QString, QVariant>> result;
    QSqlQuery query(m_database);

    query.prepare("SELECT * FROM network_connections WHERE session_id = :session_id");
    query.bindValue(":session_id", sessionId);

    if (!query.exec()) {
        qWarning() << "Failed to get network connections:" << query.lastError().text();
        return result;
    }

    while (query.next()) {
        QMap<QString, QVariant> row;
        for (int i = 0; i < query.record().count(); ++i) {
            row[query.record().fieldName(i)] = query.value(i);
        }
        result.append(row);
    }

    return result;
}

bool DatabaseManager::addFile(int sessionId, const QMap<QString, QVariant>& file) {
    QSqlQuery query(m_database);
    query.prepare(
        "INSERT INTO files (session_id, path, name, size, hash_md5, hash_sha256, "
        "hash_sha1, create_time, modify_time, access_time, attributes, "
        "owner, is_suspicious, suspicious_reason, file_type, description) "
        "VALUES (:session_id, :path, :name, :size, :md5, :sha256, "
        ":sha1, :create_time, :modify_time, :access_time, :attrs, "
        ":owner, :suspicious, :reason, :type, :desc)"
    );

    query.bindValue(":session_id", sessionId);
    query.bindValue(":path", file["path"]);
    query.bindValue(":name", file["name"]);
    query.bindValue(":size", file["size"]);
    query.bindValue(":md5", file["hashMd5"]);
    query.bindValue(":sha256", file["hashSha256"]);
    query.bindValue(":sha1", file["hashSha1"]);
    query.bindValue(":create_time", file["createTime"]);
    query.bindValue(":modify_time", file["modifyTime"]);
    query.bindValue(":access_time", file["accessTime"]);
    query.bindValue(":attrs", file["attributes"]);
    query.bindValue(":owner", file["owner"]);
    query.bindValue(":suspicious", file["isSuspicious"]);
    query.bindValue(":reason", file["suspiciousReason"]);
    query.bindValue(":type", file["fileType"]);
    query.bindValue(":desc", file["description"]);

    return query.exec();
}

QList<QMap<QString, QVariant>> DatabaseManager::getFiles(int sessionId) {
    QList<QMap<QString, QVariant>> result;
    QSqlQuery query(m_database);

    query.prepare("SELECT * FROM files WHERE session_id = :session_id");
    query.bindValue(":session_id", sessionId);

    if (!query.exec()) {
        qWarning() << "Failed to get files:" << query.lastError().text();
        return result;
    }

    while (query.next()) {
        QMap<QString, QVariant> row;
        for (int i = 0; i < query.record().count(); ++i) {
            row[query.record().fieldName(i)] = query.value(i);
        }
        result.append(row);
    }

    return result;
}

bool DatabaseManager::addThreat(int sessionId, const QMap<QString, QVariant>& threat) {
    QSqlQuery query(m_database);
    query.prepare(
        "INSERT INTO threats (session_id, threat_type, threat_name, description, "
        "severity, file_path, process_id, detection_time, status, remediation, reference) "
        "VALUES (:session_id, :type, :name, :desc, "
        ":severity, :path, :pid, :time, :status, :remediation, :reference)"
    );

    query.bindValue(":session_id", sessionId);
    query.bindValue(":type", threat["threatType"]);
    query.bindValue(":name", threat["threatName"]);
    query.bindValue(":desc", threat["description"]);
    query.bindValue(":severity", threat["severity"]);
    query.bindValue(":path", threat["filePath"]);
    query.bindValue(":pid", threat["processId"]);
    query.bindValue(":time", QDateTime::currentDateTime());
    query.bindValue(":status", threat["status"]);
    query.bindValue(":remediation", threat["remediation"]);
    query.bindValue(":reference", threat["reference"]);

    return query.exec();
}

QList<QMap<QString, QVariant>> DatabaseManager::getThreats(int sessionId) {
    QList<QMap<QString, QVariant>> result;
    QSqlQuery query(m_database);

    query.prepare("SELECT * FROM threats WHERE session_id = :session_id ORDER BY severity");
    query.bindValue(":session_id", sessionId);

    if (!query.exec()) {
        qWarning() << "Failed to get threats:" << query.lastError().text();
        return result;
    }

    while (query.next()) {
        QMap<QString, QVariant> row;
        for (int i = 0; i < query.record().count(); ++i) {
            row[query.record().fieldName(i)] = query.value(i);
        }
        result.append(row);
    }

    return result;
}

bool DatabaseManager::addLogEntry(int sessionId, const QMap<QString, QVariant>& entry) {
    QSqlQuery query(m_database);
    query.prepare(
        "INSERT INTO log_entries (session_id, log_type, timestamp, source, "
        "event_id, level, message, raw_data, is_anomaly, anomaly_reason) "
        "VALUES (:session_id, :type, :time, :source, "
        ":event_id, :level, :message, :raw, :anomaly, :reason)"
    );

    query.bindValue(":session_id", sessionId);
    query.bindValue(":type", entry["logType"]);
    query.bindValue(":time", entry["timestamp"]);
    query.bindValue(":source", entry["source"]);
    query.bindValue(":event_id", entry["eventId"]);
    query.bindValue(":level", entry["level"]);
    query.bindValue(":message", entry["message"]);
    query.bindValue(":raw", entry["rawData"]);
    query.bindValue(":anomaly", entry["isAnomaly"]);
    query.bindValue(":reason", entry["anomalyReason"]);

    return query.exec();
}

QList<QMap<QString, QVariant>> DatabaseManager::getLogEntries(int sessionId) {
    QList<QMap<QString, QVariant>> result;
    QSqlQuery query(m_database);

    query.prepare("SELECT * FROM log_entries WHERE session_id = :session_id ORDER BY timestamp");
    query.bindValue(":session_id", sessionId);

    if (!query.exec()) {
        qWarning() << "Failed to get log entries:" << query.lastError().text();
        return result;
    }

    while (query.next()) {
        QMap<QString, QVariant> row;
        for (int i = 0; i < query.record().count(); ++i) {
            row[query.record().fieldName(i)] = query.value(i);
        }
        result.append(row);
    }

    return result;
}

bool DatabaseManager::addWebShellThreat(int sessionId, const QMap<QString, QVariant>& threat) {
    QSqlQuery query(m_database);
    query.prepare(
        "INSERT INTO webshell_threats (session_id, file_path, threat_type, description, "
        "severity, detection_tool, signature, file_hash, file_content, is_confirmed, "
        "detection_time, tags, scan_options, recommendation) "
        "VALUES (:session_id, :path, :type, :desc, "
        ":severity, :tool, :signature, :hash, :content, :confirmed, "
        ":time, :tags, :options, :recommendation)"
    );

    query.bindValue(":session_id", sessionId);
    query.bindValue(":path", threat["filePath"]);
    query.bindValue(":type", threat["threatType"]);
    query.bindValue(":desc", threat["description"]);
    query.bindValue(":severity", threat["severity"]);
    query.bindValue(":tool", threat["detectionTool"]);
    query.bindValue(":signature", threat["signature"]);
    query.bindValue(":hash", threat["fileHash"]);
    query.bindValue(":content", threat["fileContent"]);
    query.bindValue(":confirmed", threat["isConfirmed"]);
    query.bindValue(":time", QDateTime::currentDateTime());
    query.bindValue(":tags", threat["tags"]);
    query.bindValue(":options", threat["scanOptions"]);
    query.bindValue(":recommendation", threat["recommendation"]);

    return query.exec();
}

QList<QMap<QString, QVariant>> DatabaseManager::getWebShellThreats(int sessionId) {
    QList<QMap<QString, QVariant>> result;
    QSqlQuery query(m_database);

    query.prepare("SELECT * FROM webshell_threats WHERE session_id = :session_id ORDER BY severity");
    query.bindValue(":session_id", sessionId);

    if (!query.exec()) {
        qWarning() << "Failed to get webshell threats:" << query.lastError().text();
        return result;
    }

    while (query.next()) {
        QMap<QString, QVariant> row;
        for (int i = 0; i < query.record().count(); ++i) {
            row[query.record().fieldName(i)] = query.value(i);
        }
        result.append(row);
    }

    return result;
}

bool DatabaseManager::loadDictionary(const QString& category, const QList<QMap<QString, QVariant>>& items) {
    QSqlQuery query(m_database);

    // 开始事务
    m_database.transaction();

    for (const auto& item : items) {
        query.prepare(
            "INSERT INTO builtin_dictionary (category, name, pattern, type, description, "
            "hash, suffix, process_name, file_name, severity, tags, update_time) "
            "VALUES (:category, :name, :pattern, :type, :desc, "
            ":hash, :suffix, :process, :filename, :severity, :tags, :time)"
        );

        query.bindValue(":category", category);
        query.bindValue(":name", item["name"]);
        query.bindValue(":pattern", item["pattern"]);
        query.bindValue(":type", item["type"]);
        query.bindValue(":desc", item["description"]);
        query.bindValue(":hash", item["hash"]);
        query.bindValue(":suffix", item["suffix"]);
        query.bindValue(":process", item["processName"]);
        query.bindValue(":filename", item["fileName"]);
        query.bindValue(":severity", item["severity"]);
        query.bindValue(":tags", item["tags"]);
        query.bindValue(":time", QDateTime::currentDateTime());

        if (!query.exec()) {
            m_database.rollback();
            qWarning() << "Failed to load dictionary item:" << query.lastError().text();
            return false;
        }
    }

    return m_database.commit();
}

QList<QMap<QString, QVariant>> DatabaseManager::getDictionary(const QString& category) {
    QList<QMap<QString, QVariant>> result;
    QSqlQuery query(m_database);

    if (category.isEmpty()) {
        query.exec("SELECT * FROM builtin_dictionary WHERE is_enabled = 1");
    } else {
        query.prepare("SELECT * FROM builtin_dictionary WHERE category = :category AND is_enabled = 1");
        query.bindValue(":category", category);
    }

    if (!query.exec()) {
        qWarning() << "Failed to get dictionary:" << query.lastError().text();
        return result;
    }

    while (query.next()) {
        QMap<QString, QVariant> row;
        for (int i = 0; i < query.record().count(); ++i) {
            row[query.record().fieldName(i)] = query.value(i);
        }
        result.append(row);
    }

    return result;
}

QList<QMap<QString, QVariant>> DatabaseManager::executeQuery(const QString& queryStr) {
    QList<QMap<QString, QVariant>> result;
    QSqlQuery query(m_database);

    if (!query.exec(queryStr)) {
        qWarning() << "Query failed:" << query.lastError().text();
        return result;
    }

    while (query.next()) {
        QMap<QString, QVariant> row;
        for (int i = 0; i < query.record().count(); ++i) {
            row[query.record().fieldName(i)] = query.value(i);
        }
        result.append(row);
    }

    return result;
}

bool DatabaseManager::cleanupOldData(int daysToKeep) {
    QSqlQuery query(m_database);
    query.prepare(
        "DELETE FROM scan_sessions WHERE start_time < datetime('now', '-' || :days || ' days')"
    );
    query.bindValue(":days", daysToKeep);

    if (!query.exec()) {
        qWarning() << "Failed to cleanup old data:" << query.lastError().text();
        return false;
    }

    qDebug() << "Old data cleanup completed";
    return true;
}
