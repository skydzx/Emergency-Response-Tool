/**
 * @file db_init.cpp
 * @brief Database Initialization Tool
 * @version 1.0.0
 */

#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QTextStream>
#include <QDateTime>
#include <iostream>

void printUsage() {
    std::cout << "========================================" << std::endl;
    std::cout << "Emergency Response Tool - DB Init" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Usage: db_init <command>" << std::endl;
    std::cout << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  init      - Initialize database" << std::endl;
    std::cout << "  validate  - Validate database schema" << std::endl;
    std::cout << "  backup    - Backup database" << std::endl;
    std::cout << "  clear     - Clear all data" << std::endl;
    std::cout << "  info      - Show database info" << std::endl;
    std::cout << std::endl;
}

bool initializeDatabase(const QString& dbPath) {
    qDebug() << "Initializing database at:" << dbPath;

    // Remove existing database connection
    QSqlDatabase::removeDatabase("QSQLITE");

    // Create new database
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName(dbPath);

    if (!db.open()) {
        qCritical() << "Failed to open database:" << db.lastError().text();
        return false;
    }

    // Execute schema initialization from schema.sql
    QFile schemaFile("sql/schema.sql");
    if (!schemaFile.open(QIODevice::ReadOnly)) {
        qCritical() << "Failed to open schema file!";
        db.close();
        return false;
    }

    QTextStream in(&schemaFile);
    QString sql = in.readAll();
    schemaFile.close();

    // Split and execute SQL statements
    QStringList statements = sql.split(";", Qt::SkipEmptyParts);

    QSqlQuery query(db);
    int successCount = 0;
    int failCount = 0;

    for (const QString& statement : statements) {
        QString trimmed = statement.trimmed();
        if (trimmed.isEmpty() || trimmed.startsWith("--") || trimmed.startsWith("PRINT")) {
            continue;
        }

        if (query.exec(trimmed)) {
            successCount++;
        } else {
            QString error = query.lastError().text();
            if (!error.contains("already exists") && !error.contains("duplicate")) {
                qWarning() << "SQL execution warning:" << error;
                failCount++;
            } else {
                successCount++;
            }
        }
    }

    db.close();

    qDebug() << "Database initialization completed!";
    qDebug() << "Successful statements:" << successCount;
    qDebug() << "Failed statements:" << failCount;

    return failCount == 0;
}

bool backupDatabase(const QString& dbPath, const QString& backupPath) {
    qDebug() << "Backing up database from" << dbPath << "to" << backupPath;

    QFile source(dbPath);
    QFile destination(backupPath);

    if (!source.exists()) {
        qCritical() << "Source database does not exist!";
        return false;
    }

    if (destination.exists()) {
        destination.remove();
    }

    if (!source.copy(backupPath)) {
        qCritical() << "Failed to backup database:" << source.errorString();
        return false;
    }

    qDebug() << "Database backup completed!";
    return true;
}

bool clearDatabase(const QString& dbPath) {
    qDebug() << "Clearing database at:" << dbPath;

    QSqlDatabase::removeDatabase("QSQLITE");

    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName(dbPath);

    if (!db.open()) {
        qCritical() << "Failed to open database:" << db.lastError().text();
        return false;
    }

    // Get all tables
    QStringList tables = db.tables();

    // Delete all data from tables
    QSqlQuery query(db);
    for (const QString& table : tables) {
        if (query.exec("DELETE FROM " + table)) {
            qDebug() << "Cleared table:" << table;
        } else {
            qWarning() << "Failed to clear table:" << table;
        }
    }

    db.close();
    qDebug() << "Database cleared!";

    return true;
}

void showDatabaseInfo(const QString& dbPath) {
    qDebug() << "Showing database info for:" << dbPath;

    QSqlDatabase::removeDatabase("QSQLITE");

    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName(dbPath);

    if (!db.open()) {
        qCritical() << "Failed to open database:" << db.lastError().text();
        return;
    }

    qDebug() << "\n========================================";
    qDebug() << "Database Information";
    qDebug() << "========================================";

    // Database info
    qDebug() << "Database Name:" << db.databaseName();
    qDebug() << "Database Size:" << QFile(dbPath).size() << "bytes";

    // Tables
    QStringList tables = db.tables();
    qDebug() << "\nTables (" << tables.size() << "):";
    for (const QString& table : tables) {
        QSqlQuery query(db);
        query.exec("SELECT COUNT(*) FROM " + table);
        int count = 0;
        if (query.next()) {
            count = query.value(0).toInt();
        }
        qDebug() << "  -" << table << ":" << count << "rows";
    }

    db.close();

    qDebug() << "\n========================================";
}

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);

    // Determine database path
    QString dbPath = "data/emergency_response.db";
    QDir appDir(QCoreApplication::applicationDirPath());
    QString absoluteDbPath = appDir.filePath(dbPath);

    // Parse command
    QString command;
    if (argc > 1) {
        command = argv[1];
    } else {
        printUsage();
        return 0;
    }

    bool success = false;

    if (command == "init") {
        success = initializeDatabase(absoluteDbPath);
    } else if (command == "backup") {
        QString backupPath = appDir.filePath("data/backup_") + QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss") + ".db";
        success = backupDatabase(absoluteDbPath, backupPath);
    } else if (command == "clear") {
        success = clearDatabase(absoluteDbPath);
    } else if (command == "info") {
        showDatabaseInfo(absoluteDbPath);
        success = true;
    } else {
        printUsage();
        return 0;
    }

    if (!success) {
        qCritical() << "Operation failed!";
        return 1;
    }

    return 0;
}
