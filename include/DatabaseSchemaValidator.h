#ifndef DATABASESCHEMAVALIDATOR_H
#define DATABASESCHEMAVALIDATOR_H

#include <QObject>
#include <QSqlDatabase>
#include <QStringList>
#include <QMap>

/**
 * @brief 数据库架构验证器
 * 用于验证数据库表结构是否正确创建
 */
class DatabaseSchemaValidator : public QObject {
    Q_OBJECT

public:
    explicit DatabaseSchemaValidator(QObject *parent = nullptr);
    ~DatabaseSchemaValidator();

    bool validateDatabase(const QString& dbPath);
    bool validateAllTables();
    bool validateTable(const QString& tableName, const QMap<QString, QString>& expectedColumns);
    int getRowCount(const QString& tableName);
    QStringList getTableNames();
    QStringList getColumnNames(const QString& tableName);

    // 获取验证报告
    QString getValidationReport();

signals:
    void validationComplete(bool success, const QString& report);
    void validationError(const QString& error);

private:
    QSqlDatabase m_database;
    QString m_lastError;
    QString m_validationReport;

    void appendToReport(const QString& message);
    bool openDatabase(const QString& dbPath);
    void closeDatabase();
};

#endif // DATABASESCHEMAVALIDATOR_H
