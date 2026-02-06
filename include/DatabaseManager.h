#ifndef DATABASEMANAGER_H
#define DATABASEMANAGER_H

#include <QObject>
#include <QSqlDatabase>
#include <QString>
#include <QList>
#include <QMap>

class DatabaseManager : public QObject {
    Q_OBJECT

public:
    static DatabaseManager* instance();
    bool initialize(const QString& dbPath = "data/emergency_response.db");
    bool isInitialized() const;

    // 扫描会话管理
    int createSession(const QString& sessionName);
    bool closeSession(int sessionId);
    QList<QMap<QString, QVariant>> getSessions();

    // 进程信息
    bool addProcess(int sessionId, const QMap<QString, QVariant>& process);
    QList<QMap<QString, QVariant>> getProcesses(int sessionId);

    // 网络连接
    bool addNetworkConnection(int sessionId, const QMap<QString, QVariant>& conn);
    QList<QMap<QString, QVariant>> getNetworkConnections(int sessionId);

    // 文件信息
    bool addFile(int sessionId, const QMap<QString, QVariant>& file);
    QList<QMap<QString, QVariant>> getFiles(int sessionId);

    // 威胁检测结果
    bool addThreat(int sessionId, const QMap<QString, QVariant>& threat);
    QList<QMap<QString, QVariant>> getThreats(int sessionId);

    // 日志条目
    bool addLogEntry(int sessionId, const QMap<QString, QVariant>& entry);
    QList<QMap<QString, QVariant>> getLogEntries(int sessionId);

    // WebShell检测结果
    bool addWebShellThreat(int sessionId, const QMap<QString, QVariant>& threat);
    QList<QMap<QString, QVariant>> getWebShellThreats(int sessionId);

    // 字典管理
    bool loadDictionary(const QString& category, const QList<QMap<QString, QVariant>>& items);
    QList<QMap<QString, QVariant>> getDictionary(const QString& category);

    // 通用查询
    QList<QMap<QString, QVariant>> executeQuery(const QString& query);

    // 清理过期数据
    bool cleanupOldData(int daysToKeep = 30);

signals:
    void databaseInitialized();
    void errorOccurred(const QString& error);

private:
    DatabaseManager(QObject *parent = nullptr);
    ~DatabaseManager();
    static DatabaseManager* m_instance;

    bool createTables();
    bool createSessionTable();
    bool createProcessTable();
    bool createNetworkConnectionTable();
    bool createFileTable();
    bool createThreatTable();
    bool createLogEntryTable();
    bool createWebShellThreatTable();
    bool createWebShellRulesTable();
    bool createWebShellToolsTable();
    bool createDictionaryTable();

    QSqlDatabase m_database;
    QString m_dbPath;
    bool m_initialized;
};

#endif // DATABASEMANAGER_H
