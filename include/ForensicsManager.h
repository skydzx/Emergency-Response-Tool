#ifndef FORENSICSMANAGER_H
#define FORENSICSMANAGER_H

#include <QObject>
#include <QString>
#include <QList>
#include <QMap>
#include <QVector>
#include <QDateTime>
#include <QJsonObject>
#include <QJsonArray>
#include <QProcess>
#include <QFile>
#include <QDir>

struct ForensicsItem {
    int id;
    QString type;              // "memory", "registry", "process", "network", "file", "timeline"
    QString name;
    QString description;
    QString sourcePath;
    QString destPath;
    QString status;            // "pending", "collecting", "completed", "failed"
    QString acquisitionMethod; // "live", "dead", "hybrid"
    QString format;           // "raw", "dmp", "mem", "reg", "csv", "json"
    qint64 size;
    QString hash;
    QDateTime collectedTime;
    QString collectedBy;
    QString notes;
    QJsonObject metadata;
};

struct MemoryAcquisition {
    QString target;
    QString outputPath;
    QString format;           // "raw", "lime", "aff4", "ewf"
    bool compress;
    bool encrypt;
    QString encryptionKey;
    int progress;
    bool suspended;
    bool pagefileIncluded;
    bool srlazyIncluded;
};

struct RegistryHive {
    QString name;
    QString hivePath;        // HKEY_LOCAL_MACHINE, etc.
    QString savePath;
    bool isLoaded;
    QString keyPath;
    QString status;
    QDateTime exportedTime;
};

struct ProcessDump {
    int processId;
    QString processName;
    QString fullPath;
    QString dumpPath;
    bool fullDump;
    bool minidump;
    bool handleDump;
    bool includeThreads;
    QString dumpFormat;      // "dmp", "raw"
    qint64 dumpSize;
    QString status;
    QDateTime dumpedTime;
};

struct TimelineEntry {
    QDateTime timestamp;
    QString source;
    QString eventType;
    QString description;
    QString details;
    QString artifact;
    QString process;
    QString user;
    QString host;
    QString riskLevel;        // "info", "low", "medium", "high", "critical"
    int score;
    QJsonObject rawData;
};

struct ArtifactInfo {
    QString name;
    QString category;
    QString description;
    QString path;
    QString format;
    QString collector;
    bool isAvailable;
    bool isCritical;
    QString lastModified;
    int importance;
};

class ForensicsManager : public QObject {
    Q_OBJECT

public:
    explicit ForensicsManager(QObject *parent = nullptr);
    ~ForensicsManager();

    // 取证项目管理
    QList<ForensicsItem> getAllItems();
    QList<ForensicsItem> getItemsByType(const QString& type);
    ForensicsItem getItem(int itemId);
    bool addItem(const ForensicsItem& item);
    bool updateItem(const ForensicsItem& item);
    bool deleteItem(int itemId);
    bool exportItem(int itemId, const QString& destPath);

    // 内存取证
    bool acquireMemory(const MemoryAcquisition& acquisition);
    bool acquireProcessMemory(int processId, const QString& outputPath);
    bool acquireFullMemory(const QString& outputPath);
    bool suspendAndDumpProcess(int processId, const QString& outputPath);

    // 注册表取证
    bool exportRegistryHive(const QString& hivePath, const QString& savePath);
    bool exportRegistryKey(const QString& keyPath, const QString& savePath);
    QList<RegistryHive> getLoadedHives();
    bool parseRegistryHive(const QString& hivePath, QJsonObject& result);

    // 进程取证
    bool dumpProcess(int processId, const QString& outputPath, bool fullDump = false);
    bool dumpProcessTree(int processId, const QString& outputPath);
    QList<ProcessDump> getProcessDumps();
    bool analyzeProcessDump(const QString& dumpPath);

    // 网络取证
    bool captureNetworkTraffic(const QString& outputPath, int duration = 60);
    bool exportNetstat(const QString& outputPath);
    bool exportPacketCapture(const QString& interface, const QString& outputPath);

    // 文件取证
    bool collectFile(const QString& filePath, const QString& destPath);
    bool collectDirectory(const QString& dirPath, const QString& destPath,
                          const QStringList& filters = QStringList());
    bool calculateFileHash(const QString& filePath, QString& md5, QString& sha1, QString& sha256);

    // 时间线分析
    QList<TimelineEntry> collectTimeline(const QDateTime& startTime,
                                         const QDateTime& endTime);
    bool generateTimelineReport(const QList<TimelineEntry>& timeline,
                                const QString& outputPath);
    QList<TimelineEntry> analyzeTimeline(const QList<TimelineEntry>& timeline);

    // 取证Artifacts
    QList<ArtifactInfo> listAvailableArtifacts();
    bool collectArtifact(const QString& artifactName, const QString& destPath);
    bool collectAllCriticalArtifacts(const QString& destPath);

    // 取证工具调用
    bool executeVolatility(const QStringList& args, QString& output);
    bool executeAutopsy(const QString& casePath, const QString& imagePath);
    bool executeRegistryParser(const QString& hivePath, const QString& outputPath);

    // 案件管理
    bool createCase(const QString& caseName, const QString& casePath);
    bool closeCase();
    QJsonObject getCurrentCase();

signals:
    void acquisitionProgress(const QString& type, int progress);
    void acquisitionCompleted(const QString& type, const QString& outputPath);
    void acquisitionFailed(const QString& type, const QString& error);
    void itemCollected(const ForensicsItem& item);
    void itemStatusChanged(const ForensicsItem& item);
    void timelineGenerated(int entryCount);
    void errorOccurred(const QString& error);

private:
    // 内部数据
    QList<ForensicsItem> m_items;
    QList<MemoryAcquisition> m_acquisitions;
    QList<ProcessDump> m_processDumps;
    QJsonObject m_currentCase;

    // 内部方法
    bool initializeCase(const QString& casePath);
    bool saveItemToDatabase(const ForensicsItem& item);
    bool loadItemsFromDatabase();
    QString getTimestamp();
    QString calculateHash(const QString& filePath, const QString& algorithm);
    bool createDirectoryIfNotExists(const QString& path);
};

#endif // FORENSICSMANAGER_H
