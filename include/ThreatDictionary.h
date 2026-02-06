#ifndef THREATDICTIONARY_H
#define THREATDICTIONARY_H

#include <QObject>
#include <QString>
#include <QList>
#include <QMap>
#include <QVector>
#include <QDateTime>
#include <QJsonObject>
#include <QJsonArray>
#include <QRegularExpression>

struct ThreatEntry {
    int id;
    QString name;
    QString category;         // "process", "file", "webshell", "ransomware", "virus", "trojan"
    QString type;             // "hash", "name", "path", "signature", "behavior"
    QString value;            // Hash value, name pattern, path pattern, or signature
    QString severity;         // "critical", "high", "medium", "low"
    QString description;
    QString recommendation;
    QString source;
    QStringList tags;
    bool isEnabled;
    int matchCount;
    QDateTime createdTime;
    QDateTime updatedTime;
    QDateTime lastMatchedTime;
};

struct DictionaryCategory {
    QString name;
    QString description;
    int entryCount;
    int enabledCount;
    QString lastUpdated;
    QString icon;
};

struct MatchingResult {
    QString originalValue;
    QString matchedValue;
    QString category;
    QString severity;
    QString description;
    QString recommendation;
    QString matchedEntryName;
    int matchedEntryId;
    QDateTime matchedTime;
};

struct RansomwareSignature {
    QString name;
    QString extension;        // 被加密的文件扩展名
    QString ransomwareFamily; // 勒索病毒家族
    QString severity;
    QString description;
    QString ransomNotePattern; // 勒索信模式
    QStringList indicators;
    bool isConfirmed;
};

class ThreatDictionary : public QObject {
    Q_OBJECT

public:
    explicit ThreatDictionary(QObject *parent = nullptr);
    ~ThreatDictionary();

    // 字典加载
    bool loadFromFile(const QString& filePath);
    bool loadFromJson(const QJsonObject& json);
    bool loadBuiltinDictionaries();
    bool saveToFile(const QString& filePath);

    // 字典管理
    bool addEntry(const ThreatEntry& entry);
    bool updateEntry(const ThreatEntry& entry);
    bool deleteEntry(int entryId);
    bool enableEntry(int entryId);
    bool disableEntry(int entryId);
    bool enableCategory(const QString& category);
    bool disableCategory(const QString& category);

    // 字典查询
    ThreatEntry getEntry(int entryId);
    QList<ThreatEntry> getAllEntries();
    QList<ThreatEntry> getEntriesByCategory(const QString& category);
    QList<ThreatEntry> getEnabledEntries();
    QList<DictionaryCategory> getCategories();

    // 特征比对
    MatchingResult matchProcess(const QString& processName, const QString& processPath = "");
    MatchingResult matchFileHash(const QString& hash, const QString& filePath = "");
    MatchingResult matchFileName(const QString& fileName);
    MatchingResult matchFilePath(const QString& filePath);
    MatchingResult matchSignature(const QString& content);

    // 批量比对
    QList<MatchingResult> matchProcesses(const QList<QString>& processNames);
    QList<MatchingResult> matchFileHashes(const QList<QString>& hashes);
    QList<MatchingResult> matchFilePaths(const QList<QString>& filePaths);
    QList<MatchingResult> matchSignatures(const QList<QString>& contents);

    // 勒索病毒检测
    QList<RansomwareSignature> loadRansomwareSignatures();
    QList<RansomwareSignature> detectRansomware(const QString& fileExtension);
    MatchingResult checkRansomwareIndicators(const QString& filePath);

    // 恶意进程检测
    QList<ThreatEntry> loadProcessWhitelist();
    bool isProcessTrusted(const QString& processName, const QString& processPath = "");

    // 恶意域名/IP检测
    bool checkMaliciousDomain(const QString& domain);
    bool checkMaliciousIP(const QString& ipAddress);

    // 统计
    int getTotalEntryCount();
    int getEnabledEntryCount();
    int getMatchCount(int entryId);
    QList<ThreatEntry> getTopMatchedEntries(int topN = 10);

signals:
    void entryAdded(const ThreatEntry& entry);
    void entryUpdated(const ThreatEntry& entry);
    void entryDeleted(int entryId);
    void matchFound(const MatchingResult& result);
    void dictionaryLoaded(int entryCount);
    void errorOccurred(const QString& error);

private:
    // 内部数据
    QList<ThreatEntry> m_entries;
    QList<RansomwareSignature> m_ransomwareSignatures;
    QList<QString> m_processWhitelist;

    // 初始化内置字典
    void initializeProcessDictionary();
    void initializeFileDictionary();
    void initializeWebShellDictionary();
    void initializeRansomwareDictionary();
    void initializeNetworkDictionary();
    void initializeBehaviorDictionary();

    // 匹配辅助方法
    bool matchExact(const QString& value, const QString& pattern);
    bool matchWildcard(const QString& value, const QString& pattern);
    bool matchRegex(const QString& value, const QString& pattern);
    bool matchHash(const QString& value, const QString& pattern);

    // 加载/保存
    QJsonObject toJson();
    ThreatEntry parseEntry(const QJsonObject& json);
    QJsonObject entryToJson(const ThreatEntry& entry);
};

#endif // THREATDICTIONARY_H
