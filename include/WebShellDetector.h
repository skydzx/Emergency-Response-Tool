#ifndef WEBSHELLDETECTOR_H
#define WEBSHELLDETECTOR_H

#include <QObject>
#include <QString>
#include <QList>
#include <QMap>
#include <QVector>
#include <QRegularExpression>
#include <QFile>
#include <QDir>
#include <QDateTime>
#include <QJsonObject>
#include <QJsonArray>

struct WebShellThreat {
    int id;
    QString filePath;
    QString fileName;
    QString fileContent;
    QString fileHash;
    qint64 fileSize;
    QString threatType;      // "eval", "assert", "system", "shell_exec", etc.
    QString description;
    QString severity;        // "low", "medium", "high", "critical"
    QString detectionTool;    // "signature", "behavior", "dshield", "hippo"
    QString signature;        // 匹配的签名
    int lineNumber;
    QString matchedCode;
    QString recommendation;
    QDateTime detectedTime;
    bool isConfirmed;
    QStringList tags;
    QString scanOptions;
};

struct WebShellRule {
    int id;
    QString name;
    QString pattern;
    QString type;            // "regex", "keyword", "signature"
    QString severity;
    QString category;
    QString description;
    bool isEnabled;
    int matchCount;
    QString recommendation;
    QDateTime createdTime;
    QDateTime updatedTime;
};

struct WebShellToolConfig {
    QString name;
    QString path;
    QString version;
    bool isAvailable;
    QString description;
    QStringList supportedExtensions;
    QStringList scanOptions;
    QDateTime lastCheckTime;
};

struct WebShellScanResult {
    QString scanPath;
    int totalFiles;
    int scannedFiles;
    int threatCount;
    int confirmedCount;
    int suspiciousCount;
    QList<WebShellThreat> threats;
    QDateTime startTime;
    QDateTime endTime;
    QString scanOptions;
    int scanDuration;  // milliseconds
};

class WebShellDetector : public QObject {
    Q_OBJECT

public:
    explicit WebShellDetector(QObject *parent = nullptr);
    ~WebShellDetector();

    // 扫描功能
    WebShellScanResult scanDirectory(const QString& path, const QStringList& extensions = QStringList());
    WebShellScanResult scanFile(const QString& filePath);

    // 第三方工具集成
    bool configureDShield(const QString& path);
    bool configureHippo(const QString& path);
    WebShellScanResult scanWithDShield(const QString& webRoot);
    WebShellScanResult scanWithHippo(const QString& webRoot);
    bool checkToolAvailability(const QString& toolName);

    // 规则管理
    QList<WebShellRule> loadRules();
    bool addRule(const WebShellRule& rule);
    bool updateRule(const WebShellRule& rule);
    bool deleteRule(int ruleId);
    bool enableRule(int ruleId);
    bool disableRule(int ruleId);
    QList<WebShellRule> getEnabledRules();

    // 签名检测
    QList<WebShellThreat> detectBySignature(const QString& filePath, const QString& content);
    QList<WebShellThreat> detectByBehavior(const QString& filePath, const QString& content);

    // 威胁管理
    QList<WebShellThreat> getThreats();
    QList<WebShellThreat> getThreatsByType(const QString& type);
    QList<WebShellThreat> getThreatsBySeverity(const QString& severity);
    bool confirmThreat(int threatId);
    bool ignoreThreat(int threatId);
    bool deleteThreatFile(int threatId);

    // 文件操作
    QString readFileContent(const QString& filePath);
    QString calculateFileHash(const QString& filePath);
    QString getFileType(const QString& extension);

signals:
    void progressUpdated(int percentage, const QString& status);
    void fileScanned(const QString& filePath, int threatCount);
    void threatFound(const WebShellThreat& threat);
    void scanCompleted(const WebShellScanResult& result);
    void toolOutput(const QString& toolName, const QString& output);
    void errorOccurred(const QString& error);

private:
    // 检测规则
    QList<WebShellRule> m_detectionRules;
    QList<WebShellRule> loadBuiltinRules();
    void initializeRules();

    // PHP检测
    QList<WebShellThreat> detectPHPShell(const QString& filePath, const QString& content);
    QList<WebShellThreat> detectPHPeval(const QString& filePath, const QString& content);
    QList<WebShellThreat> detectPHPassert(const QString& filePath, const QString& content);
    QList<WebShellThreat> detectPHPsystem(const QString& filePath, const QString& content);
    QList<WebShellThreat> detectPHPshellExec(const QString& filePath, const QString& content);
    QList<WebShellThreat> detectPHPbackdoor(const QString& filePath, const QString& content);

    // ASP/ASPX检测
    QList<WebShellThreat> detectASPShell(const QString& filePath, const QString& content);
    QList<WebShellThreat> detectASPExecute(const QString& filePath, const QString& content);

    // JSP检测
    QList<WebShellThreat> detectJSPShell(const QString& filePath, const QString& content);

    // 通用检测
    QList<WebShellThreat> detectCommonBackdoor(const QString& filePath, const QString& content);
    QList<WebShellThreat> detectObfuscatedCode(const QString& filePath, const QString& content);
    QList<WebShellThreat> detectEncodedContent(const QString& filePath, const QString& content);

    // 辅助方法
    QStringList getWebExtensions();
    QString extractMatchedCode(const QString& content, int position, int length = 100);
    int findLineNumber(const QString& content, int position);
    QString getSeverityFromType(const QString& type);

    // 配置文件
    QString getConfigPath();
    QJsonObject loadConfig();
    bool saveConfig(const QJsonObject& config);

    // 扫描设置
    QStringList m_scanExtensions;
    bool m_scanSubdirectories;
    bool m_checkThirdPartyTools;
    QString m_dshieldPath;
    QString m_hippoPath;

    // 扫描状态
    WebShellScanResult m_currentResult;
    int m_scannedFiles;
    std::atomic<bool> m_cancelled;
};

#endif // WEBSHELLDETECTOR_H
