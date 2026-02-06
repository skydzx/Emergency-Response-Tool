#ifndef THIRDPARTYTOOLSMANAGER_H
#define THIRDPARTYTOOLSMANAGER_H

#include <QObject>
#include <QString>
#include <QList>
#include <QMap>
#include <QVector>
#include <QDateTime>
#include <QJsonObject>
#include <QJsonArray>
#include <QProcess>

struct ToolInfo {
    int id;
    QString name;              // 工具名称
    QString category;          // 工具类别
    QString description;        // 功能描述
    QString version;           // 版本号
    QString path;              // 本地路径
    QString downloadUrl;       // 下载地址
    QString installGuide;      // 安装指南
    QStringList supportedOS;   // 支持的操作系统
    QStringList arguments;     // 默认参数
    QStringList scanOptions;   // 扫描选项
    QString icon;             // 图标名称
    bool isInstalled;          // 是否已安装
    bool isEnabled;           // 是否启用
    bool isPortable;          // 是否便携版
    QString status;           // 状态
    QString lastCheckTime;     // 最后检查时间
    QString lastRunTime;       // 最后运行时间
    QString outputPath;        // 输出路径
    QString configPath;        // 配置文件路径
    QStringList tags;         // 标签
    QMap<QString, QString> metadata; // 元数据
};

struct ToolResult {
    int id;
    int toolId;
    QString toolName;
    QString resultType;        // "text", "json", "html", "xml", "csv"
    QString output;           // 输出内容
    QString outputFile;       // 输出文件路径
    QDateTime startTime;
    QDateTime endTime;
    int exitCode;
    bool success;
    QString errorMessage;
    QMap<QString, QString> metadata;
};

struct ToolCategory {
    QString name;
    QString icon;
    QString description;
    int toolCount;
    int installedCount;
    QList<ToolInfo> tools;
};

class ThirdPartyToolsManager : public QObject {
    Q_OBJECT

public:
    explicit ThirdPartyToolsManager(QObject *parent = nullptr);
    ~ThirdPartyToolsManager();

    // 工具管理
    QList<ToolInfo> getAllTools();
    QList<ToolInfo> getInstalledTools();
    QList<ToolInfo> getEnabledTools();
    QList<ToolInfo> getToolsByCategory(const QString& category);
    ToolInfo getTool(int toolId);
    ToolInfo getToolByName(const QString& name);

    // 工具安装
    bool installTool(int toolId);
    bool uninstallTool(int toolId);
    bool downloadTool(int toolId);
    bool configureTool(int toolId, const QJsonObject& config);
    bool checkToolAvailability(int toolId);
    bool updateTool(int toolId);

    // 工具运行
    bool runTool(int toolId);
    bool runToolWithArgs(int toolId, const QStringList& args);
    bool runToolAsync(int toolId);
    bool stopTool(int toolId);
    bool stopAllTools();
    ToolResult getLastResult(int toolId);
    QList<ToolResult> getToolResults(int toolId);

    // 工具配置
    QJsonObject getToolConfig(int toolId);
    bool saveToolConfig(int toolId, const QJsonObject& config);
    bool resetToolConfig(int toolId);
    QString getToolOutputPath(int toolId);
    bool setToolOutputPath(int toolId, const QString& path);

    // 工具分类
    QList<ToolCategory> getCategories();
    QList<ToolCategory> getCategoriesWithTools();
    QString getCategoryIcon(const QString& category);

signals:
    void toolInstalled(const ToolInfo& tool);
    void toolUninstalled(const ToolInfo& tool);
    void toolStatusChanged(const ToolInfo& tool);
    void toolOutputReceived(const ToolInfo& tool, const QString& output);
    void toolExecutionCompleted(const ToolInfo& tool, const ToolResult& result);
    void toolErrorOccurred(const ToolInfo& tool, const QString& error);
    void downloadProgress(const QString& toolName, int progress);
    void downloadCompleted(const QString& toolName, const QString& path);
    void errorOccurred(const QString& error);

private:
    // 内部数据
    QList<ToolInfo> m_tools;
    QMap<int, ToolResult> m_lastResults;
    QList<ToolResult> m_toolResults;
    QProcess* m_currentProcess;

    // 初始化工具列表
    void initializeTools();
    void initializeProcessTools();
    void initializeMemoryTools();
    void initializeNetworkTools();
    void initializeForensicsTools();
    void initializeWebSecurityTools();
    void initializeSystemTools();

    // 工具检查
    bool checkToolPath(const QString& path);
    bool checkToolVersion(const QString& path, QString& version);

    // 工具运行辅助
    bool executeTool(const QString& command, const QStringList& args, ToolResult& result);
    QString buildCommand(const ToolInfo& tool, const QStringList& args = QStringList());
    QString parseOutputFormat(const QString& format);

    // 配置文件
    QString getConfigPath();
    QJsonObject loadConfig();
    bool saveConfig(const QJsonObject& config);
    QJsonObject loadToolConfig(int toolId);
    bool saveToolConfigToFile(int toolId, const QJsonObject& config);

    // 下载辅助
    bool downloadFile(const QString& url, const QString& path, int& progress);
    bool extractArchive(const QString& archivePath, const QString& destPath);

    // 工具模板
    void createToolTemplate();
};

#endif // THIRDPARTYTOOLSMANAGER_H
