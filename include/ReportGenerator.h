#ifndef REPORTGENERATOR_H
#define REPORTGENERATOR_H

#include <QObject>
#include <QString>
#include <QList>
#include <QMap>
#include <QVector>
#include <QDateTime>
#include <QJsonObject>
#include <QJsonArray>
#include <QTextDocument>
#include <QTextCursor>

struct ReportSection {
    QString title;
    QString content;
    QString type;           // "text", "table", "chart", "list", "code"
    QString style;         // "heading", "normal", "warning", "danger", "info"
    int order;
    QJsonObject data;
    QStringList headers;
    QList<QStringList> rows;
};

struct ReportFinding {
    int id;
    QString category;
    QString severity;       // "critical", "high", "medium", "low", "info"
    QString title;
    QString description;
    QString recommendation;
    QString evidence;
    QString affectedItem;
    QString timestamp;
    int score;
    bool resolved;
    QJsonObject details;
};

struct ReportSummary {
    int totalScans;
    int totalFindings;
    int criticalCount;
    int highCount;
    int mediumCount;
    int lowCount;
    int infoCount;
    double riskScore;
    QString securityLevel;  // "excellent", "good", "fair", "poor", "critical"
    QString overallStatus;  // "secure", "warning", "danger"
    QDateTime scanStartTime;
    QDateTime scanEndTime;
    QString scanDuration;
    QString scannedTargets;
    QString scannerVersion;
};

struct ReportTemplate {
    QString name;
    QString description;
    QString type;          // "full", "executive", "technical", "custom"
    QString style;          // "modern", "classic", "minimal", "corporate"
    QStringList sections;
    bool includeCharts;
    bool includeTimeline;
    bool includeRecommendations;
    bool includeEvidence;
    QJsonObject settings;
};

class ReportGenerator : public QObject {
    Q_OBJECT

public:
    explicit ReportGenerator(QObject *parent = nullptr);
    ~ReportGenerator();

    // 报告生成
    bool generateReport(const QString& type, const QString& outputPath);
    bool generateHtmlReport(const QString& outputPath);
    bool generateJsonReport(const QString& outputPath);
    bool generatePdfReport(const QString& outputPath);
    bool generateCsvReport(const QString& outputPath);
    bool generateMarkdownReport(const QString& outputPath);

    // 报告模板
    QList<ReportTemplate> getAvailableTemplates();
    bool loadTemplate(const QString& templateName);
    bool saveTemplate(const ReportTemplate& template);
    bool deleteTemplate(const QString& templateName);
    ReportTemplate getCurrentTemplate();

    // 报告内容管理
    void addSection(const ReportSection& section);
    void addFinding(const ReportFinding& finding);
    void setSummary(const ReportSummary& summary);
    void clearContent();

    // 报告数据
    bool loadScanResults(const QString& filePath);
    bool loadScanResultsFromJson(const QJsonObject& json);
    bool saveReportData(const QString& filePath);
    QJsonObject getReportData();

    // 风险评估
    ReportSummary calculateSummary();
    int calculateRiskScore();
    QString getSecurityLevel(int score);

    // 报告预览
    QString getHtmlPreview();
    QString getTextPreview();

    // 报告配置
    void setReportTitle(const QString& title);
    void setReportAuthor(const QString& author);
    void setCompanyName(const QString& company);
    void setLogoPath(const QString& path);
    void setThemeColor(const QString& color);

    // 导出选项
    void setPageSize(const QString& size);
    void setOrientation(const QString& orientation);
    void setIncludeScreenshots(bool include);
    void setCompressOutput(bool compress);

signals:
    void reportGenerated(const QString& outputPath);
    void generationProgress(int progress);
    void generationFailed(const QString& error);
    void templateLoaded(const QString& templateName);
    void errorOccurred(const QString& error);

private:
    // 内部数据
    QList<ReportSection> m_sections;
    QList<ReportFinding> m_findings;
    ReportSummary m_summary;
    ReportTemplate m_currentTemplate;
    QJsonObject m_reportData;

    // 报告配置
    QString m_reportTitle;
    QString m_reportAuthor;
    QString m_companyName;
    QString m_logoPath;
    QString m_themeColor;
    QString m_pageSize;
    QString m_orientation;
    bool m_includeScreenshots;
    bool m_compressOutput;

    // 内部方法
    void initializeDefaultTemplate();
    QString generateHtmlContent();
    QString generateJsonContent();
    QString generateMarkdownContent();
    QString renderSection(const ReportSection& section);
    QString renderFinding(const ReportFinding& finding);
    QString renderSummary(const ReportSummary& summary);
    QString generateTable(const QStringList& headers, const QList<QStringList>& rows);
    QString generateRiskMeter(int score);
    QString getSeverityColor(const QString& severity);
    QString getSeverityIcon(const QString& severity);
    QString formatTimestamp(const QDateTime& timestamp);
    bool writeToFile(const QString& filePath, const QString& content);
};

#endif // REPORTGENERATOR_H
