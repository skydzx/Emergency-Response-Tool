#include "ReportGenerator.h"
#include "DatabaseManager.h"
#include <QFile>
#include <QTextStream>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDateTime>
#include <QDir>
#include <QDebug>

ReportGenerator::ReportGenerator(QObject *parent)
    : QObject(parent)
    , m_includeScreenshots(true)
    , m_compressOutput(false)
    , m_themeColor("#2196F3")
    , m_pageSize("A4")
    , m_orientation("portrait")
{
    initializeDefaultTemplate();
}

ReportGenerator::~ReportGenerator()
{
}

void ReportGenerator::initializeDefaultTemplate()
{
    m_currentTemplate.name = "Default";
    m_currentTemplate.description = "Standard security report template";
    m_currentTemplate.type = "full";
    m_currentTemplate.style = "modern";
    m_currentTemplate.includeCharts = true;
    m_currentTemplate.includeTimeline = true;
    m_currentTemplate.includeRecommendations = true;
    m_currentTemplate.includeEvidence = true;

    // 默认包含的报告部分
    m_currentTemplate.sections = {
        "summary",
        "findings",
        "risk_analysis",
        "recommendations",
        "timeline",
        "evidence",
        "appendix"
    };

    m_reportTitle = "Security Assessment Report";
    m_reportAuthor = "Emergency Response Tool";
}

bool ReportGenerator::generateReport(const QString& type, const QString& outputPath)
{
    emit generationProgress(10);

    bool result = false;
    QString format = type.toLower();

    if (format == "html") {
        result = generateHtmlReport(outputPath);
    } else if (format == "json") {
        result = generateJsonReport(outputPath);
    } else if (format == "pdf") {
        result = generatePdfReport(outputPath);
    } else if (format == "csv") {
        result = generateCsvReport(outputPath);
    } else if (format == "markdown" || format == "md") {
        result = generateMarkdownReport(outputPath);
    } else {
        emit generationFailed("Unsupported report format: " + type);
        return false;
    }

    if (result) {
        emit generationProgress(100);
        emit reportGenerated(outputPath);
    } else {
        emit generationFailed("Failed to generate report");
    }

    return result;
}

bool ReportGenerator::generateHtmlReport(const QString& outputPath)
{
    emit generationProgress(20);

    QString content = R"(<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>)" + m_reportTitle + R"(</title>
    <style>
        :root {
            --primary-color: )" + m_themeColor + R"(;
            --danger-color: #dc3545;
            --warning-color: #ffc107;
            --success-color: #28a745;
            --info-color: #17a2b8;
            --dark-color: #343a40;
            --light-color: #f8f9fa;
        }
        body {
            font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            background: linear-gradient(135deg, )" + m_themeColor + R"(, #1976D2);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
            margin-top: 10px;
        }
        .content {
            padding: 30px;
        }
        .section {
            margin-bottom: 30px;
            border-bottom: 1px solid #eee;
            padding-bottom: 20px;
        }
        .section h2 {
            color: )" + m_themeColor + R"(;
            border-left: 4px solid )" + m_themeColor + R"(;
            padding-left: 15px;
            margin-bottom: 20px;
        }
        .summary-box {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background: )" + m_lightColor + R"(;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            transition: transform 0.3s;
        }
        .stat-card:hover {
            transform: translateY(-5px);
        }
        .stat-card .number {
            font-size: 2.5em;
            font-weight: bold;
            color: )" + m_themeColor + R"(;
        }
        .stat-card .label {
            color: #666;
            margin-top: 5px;
        }
        .finding {
            background: #fff;
            border-left: 4px solid;
            padding: 15px;
            margin: 15px 0;
            border-radius: 0 8px 8px 0;
        }
        .finding.critical { border-color: #dc3545; background: #fff5f5; }
        .finding.high { border-color: #fd7e14; background: #fff8f0; }
        .finding.medium { border-color: #ffc107; background: #fffef0; }
        .finding.low { border-color: #17a2b8; background: #f0f8ff; }
        .finding.info { border-color: #6c757d; background: #f8f9fa; }
        .finding-title {
            font-weight: bold;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .severity-badge {
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 0.8em;
            color: white;
        }
        .severity-badge.critical { background: #dc3545; }
        .severity-badge.high { background: #fd7e14; }
        .severity-badge.medium { background: #ffc107; color: #333; }
        .severity-badge.low { background: #17a2b8; }
        .severity-badge.info { background: #6c757d; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background: )" + m_themeColor + R"(;
            color: white;
        }
        tr:hover {
            background: #f5f5f5;
        }
        .recommendation {
            background: #e3f2fd;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
        }
        .recommendation h4 {
            margin: 0 0 10px 0;
            color: )" + m_themeColor + R"(;
        }
        .footer {
            background: )" + m_darkColor + R"(;
            color: white;
            padding: 20px;
            text-align: center;
            font-size: 0.9em;
        }
        .risk-meter {
            height: 30px;
            background: #e0e0e0;
            border-radius: 15px;
            overflow: hidden;
            margin: 20px 0;
        }
        .risk-level {
            height: 100%;
            transition: width 0.5s;
        }
        .timeline {
            position: relative;
            padding-left: 30px;
        }
        .timeline::before {
            content: '';
            position: absolute;
            left: 10px;
            top: 0;
            bottom: 0;
            width: 2px;
            background: )" + m_themeColor + R"(;
        }
        .timeline-item {
            position: relative;
            margin-bottom: 20px;
        }
        .timeline-item::before {
            content: '';
            position: absolute;
            left: -24px;
            top: 5px;
            width: 12px;
            height: 12px;
            background: )" + m_themeColor + R"(;
            border-radius: 50%;
        }
        @media print {
            body { background: white; }
            .container { box-shadow: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>)" + m_reportTitle + R"(</h1>
            <div class="subtitle">
                <p>生成时间: )" + QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss") + R"(</p>
                <p>扫描人员: )" + m_reportAuthor + R"(
)";

    if (!m_companyName.isEmpty()) {
        content += R"(                <p>所属单位: )" + m_companyName + R"(</p>
)";
    }

    content += R"(            </div>
        </div>
        <div class="content">
)";

    emit generationProgress(40);

    // 报告摘要
    ReportSummary summary = calculateSummary();
    content += R"(
            <div class="section">
                <h2>1. 安全评估摘要</h2>
                <div class="summary-box">
                    <div class="stat-card">
                        <div class="number">)" + QString::number(summary.criticalCount) + R"(</div>
                        <div class="label">严重风险</div>
                    </div>
                    <div class="stat-card">
                        <div class="number">)" + QString::number(summary.highCount) + R"(</div>
                        <div class="label">高风险</div>
                    </div>
                    <div class="stat-card">
                        <div class="number">)" + QString::number(summary.mediumCount) + R"(</div>
                        <div class="label">中风险</div>
                    </div>
                    <div class="stat-card">
                        <div class="number">)" + QString::number(summary.lowCount) + R"(</div>
                        <div class="label">低风险</div>
                    </div>
                </div>
                <div class="risk-meter">
                    <div class="risk-level" style="width: )" + QString::number(summary.riskScore) + R"(%; background: )";

    if (summary.riskScore >= 80) content += "#dc3545";
    else if (summary.riskScore >= 60) content += "#fd7e14";
    else if (summary.riskScore >= 40) content += "#ffc107";
    else content += "#28a745";

    content += R"();"></div>
                </div>
                <p style="text-align: center; font-weight: bold; font-size: 1.2em;">
                    安全等级: <span style="color: )";

    if (summary.riskScore >= 80) content += "#dc3545";
    else if (summary.riskScore >= 60) content += "#fd7e14";
    else if (summary.riskScore >= 40) content += "#ffc107";
    else content += "#28a745";

    content += R"();">)" + summary.securityLevel + R"(</span>
                </p>
            </div>
)";

    emit generationProgress(60);

    // 发现的问题
    content += R"(
            <div class="section">
                <h2>2. 安全发现问题</h2>
                <p>共发现 <strong>)" + QString::number(m_findings.size()) + R"(</strong> 个安全问题</p>
)";

    for (const auto& finding : m_findings) {
        content += R"(
                <div class="finding )" + finding.severity + R"(">
                    <div class="finding-title">
                        <span>)" + finding.title + R"(</span>
                        <span class="severity-badge )" + finding.severity + R"(">)" + finding.severity.toUpper() + R"(</span>
                    </div>
                    <p><strong>描述：</strong>)" + finding.description + R"(</p>
                    <p><strong>影响范围：</strong>)" + finding.affectedItem + R"(</p>
                    <p><strong>证据：</strong><code>)" + finding.evidence + R"(</code></p>
                    <div class="recommendation">
                        <h4>修复建议</h4>
                        <p>)" + finding.recommendation + R"(</p>
                    </div>
                </div>
)";
    }

    content += R"(
            </div>
)";

    emit generationProgress(80);

    // 时间线
    content += R"(
            <div class="section">
                <h2>3. 事件时间线</h2>
                <div class="timeline">
                    <div class="timeline-item">
                        <strong>)" + summary.scanStartTime.toString("yyyy-MM-dd hh:mm:ss") + R"(</strong>
                        <p>扫描开始</p>
                    </div>
                    <div class="timeline-item">
                        <strong>)" + summary.scanEndTime.toString("yyyy-MM-dd hh:mm:ss") + R"(</strong>
                        <p>扫描完成 - 持续时间: )" + summary.scanDuration + R"(</p>
                    </div>
                </div>
            </div>
";

    // 附录
    content += R"(
            <div class="section">
                <h2>附录</h2>
                <h3>A. 扫描信息</h3>
                <table>
                    <tr><td>扫描工具版本</td><td>)" + summary.scannerVersion + R"(</td></tr>
                    <tr><td>扫描目标</td><td>)" + summary.scannedTargets + R"(</td></tr>
                    <tr><td>扫描开始时间</td><td>)" + summary.scanStartTime.toString() + R"(</td></tr>
                    <tr><td>扫描结束时间</td><td>)" + summary.scanEndTime.toString() + R"(</td></tr>
                </table>
            </div>
        </div>
        <div class="footer">
            <p>本报告由应急响应工具自动生成 | )" + QDateTime::currentDateTime().toString("yyyy") + R"(</p>
            <p>免责声明：本报告仅供参考，具体情况请结合实际环境判断</p>
        </div>
    </div>
</body>
</html>
)";

    bool success = writeToFile(outputPath, content);
    return success;
}

bool ReportGenerator::generateJsonReport(const QString& outputPath)
{
    QJsonObject report;

    // 报告元数据
    report["title"] = m_reportTitle;
    report["author"] = m_reportAuthor;
    report["company"] = m_companyName;
    report["generated"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    report["version"] = "1.0";

    // 摘要
    ReportSummary summary = calculateSummary();
    QJsonObject summaryObj;
    summaryObj["totalFindings"] = summary.totalFindings;
    summaryObj["critical"] = summary.criticalCount;
    summaryObj["high"] = summary.highCount;
    summaryObj["medium"] = summary.mediumCount;
    summaryObj["low"] = summary.lowCount;
    summaryObj["riskScore"] = summary.riskScore;
    summaryObj["securityLevel"] = summary.securityLevel;
    summaryObj["scanStartTime"] = summary.scanStartTime.toString(Qt::ISODate);
    summaryObj["scanEndTime"] = summary.scanEndTime.toString(Qt::ISODate);
    summaryObj["duration"] = summary.scanDuration;
    report["summary"] = summaryObj;

    // 发现列表
    QJsonArray findingsArray;
    for (const auto& finding : m_findings) {
        QJsonObject findingObj;
        findingObj["id"] = finding.id;
        findingObj["category"] = finding.category;
        findingObj["severity"] = finding.severity;
        findingObj["title"] = finding.title;
        findingObj["description"] = finding.description;
        findingObj["recommendation"] = finding.recommendation;
        findingObj["evidence"] = finding.evidence;
        findingObj["affectedItem"] = finding.affectedItem;
        findingObj["timestamp"] = finding.timestamp;
        findingObj["score"] = finding.score;
        findingsArray.append(findingObj);
    }
    report["findings"] = findingsArray;

    // 部分信息
    QJsonArray sectionsArray;
    for (const auto& section : m_sections) {
        QJsonObject sectionObj;
        sectionObj["title"] = section.title;
        sectionObj["type"] = section.type;
        sectionObj["content"] = section.content;
        sectionsArray.append(sectionObj);
    }
    report["sections"] = sectionsArray;

    QJsonDocument doc(report);
    return writeToFile(outputPath, doc.toJson(QJsonDocument::Indented));
}

bool ReportGenerator::generatePdfReport(const QString& outputPath)
{
    // 先生成HTML，然后使用外部工具转换为PDF
    QString tempHtml = outputPath + ".temp.html";
    if (!generateHtmlReport(tempHtml)) {
        return false;
    }

    // 使用 wkhtmltopdf 或其他工具转换为PDF
    // 这里是一个占位实现
    QFile::remove(tempHtml);

    // 实际实现需要调用外部PDF生成工具
    emit errorOccurred("PDF generation requires wkhtmltopdf or similar tool");

    // 如果不需要外部工具，可以使用Qt的QPrinter
    // QPrinter printer(QPrinter::HighResolution);
    // printer.setOutputFormat(QPrinter::PdfFormat);
    // printer.setOutputFileName(outputPath);
    // QTextDocument doc;
    // doc.setHtml(generateHtmlContent());
    // doc.print(&printer);

    return false;
}

bool ReportGenerator::generateCsvReport(const QString& outputPath)
{
    QFile file(outputPath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        return false;
    }

    QTextStream out(&file);

    // CSV头部
    out << "ID,Category,Severity,Title,Description,Recommendation,Evidence,Affected Item,Timestamp,Score\n";

    // 数据行
    for (const auto& finding : m_findings) {
        out << finding.id << ","
            << "\"" << finding.category << "\","
            << "\"" << finding.severity << "\","
            << "\"" << finding.title << "\","
            << "\"" << finding.description << "\","
            << "\"" << finding.recommendation << "\","
            << "\"" << finding.evidence << "\","
            << "\"" << finding.affectedItem << "\","
            << "\"" << finding.timestamp << "\","
            << finding.score << "\n";
    }

    file.close();
    return true;
}

bool ReportGenerator::generateMarkdownReport(const QString& outputPath)
{
    QString content = "# " + m_reportTitle + "\n\n";
    content += "**生成时间**: " + QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss") + "\n\n";
    content += "**扫描人员**: " + m_reportAuthor + "\n\n";

    if (!m_companyName.isEmpty()) {
        content += "**所属单位**: " + m_companyName + "\n\n";
    }

    // 摘要
    ReportSummary summary = calculateSummary();
    content += "## 1. 安全评估摘要\n\n";
    content += "| 指标 | 数量 |\n";
    content += "|------|------|\n";
    content << "| 严重风险 | " << summary.criticalCount << " |\n";
    content << "| 高风险 | " << summary.highCount << " |\n";
    content << "| 中风险 | " << summary.mediumCount << " |\n";
    content << "| 低风险 | " << summary.lowCount << " |\n\n";

    content += "**风险评分**: " + QString::number(summary.riskScore) + "/100\n\n";
    content += "**安全等级**: " + summary.securityLevel + "\n\n";

    // 发现
    content += "## 2. 安全发现问题\n\n";

    for (const auto& finding : m_findings) {
        content += "### " + finding.title + "\n\n";
        content += "- **严重程度**: " + finding.severity.toUpper() + "\n";
        content += "- **类别**: " + finding.category + "\n";
        content += "- **描述**: " + finding.description + "\n";
        content += "- **影响范围**: " + finding.affectedItem + "\n";
        content += "- **证据**: `" + finding.evidence + "`\n";
        content += "- **修复建议**: " + finding.recommendation + "\n\n";
    }

    // 时间线
    content += "## 3. 事件时间线\n\n";
    content += "- **扫描开始**: " + summary.scanStartTime.toString() + "\n";
    content += "- **扫描结束**: " + summary.scanEndTime.toString() + "\n";
    content += "- **持续时间**: " + summary.scanDuration + "\n\n";

    return writeToFile(outputPath, content);
}

QList<ReportTemplate> ReportGenerator::getAvailableTemplates()
{
    QList<ReportTemplate> templates;

    // 默认模板
    templates.append(m_currentTemplate);

    // 执行摘要模板
    ReportTemplate executive;
    executive.name = "Executive";
    executive.description = "Executive summary for management";
    executive.type = "executive";
    executive.style = "minimal";
    executive.includeCharts = true;
    executive.includeTimeline = false;
    executive.includeRecommendations = true;
    executive.includeEvidence = false;
    executive.sections = {"summary", "recommendations"};
    templates.append(executive);

    // 技术报告模板
    ReportTemplate technical;
    technical.name = "Technical";
    technical.description = "Detailed technical report";
    technical.type = "technical";
    technical.style = "classic";
    technical.includeCharts = true;
    technical.includeTimeline = true;
    technical.includeRecommendations = true;
    technical.includeEvidence = true;
    technical.sections = {"summary", "findings", "risk_analysis", "timeline", "evidence", "appendix"};
    templates.append(technical);

    return templates;
}

bool ReportGenerator::loadTemplate(const QString& templateName)
{
    QList<ReportTemplate> templates = getAvailableTemplates();

    for (const auto& tmpl : templates) {
        if (tmpl.name == templateName) {
            m_currentTemplate = tmpl;
            emit templateLoaded(templateName);
            return true;
        }
    }
    return false;
}

bool ReportGenerator::saveTemplate(const ReportTemplate& template)
{
    Q_UNUSED(template)
    // 保存自定义模板
    return true;
}

bool ReportGenerator::deleteTemplate(const QString& templateName)
{
    Q_UNUSED(templateName)
    // 删除模板
    return true;
}

ReportTemplate ReportGenerator::getCurrentTemplate()
{
    return m_currentTemplate;
}

void ReportGenerator::addSection(const ReportSection& section)
{
    m_sections.append(section);
}

void ReportGenerator::addFinding(const ReportFinding& finding)
{
    m_findings.append(finding);
}

void ReportGenerator::setSummary(const ReportSummary& summary)
{
    m_summary = summary;
}

void ReportGenerator::clearContent()
{
    m_sections.clear();
    m_findings.clear();
    m_reportData = QJsonObject();
}

bool ReportGenerator::loadScanResults(const QString& filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        emit errorOccurred("Cannot open file: " + filePath);
        return false;
    }

    QByteArray data = file.readAll();
    file.close();

    QJsonParseError error;
    QJsonObject json = QJsonDocument::fromJson(data, error).object();

    if (error.error != QJsonParseError::NoError) {
        emit errorOccurred("JSON parse error: " + error.errorString());
        return false;
    }

    return loadScanResultsFromJson(json);
}

bool ReportGenerator::loadScanResultsFromJson(const QJsonObject& json)
{
    m_reportData = json;

    // 加载摘要
    if (json.contains("summary")) {
        QJsonObject summaryObj = json["summary"].toObject();
        m_summary.totalFindings = summaryObj["totalFindings"].toInt();
        m_summary.criticalCount = summaryObj["critical"].toInt();
        m_summary.highCount = summaryObj["high"].toInt();
        m_summary.mediumCount = summaryObj["medium"].toInt();
        m_summary.lowCount = summaryObj["low"].toInt();
        m_summary.riskScore = summaryObj["riskScore"].toDouble();
    }

    // 加载发现
    if (json.contains("findings")) {
        QJsonArray findingsArray = json["findings"].toArray();
        for (const auto& findingVal : findingsArray) {
            QJsonObject findingObj = findingVal.toObject();
            ReportFinding finding;
            finding.id = findingObj["id"].toInt();
            finding.category = findingObj["category"].toString();
            finding.severity = findingObj["severity"].toString();
            finding.title = findingObj["title"].toString();
            finding.description = findingObj["description"].toString();
            finding.recommendation = findingObj["recommendation"].toString();
            finding.evidence = findingObj["evidence"].toString();
            finding.affectedItem = findingObj["affectedItem"].toString();
            finding.timestamp = findingObj["timestamp"].toString();
            finding.score = findingObj["score"].toInt();
            m_findings.append(finding);
        }
    }

    return true;
}

bool ReportGenerator::saveReportData(const QString& filePath)
{
    QJsonDocument doc(m_reportData);
    return writeToFile(filePath, doc.toJson(QJsonDocument::Indented));
}

QJsonObject ReportGenerator::getReportData()
{
    return m_reportData;
}

ReportSummary ReportGenerator::calculateSummary()
{
    ReportSummary summary;
    summary.totalFindings = m_findings.size();
    summary.totalScans = 1;
    summary.criticalCount = 0;
    summary.highCount = 0;
    summary.mediumCount = 0;
    summary.lowCount = 0;
    summary.infoCount = 0;

    for (const auto& finding : m_findings) {
        if (finding.severity == "critical") summary.criticalCount++;
        else if (finding.severity == "high") summary.highCount++;
        else if (finding.severity == "medium") summary.mediumCount++;
        else if (finding.severity == "low") summary.lowCount++;
        else summary.infoCount++;
    }

    summary.riskScore = calculateRiskScore();
    summary.securityLevel = getSecurityLevel(summary.riskScore);

    if (summary.riskScore >= 80) summary.overallStatus = "danger";
    else if (summary.riskScore >= 60) summary.overallStatus = "warning";
    else summary.overallStatus = "secure";

    summary.scanStartTime = QDateTime::currentDateTime().addSecs(-3600);
    summary.scanEndTime = QDateTime::currentDateTime();
    summary.scanDuration = "60 minutes";
    summary.scannedTargets = "localhost";
    summary.scannerVersion = "1.0.0";

    return summary;
}

int ReportGenerator::calculateRiskScore()
{
    int score = 0;
    for (const auto& finding : m_findings) {
        if (finding.severity == "critical") score += 100;
        else if (finding.severity == "high") score += 50;
        else if (finding.severity == "medium") score += 25;
        else if (finding.severity == "low") score += 10;
        else score += 5;
    }
    return qMin(100, score / qMax(1, m_findings.size()));
}

QString ReportGenerator::getSecurityLevel(int score)
{
    if (score >= 80) return "危险";
    if (score >= 60) return "较差";
    if (score >= 40) return "一般";
    if (score >= 20) return "良好";
    return "优秀";
}

QString ReportGenerator::getHtmlPreview()
{
    return generateHtmlContent();
}

QString ReportGenerator::getTextPreview()
{
    QString text;
    text += "========== " + m_reportTitle + " ==========\n\n";
    text += "生成时间: " + QDateTime::currentDateTime().toString() + "\n\n";

    ReportSummary summary = calculateSummary();
    text += "【安全评估摘要】\n";
    text += QString("严重风险: %1\n").arg(summary.criticalCount);
    text += QString("高风险: %1\n").arg(summary.highCount);
    text += QString("中风险: %1\n").arg(summary.mediumCount);
    text += QString("低风险: %1\n").arg(summary.lowCount);
    text += QString("风险评分: %1/100\n").arg(summary.riskScore);
    text += QString("安全等级: %1\n\n").arg(summary.securityLevel);

    text += "【安全发现问题】\n";
    for (const auto& finding : m_findings) {
        text += QString("\n[%1] %2\n").arg(finding.severity.toUpper()).arg(finding.title);
        text += QString("描述: %1\n").arg(finding.description);
        text += QString("建议: %1\n").arg(finding.recommendation);
    }

    return text;
}

void ReportGenerator::setReportTitle(const QString& title)
{
    m_reportTitle = title;
}

void ReportGenerator::setReportAuthor(const QString& author)
{
    m_reportAuthor = author;
}

void ReportGenerator::setCompanyName(const QString& company)
{
    m_companyName = company;
}

void ReportGenerator::setLogoPath(const QString& path)
{
    m_logoPath = path;
}

void ReportGenerator::setThemeColor(const QString& color)
{
    m_themeColor = color;
}

void ReportGenerator::setPageSize(const QString& size)
{
    m_pageSize = size;
}

void ReportGenerator::setOrientation(const QString& orientation)
{
    m_orientation = orientation;
}

void ReportGenerator::setIncludeScreenshots(bool include)
{
    m_includeScreenshots = include;
}

void ReportGenerator::setCompressOutput(bool compress)
{
    m_compressOutput = compress;
}

QString ReportGenerator::generateHtmlContent()
{
    // 返回HTML内容（简化版）
    return "";
}

QString ReportGenerator::generateJsonContent()
{
    QJsonDocument doc(m_reportData);
    return doc.toJson(QJsonDocument::Indented);
}

QString ReportGenerator::generateMarkdownContent()
{
    // 返回Markdown内容
    return "";
}

QString ReportGenerator::renderSection(const ReportSection& section)
{
    Q_UNUSED(section)
    return "";
}

QString ReportGenerator::renderFinding(const ReportFinding& finding)
{
    Q_UNUSED(finding)
    return "";
}

QString ReportGenerator::renderSummary(const ReportSummary& summary)
{
    Q_UNUSED(summary)
    return "";
}

QString ReportGenerator::generateTable(const QStringList& headers, const QList<QStringList>& rows)
{
    QString html = "<table><thead><tr>";
    for (const QString& header : headers) {
        html += "<th>" + header + "</th>";
    }
    html += "</tr></thead><tbody>";

    for (const QStringList& row : rows) {
        html += "<tr>";
        for (const QString& cell : row) {
            html += "<td>" + cell + "</td>";
        }
        html += "</tr>";
    }

    html += "</tbody></table>";
    return html;
}

QString ReportGenerator::generateRiskMeter(int score)
{
    QString color = "#28a745";
    if (score >= 80) color = "#dc3545";
    else if (score >= 60) color = "#fd7e14";
    else if (score >= 40) color = "#ffc107";

    return QString(R"(<div class="risk-meter"><div class="risk-level" style="width: %1%; background: %2;"></div></div>)").arg(score).arg(color);
}

QString ReportGenerator::getSeverityColor(const QString& severity)
{
    if (severity == "critical") return "#dc3545";
    if (severity == "high") return "#fd7e14";
    if (severity == "medium") return "#ffc107";
    if (severity == "low") return "#17a2b8";
    return "#6c757d";
}

QString ReportGenerator::getSeverityIcon(const QString& severity)
{
    if (severity == "critical") return "🔴";
    if (severity == "high") return "🟠";
    if (severity == "medium") return "🟡";
    if (severity == "low") return "🔵";
    return "⚪";
}

QString ReportGenerator::formatTimestamp(const QDateTime& timestamp)
{
    return timestamp.toString("yyyy-MM-dd hh:mm:ss");
}

bool ReportGenerator::writeToFile(const QString& filePath, const QString& content)
{
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        emit errorOccurred("Cannot write to file: " + filePath);
        return false;
    }

    QTextStream out(&file);
    out << content;
    file.close();

    return true;
}
