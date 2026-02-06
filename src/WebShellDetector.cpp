/**
 * @file WebShellDetector.cpp
 * @brief WebShell Detection Implementation
 * @version 1.0.0
 */

#include "WebShellDetector.h"
#include <QFile>
#include <QTextStream>
#include <QDebug>
#include <QDirIterator>
#include <QJsonDocument>
#include <QJsonArray>
#include <QCryptographicHash>

WebShellDetector::WebShellDetector(QObject *parent)
    : QObject(parent)
    , m_scannedFiles(0)
    , m_cancelled(false)
{
    initializeRules();

    // 默认扫描扩展名
    m_scanExtensions = {
        ".php", ".php3", ".php4", ".php5", ".phtml", ".phar",
        ".asp", ".aspx", ".asmx", ".ashx",
        ".jsp", ".jspx", ".jsf",
        ".cgi", ".pl", ".py"
    };

    m_scanSubdirectories = true;
    m_checkThirdPartyTools = false;
}

WebShellDetector::~WebShellDetector() {
}

// ========== 扫描功能 ==========

WebShellScanResult WebShellDetector::scanDirectory(const QString& path, const QStringList& extensions) {
    WebShellScanResult result;
    result.scanPath = path;
    result.startTime = QDateTime::currentDateTime();
    m_currentResult = result;
    m_scannedFiles = 0;
    m_cancelled = false;

    if (!QDir(path).exists()) {
        emit errorOccurred(QString("目录不存在: %1").arg(path));
        return result;
    }

    emit progressUpdated(0, QString("开始扫描: %1").arg(path));

    // 获取要扫描的文件
    QStringList filters;
    if (extensions.isEmpty()) {
        filters = getWebExtensions();
    } else {
        filters = extensions;
    }

    // 统计文件数
    int totalFiles = 0;
    QDirIterator it(path, filters, QDir::Files | QDir::Hidden,
                    QDirIterator::Subdirectories);
    while (it.hasNext()) {
        it.next();
        totalFiles++;
    }

    // 重新开始扫描
    it = QDirIterator(path, filters, QDir::Files | QDir::Hidden,
                     QDirIterator::Subdirectories);

    int scanned = 0;
    while (it.hasNext() && !m_cancelled) {
        it.next();
        QString filePath = it.filePath();

        // 扫描文件
        WebShellScanResult fileResult = scanFile(filePath);

        result.scannedFiles++;
        result.threats.append(fileResult.threats);

        scanned++;
        int progress = (scanned * 100 / totalFiles);
        emit progressUpdated(progress, QString("已扫描: %1").arg(it.fileName()));

        if (!fileResult.threats.isEmpty()) {
            for (const WebShellThreat& threat : fileResult.threats) {
                emit threatFound(threat);
            }
        }
    }

    // 统计结果
    result.totalFiles = totalFiles;
    result.threatCount = result.threats.size();
    for (const WebShellThreat& threat : result.threats) {
        if (threat.severity == "critical" || threat.severity == "high") {
            result.confirmedCount++;
        } else {
            result.suspiciousCount++;
        }
    }

    result.endTime = QDateTime::currentDateTime();
    result.scanDuration = result.startTime.msecsTo(result.endTime);

    emit progressUpdated(100, QString("扫描完成，发现 %1 个威胁").arg(result.threatCount));
    emit scanCompleted(result);

    return result;
}

WebShellScanResult WebShellDetector::scanFile(const QString& filePath) {
    WebShellScanResult result;
    result.startTime = QDateTime::currentDateTime();

    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        emit errorOccurred(QString("无法打开文件: %1").arg(filePath));
        return result;
    }

    QString content = file.readAll();
    file.close();

    // 计算文件哈希
    QString fileHash = calculateFileHash(filePath);

    // 文件信息
    QFileInfo info(filePath);
    result.threats = detectBySignature(filePath, content);

    // 添加文件信息到威胁
    for (WebShellThreat& threat : result.threats) {
        threat.fileHash = fileHash;
        threat.fileSize = info.size();
        threat.detectedTime = QDateTime::currentDateTime();
    }

    result.endTime = QDateTime::currentDateTime();
    return result;
}

// ========== 第三方工具集成 ==========

bool WebShellDetector::configureDShield(const QString& path) {
    QFileInfo info(path);
    if (!info.exists()) {
        return false;
    }
    m_dshieldPath = path;
    return true;
}

bool WebShellDetector::configureHippo(const QString& path) {
    QFileInfo info(path);
    if (!info.exists()) {
        return false;
    }
    m_hippoPath = path;
    return true;
}

WebShellScanResult WebShellDetector::scanWithDShield(const QString& webRoot) {
    WebShellScanResult result;
    result.startTime = QDateTime::currentDateTime();

    if (m_dshieldPath.isEmpty() || !QFile::exists(m_dshieldPath)) {
        emit errorOccurred("D盾路径未配置或不存在");
        return result;
    }

    // 调用D盾扫描
    QProcess process;
    QString cmd = QString("\"%1\" /scan:\"%2\" /quiet /report").arg(m_dshieldPath).arg(webRoot);
    process.start("cmd", QStringList() << "/c" << cmd);
    process.waitForFinished();

    QString output = process.readAllStandardOutput();
    emit toolOutput("D盾", output);

    // 解析D盾输出
    // 实际实现需要根据D盾的输出格式进行解析

    result.endTime = QDateTime::currentDateTime();
    return result;
}

WebShellScanResult WebShellDetector::scanWithHippo(const QString& webRoot) {
    WebShellScanResult result;
    result.startTime = QDateTime::currentDateTime();

    if (m_hippoPath.isEmpty() || !QFile::exists(m_hippoPath)) {
        emit errorOccurred("河马路径未配置或不存在");
        return result;
    }

    // 调用河马扫描
    QProcess process;
    QString cmd = QString("\"%1\" --scan \"%2\"").arg(m_hippoPath).arg(webRoot);
    process.start("cmd", QStringList() << "/c" << cmd);
    process.waitForFinished();

    QString output = process.readAllStandardOutput();
    emit toolOutput("河马", output);

    // 解析河马输出
    // 实际实现需要根据河马的输出格式进行解析

    result.endTime = QDateTime::currentDateTime();
    return result;
}

bool WebShellDetector::checkToolAvailability(const QString& toolName) {
    if (toolName == "dshield") {
        return QFile::exists(m_dshieldPath);
    } else if (toolName == "hippo") {
        return QFile::exists(m_hippoPath);
    }
    return false;
}

// ========== 规则管理 ==========

QList<WebShellRule> WebShellDetector::loadRules() {
    return m_detectionRules;
}

void WebShellDetector::initializeRules() {
    m_detectionRules = loadBuiltinRules();
}

QList<WebShellRule> WebShellDetector::loadBuiltinRules() {
    QList<WebShellRule> rules;

    // PHP eval一句话木马
    rules.append({1, "PHP eval一句话", R"(\beval\s*\(\s*\$_(?:GET|POST|REQUEST)\[)", "regex", "critical",
                 "eval一句话", "PHP", true, 0, QDateTime::currentDateTime(), QDateTime::currentDateTime(),
                 "立即删除此文件并检查是否有入侵痕迹"});

    // PHP assert可变变量
    rules.append({2, "PHP assert可变变量", R"(\bassert\s*\(\s*\$\{)", "regex", "critical",
                 "assert可变变量", "PHP", true, 0, QDateTime::currentDateTime(), QDateTime::currentDateTime(),
                 "立即删除此文件"});

    // PHP system函数
    rules.append({3, "PHP system函数", R"(\bsystem\s*\()", "regex", "high",
                 "system函数调用", "PHP", true, 0, QDateTime::currentDateTime(), QDateTime::currentDateTime(),
                 "检查是否为正常功能，必要时删除"});

    // PHP shell_exec
    rules.append({4, "PHP shell_exec", R"(\bshell_exec\s*\()", "regex", "high",
                 "shell_exec函数调用", "PHP", true, 0, QDateTime::currentDateTime(), QDateTime::currentDateTime(),
                 "检查是否为正常功能"});

    // PHP passthru
    rules.append({5, "PHP passthru", R"(\bpassthru\s*\()", "regex", "high",
                 "passthru函数调用", "PHP", true, 0, QDateTime::currentDateTime(), QDateTime::currentDateTime(),
                 "检查是否为正常功能"});

    // PHP exec
    rules.append({6, "PHP exec函数", R"(\bexec\s*\()", "regex", "high",
                 "exec函数调用", "PHP", true, 0, QDateTime::currentDateTime(), QDateTime::currentDateTime(),
                 "检查是否为正常功能"});

    // PHP popen
    rules.append({7, "PHP popen函数", R"(\bpopen\s*\()", "regex", "medium",
                 "popen函数调用", "PHP", true, 0, QDateTime::currentDateTime(), QDateTime::currentDateTime(),
                 "检查是否为正常功能"});

    // PHP proc_open
    rules.append({8, "PHP proc_open", R"(\bproc_open\s*\()", "regex", "medium",
                 "proc_open函数调用", "PHP", true, 0, QDateTime::currentDateTime(), QDateTime::currentDateTime(),
                 "检查是否为正常功能"});

    // PHP base64_decode
    rules.append({9, "PHP base64decode", R"(\bbase64_decode\s*\(\s*\$_(?:GET|POST|REQUEST)\[)", "regex", "high",
                 "base64_decode解码", "PHP", true, 0, QDateTime::currentDateTime(), QDateTime::currentDateTime(),
                 "可能用于混淆恶意代码"});

    // PHP preg_replace eval
    rules.append({10, "PHP preg_replace eval", R"(\bpreg_replace\s*\(\s*['\"].*e['\"])", "regex", "critical",
                  "preg_replace执行代码", "PHP", true, 0, QDateTime::currentDateTime(), QDateTime::currentDateTime(),
                  "立即删除此文件"});

    // PHP create_function
    rules.append({11, "PHP create_function", R"(\bcreate_function\s*\()", "regex", "medium",
                  "create_function创建函数", "PHP", true, 0, QDateTime::currentDateTime(), QDateTime::currentDateTime(),
                  "检查是否为正常功能"});

    // PHP call_user_func
    rules.append({12, "PHP call_user_func", R"(\bcall_user_func\s*\(\s*\$_(?:GET|POST|REQUEST)\[)", "regex", "high",
                  "call_user_func动态调用", "PHP", true, 0, QDateTime::currentDateTime(), QDateTime::currentDateTime(),
                  "可能用于绕过检测"});

    // PHP fopen+fread+fwrite
    rules.append({13, "PHP webshell文件操作", R"(\bfopen\s*\(\s*\$_(?:GET|POST|REQUEST)\[)", "regex", "high",
                  "动态文件操作", "PHP", true, 0, QDateTime::currentDateTime(), QDateTime::currentDateTime(),
                  "可能用于文件管理"});

    // ASP execute
    rules.append({14, "ASP Execute", R"(\bExecute\s*\(\s*Request)", "regex", "critical",
                  "ASP动态执行", "ASP", true, 0, QDateTime::currentDateTime(), QDateTime::currentDateTime(),
                  "立即删除此文件"});

    // ASP eval
    rules.append({15, "ASP Eval", R"(\bEval\s*\(\s*Request)", "regex", "critical",
                  "ASP动态执行", "ASP", true, 0, QDateTime::currentDateTime(), QDateTime::currentDateTime(),
                  "立即删除此文件"});

    // ASPX Execute
    rules.append({16, "ASPX Execute", R"(\.Execute\s*\(\s*Request)", "regex", "critical",
                  "ASPX动态执行", "ASPX", true, 0, QDateTime::currentDateTime(), QDateTime::currentDateTime(),
                  "立即删除此文件"});

    // JSP Runtime.getRuntime
    rules.append({17, "JSP Runtime执行", R"(\bRuntime\.getRuntime\s*\()", "regex", "critical",
                  "JSP命令执行", "JSP", true, 0, QDateTime::currentDateTime(), QDateTime::currentDateTime(),
                  "立即删除此文件"});

    // JSP ProcessBuilder
    rules.append({18, "JSP ProcessBuilder", R"(\bnew\s+ProcessBuilder\s*\()", "regex", "critical",
                  "JSP命令执行", "JSP", true, 0, QDateTime::currentDateTime(), QDateTime::currentDateTime(),
                  "立即删除此文件"});

    // 常见webshell特征
    rules.append({19, "Godzilla管理端", R"(godzilla|哥斯拉|ChinaZ)", "keyword", "critical",
                  "已知WebShell名称", "Common", true, 0, QDateTime::currentDateTime(), QDateTime::currentDateTime(),
                  "立即删除此文件"});

    rules.append({20, "Behinder管理端", R"(behinder|冰蝎|reGeorg)", "keyword", "critical",
                  "已知WebShell名称", "Common", true, 0, QDateTime::currentDateTime(), QDateTime::currentDateTime(),
                  "立即删除此文件"});

    rules.append({21, "中国菜刀", R"(caidao|caidao\.php|一句话)", "keyword", "critical",
                  "已知WebShell名称", "Common", true, 0, QDateTime::currentDateTime(), QDateTime::currentDateTime(),
                  "立即删除此文件"});

    rules.append({22, "Apache Shiro", R"(shiro|rememberMe)", "keyword", "medium",
                  "Shiro配置", "Common", true, 0, QDateTime::currentDateTime(), QDateTime::currentDateTime(),
                  "检查是否为正常配置"});

    return rules;
}

bool WebShellDetector::addRule(const WebShellRule& rule) {
    WebShellRule newRule = rule;
    newRule.id = m_detectionRules.size() + 1;
    newRule.createdTime = QDateTime::currentDateTime();
    newRule.updatedTime = QDateTime::currentDateTime();
    m_detectionRules.append(newRule);
    return true;
}

bool WebShellDetector::updateRule(const WebShellRule& rule) {
    for (int i = 0; i < m_detectionRules.size(); i++) {
        if (m_detectionRules[i].id == rule.id) {
            m_detectionRules[i] = rule;
            m_detectionRules[i].updatedTime = QDateTime::currentDateTime();
            return true;
        }
    }
    return false;
}

bool WebShellDetector::deleteRule(int ruleId) {
    for (int i = 0; i < m_detectionRules.size(); i++) {
        if (m_detectionRules[i].id == ruleId) {
            m_detectionRules.removeAt(i);
            return true;
        }
    }
    return false;
}

bool WebShellDetector::enableRule(int ruleId) {
    for (WebShellRule& rule : m_detectionRules) {
        if (rule.id == ruleId) {
            rule.isEnabled = true;
            return true;
        }
    }
    return false;
}

bool WebShellDetector::disableRule(int ruleId) {
    for (WebShellRule& rule : m_detectionRules) {
        if (rule.id == ruleId) {
            rule.isEnabled = false;
            return true;
        }
    }
    return false;
}

QList<WebShellRule> WebShellDetector::getEnabledRules() {
    QList<WebShellRule> enabled;
    for (const WebShellRule& rule : m_detectionRules) {
        if (rule.isEnabled) {
            enabled.append(rule);
        }
    }
    return enabled;
}

// ========== 签名检测 ==========

QList<WebShellThreat> WebShellDetector::detectBySignature(const QString& filePath, const QString& content) {
    QList<WebShellThreat> threats;
    QList<WebShellRule> rules = getEnabledRules();

    for (const WebShellRule& rule : rules) {
        if (rule.type == "regex") {
            QRegularExpression re(rule.pattern);
            QRegularExpressionMatchIterator it = re.globalMatch(content);

            while (it.hasNext()) {
                QRegularExpressionMatch match = it.next();

                WebShellThreat threat;
                threat.id = threats.size() + 1;
                threat.filePath = filePath;
                threat.fileName = QFileInfo(filePath).fileName();
                threat.fileContent = content;
                threat.threatType = rule.category;
                threat.description = rule.description;
                threat.severity = rule.severity;
                threat.detectionTool = "signature";
                threat.signature = rule.name;
                threat.lineNumber = findLineNumber(content, match.capturedStart());
                threat.matchedCode = extractMatchedCode(content, match.capturedStart());
                threat.recommendation = rule.recommendation;
                threat.detectedTime = QDateTime::currentDateTime();
                threat.isConfirmed = (threat.severity == "critical" || threat.severity == "high");
                threat.tags.append(rule.category);

                threats.append(threat);
            }
        } else if (rule.type == "keyword") {
            int pos = content.indexOf(rule.pattern, 0, Qt::CaseInsensitive);
            while (pos >= 0) {
                WebShellThreat threat;
                threat.id = threats.size() + 1;
                threat.filePath = filePath;
                threat.fileName = QFileInfo(filePath).fileName();
                threat.fileContent = content;
                threat.threatType = rule.category;
                threat.description = rule.description;
                threat.severity = rule.severity;
                threat.detectionTool = "signature";
                threat.signature = rule.name;
                threat.lineNumber = findLineNumber(content, pos);
                threat.matchedCode = extractMatchedCode(content, pos);
                threat.recommendation = rule.recommendation;
                threat.detectedTime = QDateTime::currentDateTime();
                threat.isConfirmed = (threat.severity == "critical" || threat.severity == "high");
                threat.tags.append(rule.category);

                threats.append(threat);

                pos = content.indexOf(rule.pattern, pos + 1, Qt::CaseInsensitive);
            }
        }
    }

    return threats;
}

QList<WebShellThreat> WebShellDetector::detectByBehavior(const QString& filePath, const QString& content) {
    Q_UNUSED(filePath)
    Q_UNUSED(content)
    QList<WebShellThreat> threats;
    // 行为分析检测实现
    return threats;
}

// ========== 威胁管理 ==========

QList<WebShellThreat> WebShellDetector::getThreats() {
    return m_currentResult.threats;
}

QList<WebShellThreat> WebShellDetector::getThreatsByType(const QString& type) {
    QList<WebShellThreat> filtered;
    for (const WebShellThreat& threat : m_currentResult.threats) {
        if (threat.threatType == type) {
            filtered.append(threat);
        }
    }
    return filtered;
}

QList<WebShellThreat> WebShellDetector::getThreatsBySeverity(const QString& severity) {
    QList<WebShellThreat> filtered;
    for (const WebShellThreat& threat : m_currentResult.threats) {
        if (threat.severity == severity) {
            filtered.append(threat);
        }
    }
    return filtered;
}

bool WebShellDetector::confirmThreat(int threatId) {
    for (WebShellThreat& threat : m_currentResult.threats) {
        if (threat.id == threatId) {
            threat.isConfirmed = true;
            return true;
        }
    }
    return false;
}

bool WebShellDetector::ignoreThreat(int threatId) {
    for (WebShellThreat& threat : m_currentResult.threats) {
        if (threat.id == threatId) {
            threat.severity = "info";
            return true;
        }
    }
    return false;
}

bool WebShellDetector::deleteThreatFile(int threatId) {
    for (const WebShellThreat& threat : m_currentResult.threats) {
        if (threat.id == threatId) {
            if (QFile::exists(threat.filePath)) {
                return QFile::remove(threat.filePath);
            }
        }
    }
    return false;
}

// ========== 辅助方法 ==========

QStringList WebShellDetector::getWebExtensions() {
    return m_scanExtensions;
}

QString WebShellDetector::readFileContent(const QString& filePath) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return QString();
    }

    QTextStream in(&file);
    QString content = in.readAll();
    file.close();

    return content;
}

QString WebShellDetector::calculateFileHash(const QString& filePath) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return QString();
    }

    QCryptographicHash hash(QCryptographicHash::Sha256);
    if (hash.addData(&file)) {
        file.close();
        return hash.result().toHex();
    }

    file.close();
    return QString();
}

QString WebShellDetector::getFileType(const QString& extension) {
    if (extension.contains("php", Qt::CaseInsensitive)) return "PHP";
    if (extension.contains("asp", Qt::CaseInsensitive)) return "ASP";
    if (extension.contains("aspx", Qt::CaseInsensitive)) return "ASP.NET";
    if (extension.contains("jsp", Qt::CaseInsensitive)) return "JSP";
    return "Unknown";
}

QString WebShellDetector::extractMatchedCode(const QString& content, int position, int length) {
    int start = qMax(0, position - 30);
    int end = qMin(content.length(), position + length);
    return content.mid(start, end - start).replace("\n", " ").replace("\r", " ");
}

int WebShellDetector::findLineNumber(const QString& content, int position) {
    int line = 1;
    for (int i = 0; i < position && i < content.length(); i++) {
        if (content[i] == '\n') {
            line++;
        }
    }
    return line;
}

QString WebShellDetector::getSeverityFromType(const QString& type) {
    if (type == "eval" || type == "assert") return "critical";
    if (type == "system" || type == "shell_exec") return "high";
    return "medium";
}

QString WebShellDetector::getConfigPath() {
    return "config/webshell_detector.json";
}

QJsonObject WebShellDetector::loadConfig() {
    QFile file(getConfigPath());
    if (!file.open(QIODevice::ReadOnly)) {
        return QJsonObject();
    }

    QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    file.close();
    return doc.object();
}

bool WebShellDetector::saveConfig(const QJsonObject& config) {
    QFile file(getConfigPath());
    if (!file.open(QIODevice::WriteOnly)) {
        return false;
    }

    QJsonDocument doc(config);
    file.write(doc.toJson(QJsonDocument::Indented));
    file.close();
    return true;
}

// ========== PHP检测 ==========

QList<WebShellThreat> WebShellDetector::detectPHPShell(const QString& filePath, const QString& content) {
    QList<WebShellThreat> threats;
    // 综合PHP WebShell检测
    threats.append(detectPHPeval(filePath, content));
    threats.append(detectPHPsystem(filePath, content));
    threats.append(detectPHPbackdoor(filePath, content));
    return threats;
}

QList<WebShellThreat> WebShellDetector::detectPHPeval(const QString& filePath, const QString& content) {
    QList<WebShellThreat> threats;

    QRegularExpression re(R"(\beval\s*\(\s*(\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\[[^\]]*\]))");
    QRegularExpressionMatchIterator it = re.globalMatch(content);

    while (it.hasNext()) {
        QRegularExpressionMatch match = it.next();
        WebShellThreat threat;
        threat.filePath = filePath;
        threat.fileName = QFileInfo(filePath).fileName();
        threat.threatType = "eval";
        threat.description = "PHP eval一句话木马";
        threat.severity = "critical";
        threat.detectionTool = "signature";
        threat.matchedCode = match.captured(1);
        threat.lineNumber = findLineNumber(content, match.capturedStart());
        threat.recommendation = "立即删除此文件";
        threat.detectedTime = QDateTime::currentDateTime();
        threat.isConfirmed = true;
        threats.append(threat);
    }

    return threats;
}

QList<WebShellThreat> WebShellDetector::detectPHPassert(const QString& filePath, const QString& content) {
    QList<WebShellThreat> threats;

    QRegularExpression re(R"(\bassert\s*\(\s*(\$\{?[\w\[\]'"]+\}?))");
    QRegularExpressionMatchIterator it = re.globalMatch(content);

    while (it.hasNext()) {
        QRegularExpressionMatch match = it.next();
        WebShellThreat threat;
        threat.filePath = filePath;
        threat.fileName = QFileInfo(filePath).fileName();
        threat.threatType = "assert";
        threat.description = "PHP assert可变变量";
        threat.severity = "critical";
        threat.detectionTool = "signature";
        threat.matchedCode = match.captured(1);
        threat.lineNumber = findLineNumber(content, match.capturedStart());
        threat.recommendation = "立即删除此文件";
        threat.detectedTime = QDateTime::currentDateTime();
        threat.isConfirmed = true;
        threats.append(threat);
    }

    return threats;
}

QList<WebShellThreat> WebShellDetector::detectPHPsystem(const QString& filePath, const QString& content) {
    QList<WebShellThreat> threats;

    QRegularExpression re(R"(\bsystem\s*\(\s*(\$_(?:GET|POST|REQUEST)\[[^\]]*\]))");
    QRegularExpressionMatchIterator it = re.globalMatch(content);

    while (it.hasNext()) {
        QRegularExpressionMatch match = it.next();
        WebShellThreat threat;
        threat.filePath = filePath;
        threat.fileName = QFileInfo(filePath).fileName();
        threat.threatType = "system";
        threat.description = "PHP system命令执行";
        threat.severity = "high";
        threat.detectionTool = "signature";
        threat.matchedCode = match.captured(1);
        threat.lineNumber = findLineNumber(content, match.capturedStart());
        threat.recommendation = "检查文件功能，必要时删除";
        threat.detectedTime = QDateTime::currentDateTime();
        threats.append(threat);
    }

    return threats;
}

QList<WebShellThreat> WebShellDetector::detectPHPshellExec(const QString& filePath, const QString& content) {
    QList<WebShellThreat> threats;

    QRegularExpression re(R"(\bshell_exec\s*\(\s*(\$_(?:GET|POST|REQUEST)\[[^\]]*\]))");
    QRegularExpressionMatchIterator it = re.globalMatch(content);

    while (it.hasNext()) {
        QRegularExpressionMatch match = it.next();
        WebShellThreat threat;
        threat.filePath = filePath;
        threat.fileName = QFileInfo(filePath).fileName();
        threat.threatType = "shell_exec";
        threat.description = "PHP shell_exec命令执行";
        threat.severity = "high";
        threat.detectionTool = "signature";
        threat.matchedCode = match.captured(1);
        threat.recommendation = "检查文件功能，必要时删除";
        threat.detectedTime = QDateTime::currentDateTime();
        threats.append(threat);
    }

    return threats;
}

QList<WebShellThreat> WebShellDetector::detectPHPbackdoor(const QString& filePath, const QString& content) {
    QList<WebShellThreat> threats;

    // 常见PHP WebShell特征
    QStringList patterns = {
        R"(\$\w+\s*=\s*['\"][^'\"]+['\"]\s*;.*\beval\b)",
        R"(\beval\s*\(\s*gzinflate\s*\()",
        R"(\beval\s*\(\s*base64_decode\s*\()",
        R"(\$\w+(\s*\[.+?\]\s*)*\s*=\s*\$_(?:GET|POST|REQUEST)\[)",
        R"(chr\([0-9]+\)\s*\.\s*chr\([0-9]+\))"
    };

    for (const QString& pattern : patterns) {
        QRegularExpression re(pattern);
        QRegularExpressionMatchIterator it = re.globalMatch(content);

        while (it.hasNext()) {
            QRegularExpressionMatch match = it.next();
            WebShellThreat threat;
            threat.filePath = filePath;
            threat.fileName = QFileInfo(filePath).fileName();
            threat.threatType = "backdoor";
            threat.description = "PHP WebShell后门";
            threat.severity = "high";
            threat.detectionTool = "signature";
            threat.matchedCode = extractMatchedCode(content, match.capturedStart());
            threat.lineNumber = findLineNumber(content, match.capturedStart());
            threat.recommendation = "立即删除此文件";
            threat.detectedTime = QDateTime::currentDateTime();
            threat.isConfirmed = true;
            threats.append(threat);
        }
    }

    return threats;
}

// ========== ASP/ASPX检测 ==========

QList<WebShellThreat> WebShellDetector::detectASPShell(const QString& filePath, const QString& content) {
    QList<WebShellThreat> threats;

    QRegularExpression re(R"(\b(?:eval|execute|execute\s*\(\s*Request))");
    QRegularExpressionMatchIterator it = re.globalMatch(content);

    while (it.hasNext()) {
        QRegularExpressionMatch match = it.next();
        WebShellThreat threat;
        threat.filePath = filePath;
        threat.fileName = QFileInfo(filePath).fileName();
        threat.threatType = "eval";
        threat.description = "ASP动态代码执行";
        threat.severity = "critical";
        threat.detectionTool = "signature";
        threat.matchedCode = match.captured();
        threat.lineNumber = findLineNumber(content, match.capturedStart());
        threat.recommendation = "立即删除此文件";
        threat.detectedTime = QDateTime::currentDateTime();
        threat.isConfirmed = true;
        threats.append(threat);
    }

    return threats;
}

QList<WebShellThreat> WebShellDetector::detectASPExecute(const QString& filePath, const QString& content) {
    QList<WebShellThreat> threats;

    QRegularExpression re(R"(\.Execute\s*\(\s*Request)");
    QRegularExpressionMatchIterator it = re.globalMatch(content);

    while (it.hasNext()) {
        QRegularExpressionMatch match = it.next();
        WebShellThreat threat;
        threat.filePath = filePath;
        threat.fileName = QFileInfo(filePath).fileName();
        threat.threatType = "execute";
        threat.description = "ASPX动态代码执行";
        threat.severity = "critical";
        threat.detectionTool = "signature";
        threat.matchedCode = match.captured();
        threat.lineNumber = findLineNumber(content, match.capturedStart());
        threat.recommendation = "立即删除此文件";
        threat.detectedTime = QDateTime::currentDateTime();
        threat.isConfirmed = true;
        threats.append(threat);
    }

    return threats;
}

// ========== JSP检测 ==========

QList<WebShellThreat> WebShellDetector::detectJSPShell(const QString& filePath, const QString& content) {
    QList<WebShellThreat> threats;

    QRegularExpression re(R"(\b(?:Runtime\.getRuntime|new\s+ProcessBuilder)\s*\()");
    QRegularExpressionMatchIterator it = re.globalMatch(content);

    while (it.hasNext()) {
        QRegularExpressionMatch match = it.next();
        WebShellThreat threat;
        threat.filePath = filePath;
        threat.fileName = QFileInfo(filePath).fileName();
        threat.threatType = "command";
        threat.description = "JSP命令执行";
        threat.severity = "critical";
        threat.detectionTool = "signature";
        threat.matchedCode = match.captured();
        threat.lineNumber = findLineNumber(content, match.capturedStart());
        threat.recommendation = "立即删除此文件";
        threat.detectedTime = QDateTime::currentDateTime();
        threat.isConfirmed = true;
        threats.append(threat);
    }

    return threats;
}

// ========== 通用检测 ==========

QList<WebShellThreat> WebShellDetector::detectCommonBackdoor(const QString& filePath, const QString& content) {
    QList<WebShellThreat> threats;

    // 已知WebShell名称
    QStringList names = {"godzilla", "哥斯拉", "behinder", "冰蝎", "caidao", "菜刀", "ChinaZ"};
    QString contentLower = content.toLower();

    for (const QString& name : names) {
        if (contentLower.contains(name)) {
            WebShellThreat threat;
            threat.filePath = filePath;
            threat.fileName = QFileInfo(filePath).fileName();
            threat.threatType = "known_shell";
            threat.description = QString("已知WebShell: %1").arg(name);
            threat.severity = "critical";
            threat.detectionTool = "signature";
            threat.signature = name;
            threat.matchedCode = name;
            threat.recommendation = "立即删除此文件";
            threat.detectedTime = QDateTime::currentDateTime();
            threat.isConfirmed = true;
            threats.append(threat);
        }
    }

    return threats;
}

QList<WebShellThreat> WebShellDetector::detectObfuscatedCode(const QString& filePath, const QString& content) {
    QList<WebShellThreat> threats;

    // 检测混淆代码
    if (content.length() > 5000 && content.count(';') > 100) {
        // 检测高度混淆的代码
        QRegularExpression re(R"((?:chr|ord|abs|hex|oct)\s*\()");
        QRegularExpressionMatchIterator it = re.globalMatch(content);

        if (it.hasNext()) {
            WebShellThreat threat;
            threat.filePath = filePath;
            threat.fileName = QFileInfo(filePath).fileName();
            threat.threatType = "obfuscated";
            threat.description = "检测到混淆代码";
            threat.severity = "medium";
            threat.detectionTool = "behavior";
            threat.matchedCode = "混淆代码模式";
            threat.recommendation = "检查代码内容，确认是否为恶意";
            threat.detectedTime = QDateTime::currentDateTime();
            threats.append(threat);
        }
    }

    return threats;
}

QList<WebShellThreat> WebShellDetector::detectEncodedContent(const QString& filePath, const QString& content) {
    QList<WebShellThreat> threats;

    // 检测Base64编码内容
    QRegularExpression re(R"((?:eval|echo|print|system|exec)\s*\(\s*@?(?:base64_decode|gzinflate|str_rot13)\s*\())");
    QRegularExpressionMatchIterator it = re.globalMatch(content);

    while (it.hasNext()) {
        QRegularExpressionMatch match = it.next();
        WebShellThreat threat;
        threat.filePath = filePath;
        threat.fileName = QFileInfo(filePath).fileName();
        threat.threatType = "encoded";
        threat.description = "检测到编码后门";
        threat.severity = "high";
        threat.detectionTool = "signature";
        threat.matchedCode = match.captured();
        threat.lineNumber = findLineNumber(content, match.capturedStart());
        threat.recommendation = "解码分析，确认是否为恶意";
        threat.detectedTime = QDateTime::currentDateTime();
        threats.append(threat);
    }

    return threats;
}
