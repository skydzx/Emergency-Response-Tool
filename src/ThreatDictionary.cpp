/**
 * @file ThreatDictionary.cpp
 * @brief Threat Dictionary and Feature Matching Implementation
 * @version 1.0.0
 */

#include "ThreatDictionary.h"
#include <QFile>
#include <QTextStream>
#include <QDebug>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDir>
#include <QCryptographicHash>

ThreatDictionary::ThreatDictionary(QObject *parent)
    : QObject(parent)
{
    // 初始化内置字典
    initializeProcessDictionary();
    initializeFileDictionary();
    initializeWebShellDictionary();
    initializeRansomwareDictionary();
    initializeNetworkDictionary();
    initializeBehaviorDictionary();

    // 加载勒索病毒特征
    m_ransomwareSignatures = loadRansomwareSignatures();
}

ThreatDictionary::~ThreatDictionary() {
}

// ========== 字典加载 ==========

bool ThreatDictionary::loadFromFile(const QString& filePath) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        emit errorOccurred(QString("无法打开字典文件: %1").arg(filePath));
        return false;
    }

    QByteArray data = file.readAll();
    file.close();

    QJsonParseError error;
    QJsonObject json = QJsonDocument::fromJson(data, &error).object();

    if (error.error != QJsonParseError::NoError) {
        emit errorOccurred(QString("JSON解析错误: %1").arg(error.errorString()));
        return false;
    }

    return loadFromJson(json);
}

bool ThreatDictionary::loadFromJson(const QJsonObject& json) {
    m_entries.clear();

    QJsonArray entries = json["entries"].toArray();
    for (const QJsonValue& value : entries) {
        ThreatEntry entry = parseEntry(value.toObject());
        if (entry.isEnabled) {
            m_entries.append(entry);
        }
    }

    emit dictionaryLoaded(m_entries.size());
    return true;
}

bool ThreatDictionary::loadBuiltinDictionaries() {
    // 所有内置字典已在构造函数中加载
    return true;
}

bool ThreatDictionary::saveToFile(const QString& filePath) {
    QJsonObject json;
    json["version"] = "1.0";
    json["updated"] = QDateTime::currentDateTime().toString(Qt::ISODate);

    QJsonArray entries;
    for (const ThreatEntry& entry : m_entries) {
        entries.append(entryToJson(entry));
    }
    json["entries"] = entries;

    QJsonDocument doc(json);

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly)) {
        emit errorOccurred(QString("无法写入字典文件: %1").arg(filePath));
        return false;
    }

    file.write(doc.toJson(QJsonDocument::Indented));
    file.close();

    return true;
}

// ========== 字典管理 ==========

bool ThreatDictionary::addEntry(const ThreatEntry& entry) {
    ThreatEntry newEntry = entry;
    newEntry.id = m_entries.size() + 1;
    newEntry.createdTime = QDateTime::currentDateTime();
    newEntry.updatedTime = QDateTime::currentDateTime();
    newEntry.matchCount = 0;
    m_entries.append(newEntry);
    emit entryAdded(newEntry);
    return true;
}

bool ThreatDictionary::updateEntry(const ThreatEntry& entry) {
    for (int i = 0; i < m_entries.size(); i++) {
        if (m_entries[i].id == entry.id) {
            ThreatEntry updated = entry;
            updated.updatedTime = QDateTime::currentDateTime();
            m_entries[i] = updated;
            emit entryUpdated(updated);
            return true;
        }
    }
    return false;
}

bool ThreatDictionary::deleteEntry(int entryId) {
    for (int i = 0; i < m_entries.size(); i++) {
        if (m_entries[i].id == entryId) {
            m_entries.removeAt(i);
            emit entryDeleted(entryId);
            return true;
        }
    }
    return false;
}

bool ThreatDictionary::enableEntry(int entryId) {
    for (ThreatEntry& entry : m_entries) {
        if (entry.id == entryId) {
            entry.isEnabled = true;
            entry.updatedTime = QDateTime::currentDateTime();
            return true;
        }
    }
    return false;
}

bool ThreatDictionary::disableEntry(int entryId) {
    for (ThreatEntry& entry : m_entries) {
        if (entry.id == entryId) {
            entry.isEnabled = false;
            entry.updatedTime = QDateTime::currentDateTime();
            return true;
        }
    }
    return false;
}

bool ThreatDictionary::enableCategory(const QString& category) {
    int count = 0;
    for (ThreatEntry& entry : m_entries) {
        if (entry.category == category) {
            entry.isEnabled = true;
            entry.updatedTime = QDateTime::currentDateTime();
            count++;
        }
    }
    return count > 0;
}

bool ThreatDictionary::disableCategory(const QString& category) {
    int count = 0;
    for (ThreatEntry& entry : m_entries) {
        if (entry.category == category) {
            entry.isEnabled = false;
            entry.updatedTime = QDateTime::currentDateTime();
            count++;
        }
    }
    return count > 0;
}

// ========== 字典查询 ==========

ThreatEntry ThreatDictionary::getEntry(int entryId) {
    for (const ThreatEntry& entry : m_entries) {
        if (entry.id == entryId) {
            return entry;
        }
    }
    return ThreatEntry();
}

QList<ThreatEntry> ThreatDictionary::getAllEntries() {
    return m_entries;
}

QList<ThreatEntry> ThreatDictionary::getEntriesByCategory(const QString& category) {
    QList<ThreatEntry> result;
    for (const ThreatEntry& entry : m_entries) {
        if (entry.category == category) {
            result.append(entry);
        }
    }
    return result;
}

QList<ThreatEntry> ThreatDictionary::getEnabledEntries() {
    QList<ThreatEntry> result;
    for (const ThreatEntry& entry : m_entries) {
        if (entry.isEnabled) {
            result.append(entry);
        }
    }
    return result;
}

QList<DictionaryCategory> ThreatDictionary::getCategories() {
    QMap<QString, DictionaryCategory> categories;

    for (const ThreatEntry& entry : m_entries) {
        if (!categories.contains(entry.category)) {
            DictionaryCategory cat;
            cat.name = entry.category;
            cat.entryCount = 0;
            cat.enabledCount = 0;
            categories[entry.category] = cat;
        }
        categories[entry.category].entryCount++;
        if (entry.isEnabled) {
            categories[entry.category].enabledCount++;
        }
    }

    return categories.values();
}

// ========== 特征比对 ==========

MatchingResult ThreatDictionary::matchProcess(const QString& processName, const QString& processPath) {
    MatchingResult result;

    for (const ThreatEntry& entry : m_entries) {
        if (!entry.isEnabled || entry.category != "process") {
            continue;
        }

        // 检查名称匹配
        if (matchWildcard(processName, entry.value) ||
            matchExact(processName.toLower(), entry.value.toLower())) {
            result = createMatchResult(processName, entry);
            emit matchFound(result);
            return result;
        }

        // 检查路径匹配
        if (!processPath.isEmpty()) {
            if (matchWildcard(processPath, entry.value) ||
                matchExact(processPath.toLower(), entry.value.toLower())) {
                result = createMatchResult(processPath, entry);
                emit matchFound(result);
                return result;
            }
        }
    }

    return result;
}

MatchingResult ThreatDictionary::matchFileHash(const QString& hash, const QString& filePath) {
    MatchingResult result;

    for (const ThreatEntry& entry : m_entries) {
        if (!entry.isEnabled || entry.type != "hash") {
            continue;
        }

        if (matchHash(hash.toLower(), entry.value.toLower())) {
            if (!filePath.isEmpty()) {
                result.originalValue = filePath;
            } else {
                result.originalValue = hash;
            }
            result = createMatchResult(hash, entry);
            emit matchFound(result);
            return result;
        }
    }

    return result;
}

MatchingResult ThreatDictionary::matchFileName(const QString& fileName) {
    MatchingResult result;

    for (const ThreatEntry& entry : m_entries) {
        if (!entry.isEnabled || (entry.category != "file" && entry.category != "webshell")) {
            continue;
        }

        if (matchWildcard(fileName, entry.value) ||
            matchExact(fileName.toLower(), entry.value.toLower())) {
            result = createMatchResult(fileName, entry);
            emit matchFound(result);
            return result;
        }
    }

    return result;
}

MatchingResult ThreatDictionary::matchFilePath(const QString& filePath) {
    MatchingResult result;
    QString fileName = QFileInfo(filePath).fileName();

    // 先匹配文件名
    result = matchFileName(fileName);
    if (!result.matchedValue.isEmpty()) {
        result.originalValue = filePath;
        return result;
    }

    // 再匹配路径
    for (const ThreatEntry& entry : m_entries) {
        if (!entry.isEnabled || entry.category != "file") {
            continue;
        }

        if (matchWildcard(filePath, entry.value) ||
            filePath.toLower().contains(entry.value.toLower())) {
            result = createMatchResult(filePath, entry);
            emit matchFound(result);
            return result;
        }
    }

    return result;
}

MatchingResult ThreatDictionary::matchSignature(const QString& content) {
    MatchingResult result;

    for (const ThreatEntry& entry : m_entries) {
        if (!entry.isEnabled || entry.type != "signature") {
            continue;
        }

        if (matchRegex(content, entry.value)) {
            result = createMatchResult(content.left(100), entry);
            emit matchFound(result);
            return result;
        }
    }

    return result;
}

// ========== 批量比对 ==========

QList<MatchingResult> ThreatDictionary::matchProcesses(const QList<QString>& processNames) {
    QList<MatchingResult> results;
    for (const QString& name : processNames) {
        MatchingResult result = matchProcess(name);
        if (!result.matchedValue.isEmpty()) {
            results.append(result);
        }
    }
    return results;
}

QList<MatchingResult> ThreatDictionary::matchFileHashes(const QList<QString>& hashes) {
    QList<MatchingResult> results;
    for (const QString& hash : hashes) {
        MatchingResult result = matchFileHash(hash);
        if (!result.matchedValue.isEmpty()) {
            results.append(result);
        }
    }
    return results;
}

QList<MatchingResult> ThreatDictionary::matchFilePaths(const QList<QString>& filePaths) {
    QList<MatchingResult> results;
    for (const QString& path : filePaths) {
        MatchingResult result = matchFilePath(path);
        if (!result.matchedValue.isEmpty()) {
            results.append(result);
        }
    }
    return results;
}

QList<MatchingResult> ThreatDictionary::matchSignatures(const QList<QString>& contents) {
    QList<MatchingResult> results;
    for (const QString& content : contents) {
        MatchingResult result = matchSignature(content);
        if (!result.matchedValue.isEmpty()) {
            results.append(result);
        }
    }
    return results;
}

// ========== 勒索病毒检测 ==========

QList<RansomwareSignature> ThreatDictionary::loadRansomwareSignatures() {
    QList<RansomwareSignature> signatures;

    // WannaCry
    signatures.append({"WannaCry", ".wnry", "WannaCry", "critical",
                       "WannaCry勒索病毒", R"(README\.txt|WannaDecryptor)",
                       {"svchost.exe运行加密程序", "tasksche.exe"}, false});

    // Petya
    signatures.append({"Petya", ".petya", "Petya", "critical",
                       "Petya勒索病毒", R"(README\.txt|README\.html)",
                       {"盘符挂起", "MBR覆盖"}, false});

    // NotPetya
    signatures.append({"NotPetya", ".pem", "NotPetya", "critical",
                       "NotPetya勒索病毒", R"(README\.txt)",
                       {"通过M.E.Doc更新传播"}, false});

    // Cerber
    signatures.append({"Cerber", ".cerber", "Cerber", "critical",
                       "Cerber勒索病毒", R"(README\.Cerber)",
                       {"语音合成", "桌面背景更改"}, false});

    // Locky
    signatures.append({"Locky", ".locky", "Locky", "critical",
                       "Locky勒索病毒", R"(_README\.txt|_LOCKY_RECOVER\.txt)",
                       {"邮件传播", "RSA-2048加密"}, false});

    // CryptoLocker
    signatures.append({"CryptoLocker", ".encrypted", "CryptoLocker", "critical",
                       "CryptoLocker勒索病毒", R"(DECRYPT\.html|DECRYPT\.txt)",
                       {"早期勒索病毒", "AES+RSA加密"}, false});

    // Ryuk
    signatures.append({"Ryuk", ".RUK", "Ryuk", "critical",
                       "Ryuk勒索病毒", R"(README\.txt",
                       {"定向攻击", "大额赎金"}, false});

    // Maze
    signatures.append({"Maze", ".maze", "Maze", "critical",
                       "Maze勒索病毒", R"(DECRYPT\.html|README\.txt)",
                       {"泄露数据", "双重勒索"}, false});

    // REvil/Sodinokibi
    signatures.append({"REvil", ".REvil", "REvil/Sodinokibi", "critical",
                       "REvil勒索病毒", R"(README\.txt|RECOVER\.txt)",
                       {"双重勒索", "Kaseya供应链攻击"}, false});

    // DarkSide
    signatures.append({"DarkSide", ".darkside", "DarkSide", "critical",
                       "DarkSide勒索病毒", R"(README\.txt|RESTORE\.txt)",
                       {"双重勒索", "油气管道攻击"}, false});

    return signatures;
}

QList<RansomwareSignature> ThreatDictionary::detectRansomware(const QString& fileExtension) {
    QList<RansomwareSignature> detected;
    for (const RansomwareSignature& sig : m_ransomwareSignatures) {
        if (fileExtension == sig.extension) {
            detected.append(sig);
        }
    }
    return detected;
}

MatchingResult ThreatDictionary::checkRansomwareIndicators(const QString& filePath) {
    MatchingResult result;
    QString extension = QFileInfo(filePath).suffix();

    QList<RansomwareSignature> detected = detectRansomware("." + extension);
    if (!detected.isEmpty()) {
        result.matchedValue = detected[0].name;
        result.category = "ransomware";
        result.severity = "critical";
        result.description = QString("检测到%1勒索病毒加密的文件").arg(detected[0].ransomwareFamily);
        result.recommendation = "1. 立即隔离感染主机 2. 不要支付赎金 3. 联系专业安全团队";
    }

    return result;
}

// ========== 恶意进程检测 ==========

QList<ThreatEntry> ThreatDictionary::loadProcessWhitelist() {
    QList<ThreatEntry> whitelist;

    // Windows系统进程
    whitelist.append({-1, "System", "process", "name", "System", "low",
                     "系统空闲进程", "", "Windows", {"system"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});

    whitelist.append({-1, "smss.exe", "process", "name", "smss.exe", "low",
                     "Windows会话管理器", "", "Windows", {"system"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});

    whitelist.append({-1, "csrss.exe", "process", "name", "csrss.exe", "low",
                     "客户端/服务器运行时进程", "", "Windows", {"system"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});

    whitelist.append({-1, "wininit.exe", "process", "name", "wininit.exe", "low",
                     "Windows启动初始化进程", "", "Windows", {"system"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});

    whitelist.append({-1, "services.exe", "process", "name", "services.exe", "low",
                     "服务控制管理器", "", "Windows", {"system"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});

    whitelist.append({-1, "lsass.exe", "process", "name", "lsass.exe", "low",
                     "本地安全机构", "", "Windows", {"system"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});

    whitelist.append({-1, "svchost.exe", "process", "name", "svchost.exe", "low",
                     "服务主机进程", "", "Windows", {"system"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});

    whitelist.append({-1, "explorer.exe", "process", "name", "explorer.exe", "low",
                     "Windows资源管理器", "", "Windows", {"system"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});

    return whitelist;
}

bool ThreatDictionary::isProcessTrusted(const QString& processName, const QString& processPath) {
    QList<ThreatEntry> whitelist = loadProcessWhitelist();

    for (const ThreatEntry& entry : whitelist) {
        if (matchExact(processName, entry.value)) {
            return true;
        }

        if (!processPath.isEmpty() && matchWildcard(processPath, entry.value)) {
            return true;
        }
    }

    return false;
}

// ========== 恶意域名/IP检测 ==========

bool ThreatDictionary::checkMaliciousDomain(const QString& domain) {
    Q_UNUSED(domain)
    // 实际实现需要查询恶意域名数据库
    return false;
}

bool ThreatDictionary::checkMaliciousIP(const QString& ipAddress) {
    Q_UNUSED(ipAddress)
    // 实际实现需要查询恶意IP数据库
    return false;
}

// ========== 统计 ==========

int ThreatDictionary::getTotalEntryCount() {
    return m_entries.size();
}

int ThreatDictionary::getEnabledEntryCount() {
    int count = 0;
    for (const ThreatEntry& entry : m_entries) {
        if (entry.isEnabled) {
            count++;
        }
    }
    return count;
}

int ThreatDictionary::getMatchCount(int entryId) {
    for (const ThreatEntry& entry : m_entries) {
        if (entry.id == entryId) {
            return entry.matchCount;
        }
    }
    return 0;
}

QList<ThreatEntry> ThreatDictionary::getTopMatchedEntries(int topN) {
    QList<ThreatEntry> sorted = m_entries;
    std::sort(sorted.begin(), sorted.end(),
              [](const ThreatEntry& a, const ThreatEntry& b) {
                  return a.matchCount > b.matchCount;
              });
    return sorted.mid(0, qMin(topN, sorted.size()));
}

// ========== 辅助方法 ==========

MatchingResult ThreatDictionary::createMatchResult(const QString& originalValue, const ThreatEntry& entry) {
    MatchingResult result;
    result.originalValue = originalValue;
    result.matchedValue = entry.value;
    result.category = entry.category;
    result.severity = entry.severity;
    result.description = entry.description;
    result.recommendation = entry.recommendation;
    result.matchedEntryName = entry.name;
    result.matchedEntryId = entry.id;
    result.matchedTime = QDateTime::currentDateTime();

    // 增加匹配计数
    for (ThreatEntry& e : m_entries) {
        if (e.id == entry.id) {
            e.matchCount++;
            e.lastMatchedTime = QDateTime::currentDateTime();
            break;
        }
    }

    return result;
}

bool ThreatDictionary::matchExact(const QString& value, const QString& pattern) {
    return value == pattern;
}

bool ThreatDictionary::matchWildcard(const QString& value, const QString& pattern) {
    // 将通配符转换为正则表达式
    QString regexPattern = QRegularExpression::wildcardToRegularExpression(pattern);
    QRegularExpression re(regexPattern);
    return re.match(value).hasMatch();
}

bool ThreatDictionary::matchRegex(const QString& value, const QString& pattern) {
    QRegularExpression re(pattern);
    return re.match(value).hasMatch();
}

bool ThreatDictionary::matchHash(const QString& value, const QString& pattern) {
    // 支持MD5、SHA1、SHA256
    if (pattern.length() == 32) {
        // MD5
        return value == pattern;
    } else if (pattern.length() == 40) {
        // SHA1
        return value == pattern;
    } else if (pattern.length() == 64) {
        // SHA256
        return value == pattern;
    }
    return value == pattern;
}

// ========== JSON解析 ==========

ThreatEntry ThreatDictionary::parseEntry(const QJsonObject& json) {
    ThreatEntry entry;
    entry.id = json["id"].toInt();
    entry.name = json["name"].toString();
    entry.category = json["category"].toString();
    entry.type = json["type"].toString();
    entry.value = json["value"].toString();
    entry.severity = json["severity"].toString();
    entry.description = json["description"].toString();
    entry.recommendation = json["recommendation"].toString();
    entry.source = json["source"].toString();

    QJsonArray tagsArray = json["tags"].toArray();
    for (const QJsonValue& tag : tagsArray) {
        entry.tags.append(tag.toString());
    }

    entry.isEnabled = json["enabled"].toBool(true);
    entry.matchCount = json["matchCount"].toInt(0);

    if (json.contains("created")) {
        entry.createdTime = QDateTime::fromString(json["created"].toString(), Qt::ISODate);
    }
    if (json.contains("updated")) {
        entry.updatedTime = QDateTime::fromString(json["updated"].toString(), Qt::ISODate);
    }

    return entry;
}

QJsonObject ThreatDictionary::entryToJson(const ThreatEntry& entry) {
    QJsonObject json;
    json["id"] = entry.id;
    json["name"] = entry.name;
    json["category"] = entry.category;
    json["type"] = entry.type;
    json["value"] = entry.value;
    json["severity"] = entry.severity;
    json["description"] = entry.description;
    json["recommendation"] = entry.recommendation;
    json["source"] = entry.source;

    QJsonArray tagsArray;
    for (const QString& tag : entry.tags) {
        tagsArray.append(tag);
    }
    json["tags"] = tagsArray;

    json["enabled"] = entry.isEnabled;
    json["matchCount"] = entry.matchCount;
    json["created"] = entry.createdTime.toString(Qt::ISODate);
    json["updated"] = entry.updatedTime.toString(Qt::ISODate);

    return json;
}

// ========== 初始化内置字典 ==========

void ThreatDictionary::initializeProcessDictionary() {
    // 恶意进程
    m_entries.append({1, "木马下载器", "process", "name", "downloader.exe", "high",
                     "木马下载器", "", "Builtin", {"trojan", "downloader"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});

    m_entries.append({2, "键盘记录器", "process", "name", "keylogger.exe", "high",
                     "键盘记录器", "", "Builtin", {"keylogger", "spyware"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});

    m_entries.append({3, "远程控制木马", "process", "name", "rat.exe", "critical",
                     "远程控制木马", "", "Builtin", {"trojan", "rat"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});

    m_entries.append({4, "密码窃取器", "process", "name", "passwordstealer.exe", "critical",
                     "密码窃取程序", "", "Builtin", {"stealer", "malware"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});

    m_entries.append({5, "加密货币矿工", "process", "name", "miner.exe", "medium",
                     "加密货币挖矿程序", "", "Builtin", {"miner", "crypto"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});
}

void ThreatDictionary::initializeFileDictionary() {
    // 恶意文件类型
    m_entries.append({100, "恶意脚本", "file", "extension", "*.scr", "high",
                     "屏幕保护程序文件", "检查来源，确认为可信文件", "Builtin", {"script"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});

    m_entries.append({101, "批处理文件", "file", "extension", "*.bat", "medium",
                     "批处理文件", "检查内容，确认无恶意命令", "Builtin", {"script"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});

    m_entries.append({102, "PowerShell脚本", "file", "extension", "*.ps1", "high",
                     "PowerShell脚本", "检查来源，确认为可信文件", "Builtin", {"script", "powershell"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});

    m_entries.append({103, "VBScript", "file", "extension", "*.vbs", "high",
                     "VBScript脚本", "检查来源，确认为可信文件", "Builtin", {"script", "vbs"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});
}

void ThreatDictionary::initializeWebShellDictionary() {
    // WebShell哈希
    m_entries.append({200, "中国菜刀", "webshell", "hash",
                     "d41d8cd98f00b204e9800998ecf8427e", "critical",
                     "中国菜刀WebShell", "立即删除并溯源", "Builtin", {"webshell", "caidao"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});

    m_entries.append({201, "Godzilla", "webshell", "hash",
                     "a1b2c3d4e5f6", "critical",
                     "Godzilla WebShell", "立即删除并溯源", "Builtin", {"webshell", "godzilla"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});

    m_entries.append({202, "Behinder", "webshell", "hash",
                     "f1e2d3c4b5a6", "critical",
                     "Behinder WebShell(冰蝎)", "立即删除并溯源", "Builtin", {"webshell", "behinder"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});
}

void ThreatDictionary::initializeRansomwareDictionary() {
    // 勒索病毒扩展名已在loadRansomwareSignatures中定义
}

void ThreatDictionary::initializeNetworkDictionary() {
    // 恶意网络行为
    m_entries.append({300, "可疑外连", "network", "behavior", "portscan", "high",
                     "端口扫描行为", "确认是否为安全扫描工具", "Builtin", {"network", "recon"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});

    m_entries.append({301, "数据外泄", "network", "behavior", "dataexfiltration", "critical",
                     "数据外泄行为", "立即调查并阻断", "Builtin", {"network", "exfil"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});

    m_entries.append({302, "C2通信", "network", "behavior", "c2communication", "critical",
                     "命令控制服务器通信", "立即隔离主机", "Builtin", {"network", "c2"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});
}

void ThreatDictionary::initializeBehaviorDictionary() {
    // 恶意行为模式
    m_entries.append({400, "权限提升", "behavior", "pattern", "privilegeescalation", "critical",
                     "权限提升尝试", "检查是否合法操作", "Builtin", {"privilege", "escalation"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});

    m_entries.append({401, "持久化", "behavior", "pattern", "persistence", "high",
                     "持久化操作", "检查是否为合法软件", "Builtin", {"persistence", "registry"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});

    m_entries.append({402, "防御规避", "behavior", "pattern", "defenseevasion", "high",
                     "防御规避行为", "可能为恶意软件特征", "Builtin", {"evasion", "antivirus"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});

    m_entries.append({403, "凭证访问", "behavior", "pattern", "credentialaccess", "critical",
                     "凭证访问尝试", "检查是否合法操作", "Builtin", {"credential", "mimikatz"}, true, 0,
                     QDateTime::currentDateTime(), QDateTime::currentDateTime()});
}
