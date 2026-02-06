#include "ForensicsManager.h"
#include "DatabaseManager.h"
#include <QCryptographicHash>
#include <QFileInfo>
#include <QFileDialog>
#include <QMessageBox>
#include <QDateTime>
#include <QDebug>

ForensicsManager::ForensicsManager(QObject *parent)
    : QObject(parent)
{
}

ForensicsManager::~ForensicsManager()
{
}

QList<ForensicsItem> ForensicsManager::getAllItems()
{
    return m_items;
}

QList<ForensicsItem> ForensicsManager::getItemsByType(const QString& type)
{
    QList<ForensicsItem> result;
    for (const auto& item : m_items) {
        if (item.type == type) {
            result.append(item);
        }
    }
    return result;
}

ForensicsItem ForensicsManager::getItem(int itemId)
{
    for (const auto& item : m_items) {
        if (item.id == itemId) {
            return item;
        }
    }
    return ForensicsItem();
}

bool ForensicsManager::addItem(const ForensicsItem& item)
{
    ForensicsItem newItem = item;
    newItem.id = m_items.size() + 1;
    newItem.collectedTime = QDateTime::currentDateTime();
    m_items.append(newItem);

    emit itemCollected(newItem);
    return saveItemToDatabase(newItem);
}

bool ForensicsManager::updateItem(const ForensicsItem& item)
{
    for (int i = 0; i < m_items.size(); ++i) {
        if (m_items[i].id == item.id) {
            m_items[i] = item;
            return saveItemToDatabase(item);
        }
    }
    return false;
}

bool ForensicsManager::deleteItem(int itemId)
{
    for (int i = 0; i < m_items.size(); ++i) {
        if (m_items[i].id == itemId) {
            m_items.removeAt(i);
            return true;
        }
    }
    return false;
}

bool ForensicsManager::exportItem(int itemId, const QString& destPath)
{
    ForensicsItem item = getItem(itemId);
    if (item.id == 0) {
        emit errorOccurred("Item not found");
        return false;
    }

    QFile sourceFile(item.destPath);
    if (!sourceFile.exists()) {
        emit errorOccurred("Source file not found");
        return false;
    }

    return sourceFile.copy(destPath + "/" + QFileInfo(sourceFile).fileName());
}

bool ForensicsManager::acquireMemory(const MemoryAcquisition& acquisition)
{
    MemoryAcquisition job = acquisition;
    job.progress = 0;

    // 模拟内存获取过程
    emit acquisitionProgress("memory", 10);

    // 检查目标进程/系统
    if (job.target.isEmpty()) {
        emit acquisitionFailed("memory", "Target not specified");
        return false;
    }

    emit acquisitionProgress("memory", 30);

    // 准备输出目录
    if (!createDirectoryIfNotExists(job.outputPath)) {
        emit acquisitionFailed("memory", "Failed to create output directory");
        return false;
    }

    emit acquisitionProgress("memory", 50);

    // 复制内存页面文件
    if (job.pagefileIncluded) {
        QString pagefilePath = "C:\\pagefile.sys";
        QFileInfo pagefile(pagefilePath);
        if (pagefile.exists()) {
            emit acquisitionProgress("memory", 70);
            // 实际实现中会复制页面文件
        }
    }

    emit acquisitionProgress("memory", 90);

    // 保存内存镜像信息
    ForensicsItem item;
    item.id = m_items.size() + 1;
    item.type = "memory";
    item.name = "Memory Dump - " + job.target;
    item.description = "Memory acquisition from " + job.target;
    item.sourcePath = job.target;
    item.destPath = job.outputPath;
    item.status = "completed";
    item.acquisitionMethod = "live";
    item.format = job.format;
    item.collectedTime = QDateTime::currentDateTime();
    item.collectedBy = "ForensicsManager";

    m_items.append(item);
    emit acquisitionProgress("memory", 100);
    emit acquisitionCompleted("memory", job.outputPath);
    emit itemCollected(item);

    return true;
}

bool ForensicsManager::acquireProcessMemory(int processId, const QString& outputPath)
{
    if (processId <= 0) {
        emit errorOccurred("Invalid process ID");
        return false;
    }

    if (!createDirectoryIfNotExists(outputPath)) {
        emit errorOccurred("Failed to create output directory");
        return false;
    }

    // 使用 Windows API 获取进程内存
    // 实际实现需要使用 OpenProcess, ReadProcessMemory 等 API
    QString dumpFile = outputPath + QString("/process_%1.mem").arg(processId);

    // 模拟进程内存获取
    ProcessDump dump;
    dump.processId = processId;
    dump.dumpPath = dumpFile;
    dump.fullDump = false;
    dump.status = "completed";
    dump.dumpedTime = QDateTime::currentDateTime();
    m_processDumps.append(dump);

    ForensicsItem item;
    item.id = m_items.size() + 1;
    item.type = "process";
    item.name = QString("Process Memory - PID %1").arg(processId);
    item.description = "Process memory dump";
    item.sourcePath = QString("PID:%1").arg(processId);
    item.destPath = dumpFile;
    item.status = "completed";
    item.format = "mem";
    m_items.append(item);

    emit itemCollected(item);
    return true;
}

bool ForensicsManager::acquireFullMemory(const QString& outputPath)
{
    if (!createDirectoryIfNotExists(outputPath)) {
        return false;
    }

    MemoryAcquisition acquisition;
    acquisition.target = "System";
    acquisition.outputPath = outputPath;
    acquisition.format = "raw";
    acquisition.compress = true;
    acquisition.pagefileIncluded = true;
    acquisition.srlazyIncluded = true;

    return acquireMemory(acquisition);
}

bool ForensicsManager::suspendAndDumpProcess(int processId, const QString& outputPath)
{
    // 暂停进程并获取内存
    bool suspendSuccess = false;
    bool dumpSuccess = acquireProcessMemory(processId, outputPath);

    // 恢复进程
    if (suspendSuccess) {
        // ResumeProcess(hProcess);
    }

    return dumpSuccess;
}

bool ForensicsManager::exportRegistryHive(const QString& hivePath, const QString& savePath)
{
    if (!createDirectoryIfNotExists(savePath)) {
        return false;
    }

    QString fileName = hivePath.replace("\\", "_").replace(":", "") + ".reg";
    QString saveFile = savePath + "/" + fileName;

    // 使用 reg save 命令导出注册表配置单元
    QProcess process;
    QString command = "reg";
    QStringList args = {"save", hivePath, saveFile};

    process.start(command, args);
    process.waitForFinished(30000);

    bool success = process.exitCode() == 0;

    if (success) {
        RegistryHive hive;
        hive.name = QFileInfo(hivePath).fileName();
        hive.hivePath = hivePath;
        hive.savePath = saveFile;
        hive.status = "exported";
        hive.exportedTime = QDateTime::currentDateTime();

        ForensicsItem item;
        item.id = m_items.size() + 1;
        item.type = "registry";
        item.name = "Registry Hive - " + hivePath;
        item.description = "Exported registry hive";
        item.sourcePath = hivePath;
        item.destPath = saveFile;
        item.status = "completed";
        item.format = "reg";
        m_items.append(item);

        emit itemCollected(item);
    }

    return success;
}

bool ForensicsManager::exportRegistryKey(const QString& keyPath, const QString& savePath)
{
    // 导出单个注册表键
    return exportRegistryHive(keyPath, savePath);
}

QList<RegistryHive> ForensicsManager::getLoadedHives()
{
    QList<RegistryHive> hives;

    // 常见注册表配置单元
    QStringList hivePaths = {
        "HKEY_LOCAL_MACHINE\\SYSTEM",
        "HKEY_LOCAL_MACHINE\\SOFTWARE",
        "HKEY_LOCAL_MACHINE\\SAM",
        "HKEY_LOCAL_MACHINE\\SECURITY",
        "HKEY_CURRENT_USER",
        "HKEY_USERS\\.DEFAULT"
    };

    for (const QString& path : hivePaths) {
        RegistryHive hive;
        hive.name = QFileInfo(path).fileName();
        hive.hivePath = path;
        hive.isLoaded = true;
        hive.status = "loaded";
        hives.append(hive);
    }

    return hives;
}

bool ForensicsManager::parseRegistryHive(const QString& hivePath, QJsonObject& result)
{
    Q_UNUSED(hivePath)
    // 解析注册表配置单元并返回结构化数据
    // 实际实现需要解析注册表二进制格式
    result["parsed"] = true;
    result["keys"] = 0;
    result["values"] = 0;
    return true;
}

bool ForensicsManager::dumpProcess(int processId, const QString& outputPath, bool fullDump)
{
    return acquireProcessMemory(processId, outputPath);
}

bool ForensicsManager::dumpProcessTree(int processId, const QString& outputPath)
{
    Q_UNUSED(processId)
    Q_UNUSED(outputPath)
    // 获取进程树并转储所有子进程
    // 实际实现需要遍历进程树
    return true;
}

QList<ProcessDump> ForensicsManager::getProcessDumps()
{
    return m_processDumps;
}

bool ForensicsManager::analyzeProcessDump(const QString& dumpPath)
{
    Q_UNUSED(dumpPath)
    // 使用 Volatility 分析内存转储
    return executeVolatility({"-f", dumpPath, "pslist"}, m_items.last().metadata["output"].toString());
}

bool ForensicsManager::captureNetworkTraffic(const QString& outputPath, int duration)
{
    if (!createDirectoryIfNotExists(outputPath)) {
        return false;
    }

    QString captureFile = outputPath + "/capture_" + getTimestamp() + ".pcap";

    // 使用 netsh 或 tcpdump 捕获网络流量
    QProcess process;
    QString command = "netsh";
    QStringList args = {
        "trace",
        "start",
        "scenario=netconnection",
        "capture=yes",
        QString("traceFile=%1").arg(captureFile),
        "maxsize=512",
        "fileMode=circular"
    };

    process.start(command, args);
    process.waitForStarted();

    // 等待指定时间
    QThread::sleep(duration);

    // 停止捕获
    process.start("netsh", {"trace", "stop"});
    process.waitForFinished();

    ForensicsItem item;
    item.id = m_items.size() + 1;
    item.type = "network";
    item.name = "Network Capture";
    item.description = QString("Network traffic capture (%1 seconds)").arg(duration);
    item.sourcePath = "Network Interface";
    item.destPath = captureFile;
    item.status = "completed";
    item.format = "pcap";
    item.size = QFileInfo(captureFile).size();
    m_items.append(item);

    emit itemCollected(item);
    return true;
}

bool ForensicsManager::exportNetstat(const QString& outputPath)
{
    if (!createDirectoryIfNotExists(outputPath)) {
        return false;
    }

    QString netstatFile = outputPath + "/netstat_" + getTimestamp() + ".txt";

    QProcess process;
    process.start("netstat", {"-ano"});
    process.waitForFinished();

    QFile file(netstatFile);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(process.readAllStandardOutput());
        file.close();
    }

    ForensicsItem item;
    item.id = m_items.size() + 1;
    item.type = "network";
    item.name = "Netstat Export";
    item.description = "Network connection statistics";
    item.sourcePath = "netstat -ano";
    item.destPath = netstatFile;
    item.status = "completed";
    item.format = "txt";
    m_items.append(item);

    emit itemCollected(item);
    return true;
}

bool ForensicsManager::exportPacketCapture(const QString& interface, const QString& outputPath)
{
    Q_UNUSED(interface)
    Q_UNUSED(outputPath)
    // 使用 Wireshark tshark 导出数据包
    return true;
}

bool ForensicsManager::collectFile(const QString& filePath, const QString& destPath)
{
    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists()) {
        emit errorOccurred("File not found: " + filePath);
        return false;
    }

    if (!createDirectoryIfNotExists(destPath)) {
        return false;
    }

    QString destFile = destPath + "/" + fileInfo.fileName();
    QFile sourceFile(filePath);

    if (!sourceFile.copy(destFile)) {
        emit errorOccurred("Failed to copy file");
        return false;
    }

    // 计算文件哈希
    QString md5, sha1, sha256;
    calculateFileHash(destFile, md5, sha1, sha256);

    ForensicsItem item;
    item.id = m_items.size() + 1;
    item.type = "file";
    item.name = fileInfo.fileName();
    item.description = "Collected file";
    item.sourcePath = filePath;
    item.destPath = destFile;
    item.status = "completed";
    item.format = fileInfo.suffix();
    item.size = fileInfo.size();
    item.hash = sha256;
    item.collectedTime = QDateTime::currentDateTime();
    item.metadata["md5"] = md5;
    item.metadata["sha1"] = sha1;
    m_items.append(item);

    emit itemCollected(item);
    return true;
}

bool ForensicsManager::collectDirectory(const QString& dirPath, const QString& destPath,
                                        const QStringList& filters)
{
    QDir sourceDir(dirPath);
    if (!sourceDir.exists()) {
        emit errorOccurred("Directory not found");
        return false;
    }

    if (!createDirectoryIfNotExists(destPath)) {
        return false;
    }

    QStringList files;
    if (filters.isEmpty()) {
        files = sourceDir.entryList(QDir::Files | QDir::NoDotAndDotDot);
    } else {
        files = sourceDir.entryList(filters, QDir::Files | QDir::NoDotAndDotDot);
    }

    for (const QString& file : files) {
        collectFile(dirPath + "/" + file, destPath);
    }

    return !files.isEmpty();
}

bool ForensicsManager::calculateFileHash(const QString& filePath, QString& md5, QString& sha1, QString& sha256)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return false;
    }

    QCryptographicHash md5Hash(QCryptographicHash::Md5);
    QCryptographicHash sha1Hash(QCryptographicHash::Sha1);
    QCryptographicHash sha256Hash(QCryptographicHash::Sha256);

    const qint64 bufferSize = 8192;
    char buffer[bufferSize];

    qint64 bytesRead;
    while ((bytesRead = file.read(buffer, bufferSize)) > 0) {
        md5Hash.addData(buffer, bytesRead);
        sha1Hash.addData(buffer, bytesRead);
        sha256Hash.addData(buffer, bytesRead);
    }

    md5 = md5Hash.result().toHex();
    sha1 = sha1Hash.result().toHex();
    sha256 = sha256Hash.result().toHex();

    return true;
}

QList<TimelineEntry> ForensicsManager::collectTimeline(const QDateTime& startTime,
                                                       const QDateTime& endTime)
{
    QList<TimelineEntry> timeline;

    // 收集各种Artifacts时间线
    // Windows事件日志
    collectEventLogTimeline(startTime, endTime, timeline);

    // 注册表时间线
    collectRegistryTimeline(startTime, endTime, timeline);

    // 文件系统时间线
    collectFileSystemTimeline(startTime, endTime, timeline);

    // Web日志时间线
    collectWebLogTimeline(startTime, endTime, timeline);

    return timeline;
}

bool ForensicsManager::generateTimelineReport(const QList<TimelineEntry>& timeline,
                                              const QString& outputPath)
{
    QJsonObject report;
    report["generated"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    report["totalEntries"] = timeline.size();

    QJsonArray entriesArray;
    for (const auto& entry : timeline) {
        QJsonObject entryObj;
        entryObj["timestamp"] = entry.timestamp.toString(Qt::ISODate);
        entryObj["source"] = entry.source;
        entryObj["eventType"] = entry.eventType;
        entryObj["description"] = entry.description;
        entryObj["riskLevel"] = entry.riskLevel;
        entryObj["score"] = entry.score;
        entriesArray.append(entryObj);
    }

    report["entries"] = entriesArray;

    QFile file(outputPath);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(QJsonDocument(report).toJson(QJsonDocument::Indented));
        file.close();
        return true;
    }

    return false;
}

QList<TimelineEntry> ForensicsManager::analyzeTimeline(const QList<TimelineEntry>& timeline)
{
    QList<TimelineEntry> analyzed;

    for (const auto& entry : timeline) {
        TimelineEntry analyzedEntry = entry;

        // 计算风险分数
        int score = 0;
        if (entry.riskLevel == "critical") score = 100;
        else if (entry.riskLevel == "high") score = 75;
        else if (entry.riskLevel == "medium") score = 50;
        else if (entry.riskLevel == "low") score = 25;

        // 根据事件类型调整分数
        if (entry.eventType.contains("password", Qt::CaseInsensitive)) score += 20;
        if (entry.eventType.contains("login", Qt::CaseInsensitive)) score += 10;
        if (entry.eventType.contains("process", Qt::CaseInsensitive)) score += 5;

        analyzedEntry.score = qMin(100, score);
        analyzed.append(analyzedEntry);
    }

    emit timelineGenerated(analyzed.size());
    return analyzed;
}

QList<ArtifactInfo> ForensicsManager::listAvailableArtifacts()
{
    QList<ArtifactInfo> artifacts;

    // Windows系统Artifacts
    QStringList artifactPaths = {
        // 注册表
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache",
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer",
        // 文件系统
        "$MFT",
        "$LogFile",
        "$Boot",
        "$UsnJrnl",
        // Web浏览器
        "%APPDATA%\\Roaming\\Microsoft\\Windows\\Cookies",
        "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\History",
        "%APPDATA%\\Mozilla\\Firefox\\Profiles",
        // 邮件
        "%APPDATA%\\Thunderbird",
        "%APPDATA%\\Microsoft\\Outlook",
        // 即时通讯
        "%APPDATA%\\Telegram Desktop\\tdata",
        "%APPDATA%\\Discord",
    };

    for (const QString& path : artifactPaths) {
        ArtifactInfo info;
        info.path = path;
        info.isAvailable = QDir(path).exists() || QFileInfo(path).exists();
        artifacts.append(info);
    }

    return artifacts;
}

bool ForensicsManager::collectArtifact(const QString& artifactName, const QString& destPath)
{
    Q_UNUSED(artifactName)
    Q_UNUSED(destPath)
    // 收集特定artifact
    return true;
}

bool ForensicsManager::collectAllCriticalArtifacts(const QString& destPath)
{
    if (!createDirectoryIfNotExists(destPath)) {
        return false;
    }

    // 收集关键系统信息
    exportNetstat(destPath);
    exportRegistryHive("HKEY_LOCAL_MACHINE\\SYSTEM", destPath);
    exportRegistryHive("HKEY_LOCAL_MACHINE\\SOFTWARE", destPath);

    // 收集浏览器历史
    QString browserPath = destPath + "/browsers";
    createDirectoryIfNotExists(browserPath);

    return true;
}

bool ForensicsManager::executeVolatility(const QStringList& args, QString& output)
{
    QProcess process;
    process.start("volatility3", args);
    process.waitForFinished(60000);

    output = process.readAllStandardOutput();
    return process.exitCode() == 0;
}

bool ForensicsManager::executeAutopsy(const QString& casePath, const QString& imagePath)
{
    Q_UNUSED(casePath)
    Q_UNUSED(imagePath)
    // 调用 Autopsy 进行法证分析
    return true;
}

bool ForensicsManager::executeRegistryParser(const QString& hivePath, const QString& outputPath)
{
    Q_UNUSED(hivePath)
    Q_UNUSED(outputPath)
    // 解析注册表配置单元
    return true;
}

bool ForensicsManager::createCase(const QString& caseName, const QString& casePath)
{
    if (!createDirectoryIfNotExists(casePath)) {
        return false;
    }

    m_currentCase["name"] = caseName;
    m_currentCase["path"] = casePath;
    m_currentCase["created"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    m_currentCase["status"] = "open";

    // 创建案件目录结构
    createDirectoryIfNotExists(casePath + "/memory");
    createDirectoryIfNotExists(casePath + "/registry");
    createDirectoryIfNotExists(casePath + "/processes");
    createDirectoryIfNotExists(casePath + "/files");
    createDirectoryIfNotExists(casePath + "/network");
    createDirectoryIfNotExists(casePath + "/timeline");

    return true;
}

bool ForensicsManager::closeCase()
{
    if (m_currentCase.isEmpty()) {
        return false;
    }

    m_currentCase["closed"] = QDateTime::currentDateTime().toString(Qt::ISODate);
    m_currentCase["status"] = "closed";

    return true;
}

QJsonObject ForensicsManager::getCurrentCase()
{
    return m_currentCase;
}

bool ForensicsManager::initializeCase(const QString& casePath)
{
    return createDirectoryIfNotExists(casePath);
}

bool ForensicsManager::saveItemToDatabase(const ForensicsItem& item)
{
    Q_UNUSED(item)
    // 保存到SQLite数据库
    return true;
}

bool ForensicsManager::loadItemsFromDatabase()
{
    // 从数据库加载取证项目
    return true;
}

QString ForensicsManager::getTimestamp()
{
    return QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss");
}

QString ForensicsManager::calculateHash(const QString& filePath, const QString& algorithm)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return QString();
    }

    QCryptographicHash::Algorithm algo;
    if (algorithm == "md5") algo = QCryptographicHash::Md5;
    else if (algorithm == "sha1") algo = QCryptographicHash::Sha1;
    else algo = QCryptographicHash::Sha256;

    QCryptographicHash hash(algo);
    hash.addData(&file);

    return hash.result().toHex();
}

bool ForensicsManager::createDirectoryIfNotExists(const QString& path)
{
    QDir dir(path);
    if (!dir.exists()) {
        return dir.mkpath(".");
    }
    return true;
}

void ForensicsManager::collectEventLogTimeline(const QDateTime& startTime,
                                               const QDateTime& endTime,
                                               QList<TimelineEntry>& timeline)
{
    Q_UNUSED(startTime)
    Q_UNUSED(endTime)
    // 从Windows事件日志收集时间线
    // 实际实现需要解析.evtx文件
}

void ForensicsManager::collectRegistryTimeline(const QDateTime& startTime,
                                               const QDateTime& endTime,
                                               QList<TimelineEntry>& timeline)
{
    Q_UNUSED(startTime)
    Q_UNUSED(endTime)
    // 从注册表收集时间线
}

void ForensicsManager::collectFileSystemTimeline(const QDateTime& startTime,
                                                 const QDateTime& endTime,
                                                 QList<TimelineEntry>& timeline)
{
    Q_UNUSED(startTime)
    Q_UNUSED(endTime)
    // 收集文件系统时间线（$MFT, $UsnJrnl等）
}

void ForensicsManager::collectWebLogTimeline(const QDateTime& startTime,
                                             const QDateTime& endTime,
                                             QList<TimelineEntry>& timeline)
{
    Q_UNUSED(startTime)
    Q_UNUSED(endTime)
    // 收集Web服务器日志时间线
}
