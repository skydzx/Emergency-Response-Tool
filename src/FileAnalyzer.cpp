/**
 * @file FileAnalyzer.cpp
 * @brief File and Directory Analysis Implementation
 * @version 1.0.0
 */

#include "FileAnalyzer.h"
#include <QFile>
#include <QTextStream>
#include <QDebug>
#include <QCryptographicHash>
#include <QFileDialog>
#include <QDirIterator>
#include <Win32/Win32.hpp>

// 危险扩展名（可直接执行或包含恶意代码）
const QStringList FileAnalyzer::DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".pif", ".msi", ".dll", ".ocx", ".cpl",
    ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf",
    ".wsh", ".psh1", ".psh2", ".hta", ".chm", ".msh",
    ".xml", ".xsl", ".xslt", ".xps", ".reg", ".inf", ".ini"
};

// 可疑扩展名（可能被滥用）
const QStringList FileAnalyzer::SUSPICIOUS_EXTENSIONS = {
    ".tmp", ".temp", ".bak", ".old", ".backup", ".swp", ".swo",
    ".log", ".txt", ".dat", ".bin", ".raw", ".img", ".iso"
};

// 危险文件名模式
const QStringList FileAnalyzer::DANGEROUS_PATTERNS = {
    "password", "credential", "key", "token", "secret",
    "hack", "crack", "keygen", "patcher", "cheat",
    "malware", "virus", "trojan", "backdoor", "rootkit",
    "rat", "stealer", "logger", "keylogger", "injector"
};

FileAnalyzer::FileAnalyzer(QObject *parent)
    : QObject(parent)
    , m_minFileSize(0)
    , m_maxFileSize(-1)
    , m_includeHidden(false)
    , m_scanSubdirectories(true)
    , m_cancelled(false)
{
}

FileAnalyzer::~FileAnalyzer() {
}

// ========== 文件扫描 ==========

FileScanResult FileAnalyzer::scanDirectory(const QString& path, const QStringList& extensions) {
    FileScanResult result;
    result.scanPath = path;
    result.startTime = QDateTime::currentDateTime();
    result.totalFiles = 0;
    result.scannedFiles = 0;
    result.suspiciousFiles = 0;
    result.hiddenFiles = 0;
    result.executableFiles = 0;
    result.totalSize = 0;

    m_scanPath = path;
    m_fileExtensions = extensions;
    m_cancelled = false;

    QList<FileInfo> files;
    QDir dir(path);

    if (!dir.exists()) {
        emit errorOccurred(QString("目录不存在: %1").arg(path));
        return result;
    }

    emit progressUpdated(0, QString("开始扫描: %1").arg(path));

    // 递归扫描目录
    int total = 0;
    int current = 0;

    // 先计算总文件数
    QDirIterator it(path, QDir::AllEntries | QDir::Hidden | QDir::System,
                    QDirIterator::Subdirectories);
    while (it.hasNext()) {
        it.next();
        total++;
    }

    // 重新开始扫描
    it = QDirIterator(path, QDir::AllEntries | QDir::Hidden | QDir::System,
                       QDirIterator::Subdirectories);

    while (it.hasNext() && !m_cancelled) {
        it.next();
        QFileInfo fileInfo = it.fileInfo();

        if (fileInfo.isFile()) {
            FileInfo info;
            processFile(fileInfo, files);

            result.scannedFiles++;
            result.totalSize += info.size;

            if (info.isExecutable) result.executableFiles++;
            if (info.isHidden) result.hiddenFiles++;
            if (info.isSuspicious) {
                result.suspiciousFiles++;
                result.suspiciousFilesList.append(info);
            }

            emit fileFound(info);

            // 更新进度
            int progress = (total > 0) ? (current * 100 / total) : 0;
            emit progressUpdated(progress, QString("已扫描: %1").arg(fileInfo.fileName()));
        }
        current++;
    }

    result.totalFiles = files.size();
    result.endTime = QDateTime::currentDateTime();

    // 生成分析报告
    result.recentlyModifiedFiles = findRecentlyModifiedFiles(files, QDateTime::currentDateTime().addDays(-7));
    result.largeFiles = findLargeFiles(files, 100 * 1024 * 1024); // 100MB以上

    emit scanCompleted(result);

    return result;
}

FileScanResult FileAnalyzer::scanQuick(const QString& path) {
    // 快速扫描：仅扫描可执行文件和近期修改的文件
    QStringList extensions = {
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        ".scr", ".pif", ".msi", ".ocx", ".cpl"
    };
    return scanDirectory(path, extensions);
}

FileScanResult FileAnalyzer::scanFull(const QString& path) {
    // 全盘扫描
    return scanDirectory(path, QStringList());
}

// ========== 单文件分析 ==========

FileInfo FileFile(const QString&Analyzer::analyze filePath) {
    FileInfo info;
    info.path = filePath;

    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists()) {
        info.isSuspicious = true;
        info.suspiciousReason = "文件不存在";
        return info;
    }

    // 分析文件信息
    processFile(fileInfo, QList<FileInfo>()); // 不收集，只是填充info
    analyzeFileAttributes(fileInfo, info);

    // 完整分析
    info.riskLevel = evaluateRiskLevel(info);
    info.isSuspicious = isFileSuspicious(info);

    return info;
}

bool FileAnalyzer::isFileSuspicious(const FileInfo& file) {
    // 检查危险扩展名
    if (DANGEROUS_EXTENSIONS.contains(file.extension, Qt::CaseInsensitive)) {
        // 检查是否在可疑位置
        QString pathLower = file.path.toLower();
        if (pathLower.contains("temp\\") || pathLower.contains("appdata\\")) {
            return true;
        }
    }

    // 检查可疑模式
    QString nameLower = file.name.toLower();
    for (const QString& pattern : DANGEROUS_PATTERNS) {
        if (nameLower.contains(pattern.toLower())) {
            return true;
        }
    }

    // 检查双重扩展名
    if (checkDoubleExtension(file.name)) {
        return true;
    }

    // 检查隐藏的可执行文件
    if (file.isExecutable && file.isHidden && !file.isSystem) {
        return true;
    }

    return false;
}

// ========== 哈希计算 ==========

QString FileAnalyzer::calculateMD5(const QString& filePath) {
    QString hash;
    computeFileHash(filePath, QCryptographicHash::Md5, hash);
    return hash;
}

QString FileAnalyzer::calculateSHA1(const QString& filePath) {
    QString hash;
    computeFileHash(filePath, QCryptographicHash::Sha1, hash);
    return hash;
}

QString FileAnalyzer::calculateSHA256(const QString& filePath) {
    QString hash;
    computeFileHash(filePath, QCryptographicHash::Sha256, hash);
    return hash;
}

bool FileAnalyzer::calculateAllHashes(const QString& filePath, QString& md5, QString& sha1, QString& sha256) {
    md5 = calculateMD5(filePath);
    sha1 = calculateSHA1(filePath);
    sha256 = calculateSHA256(filePath);
    return !md5.isEmpty() && !sha1.isEmpty() && !sha256.isEmpty();
}

// ========== 危险文件检测 ==========

QList<FileInfo> FileAnalyzer::findSuspiciousFiles(const QList<FileInfo>& files) {
    QList<FileInfo> suspicious;
    for (const FileInfo& file : files) {
        if (isFileSuspicious(file)) {
            suspicious.append(file);
            emit suspiciousFileFound(file);
        }
    }
    return suspicious;
}

QList<FileInfo> FileAnalyzer::findRecentlyModifiedFiles(const QList<FileInfo>& files, const QDateTime& since) {
    QList<FileInfo> recent;
    for (const FileInfo& file : files) {
        if (file.modifyTime >= since) {
            recent.append(file);
        }
    }
    return recent;
}

QList<FileInfo> FileAnalyzer::findLargeFiles(const QList<FileInfo>& files, qint64 minSize) {
    QList<FileInfo> large;
    for (const FileInfo& file : files) {
        if (file.size >= minSize) {
            large.append(file);
        }
    }
    return large;
}

QList<FileInfo> FileAnalyzer::findHiddenFiles(const QList<FileInfo>& files) {
    QList<FileInfo> hidden;
    for (const FileInfo& file : files) {
        if (file.isHidden) {
            hidden.append(file);
        }
    }
    return hidden;
}

// ========== 文件搜索 ==========

QList<FileInfo> FileAnalyzer::searchByName(const QString& pattern) {
    QList<FileInfo> results;
    QDir dir(m_scanPath);

    QStringList filters;
    filters << QString("*%1*").arg(pattern);

    QDirIterator it(m_scanPath, filters, QDir::AllEntries | QDir::Hidden | QDir::System,
                    QDirIterator::Subdirectories);

    while (it.hasNext()) {
        it.next();
        QFileInfo fileInfo = it.fileInfo();
        if (fileInfo.isFile()) {
            FileInfo info;
            processFile(fileInfo, results);
        }
    }

    return results;
}

QList<FileInfo> FileAnalyzer::searchByExtension(const QString& extension) {
    QList<FileInfo> results;
    QDir dir(m_scanPath);

    QStringList filters;
    filters << QString("*%1").arg(extension);

    QDirIterator it(m_scanPath, filters, QDir::AllEntries | QDir::Hidden | QDir::System,
                    QDirIterator::Subdirectories);

    while (it.hasNext()) {
        it.next();
        QFileInfo fileInfo = it.fileInfo();
        if (fileInfo.isFile()) {
            FileInfo info;
            processFile(fileInfo, results);
        }
    }

    return results;
}

QList<FileInfo> FileAnalyzer::searchByTimeRange(const QDateTime& start, const QDateTime& end) {
    QList<FileInfo> results;
    QDir dir(m_scanPath);

    QDirIterator it(m_scanPath, QDir::AllEntries | QDir::Hidden | QDir::System,
                     QDirIterator::Subdirectories);

    while (it.hasNext()) {
        it.next();
        QFileInfo fileInfo = it.fileInfo();
        if (fileInfo.isFile()) {
            QDateTime modTime = fileInfo.lastModified();
            if (modTime >= start && modTime <= end) {
                FileInfo info;
                processFile(fileInfo, results);
            }
        }
    }

    return results;
}

QList<FileInfo> FileAnalyzer::searchBySize(qint64 minSize, qint64 maxSize) {
    QList<FileInfo> results;
    QDir dir(m_scanPath);

    QDirIterator it(m_scanPath, QDir::AllEntries | QDir::Hidden | QDir::System,
                     QDirIterator::Subdirectories);

    while (it.hasNext()) {
        it.next();
        QFileInfo fileInfo = it.fileInfo();
        if (fileInfo.isFile()) {
            qint64 size = fileInfo.size();
            if (size >= minSize && (maxSize < 0 || size <= maxSize)) {
                FileInfo info;
                processFile(fileInfo, results);
            }
        }
    }

    return results;
}

// ========== 恶意特征检测 ==========

bool FileAnalyzer::checkMaliciousPattern(const QString& content) {
    Q_UNUSED(content)
    // 实际实现应该检查恶意代码特征
    return false;
}

bool FileAnalyzer::checkSuspiciousExtension(const QString& extension) {
    return SUSPICIOUS_EXTENSIONS.contains(extension, Qt::CaseInsensitive);
}

bool FileAnalyzer::checkDoubleExtension(const QString& filename) {
    // 检查双重扩展名（如 .txt.exe）
    QStringList parts = filename.split(".");
    return parts.size() > 2;
}

bool FileAnalyzer::checkKnownMaliciousHash(const QString& hash) {
    Q_UNUSED(hash)
    // 实际实现应该查询恶意软件哈希数据库
    return false;
}

// ========== 文件操作 ==========

bool FileAnalyzer::deleteFile(const QString& filePath) {
    QFile file(filePath);
    return file.remove();
}

bool FileAnalyzer::quarantineFile(const QString& filePath, const QString& quarantinePath) {
    QFileInfo original(filePath);
    QString fileName = original.fileName();
    QString destPath = quarantinePath + "/" + fileName;

    // 复制文件到隔离区
    if (QFile::copy(filePath, destPath)) {
        // 尝试删除原文件
        return deleteFile(filePath);
    }
    return false;
}

bool FileAnalyzer::restoreFile(const QString& quarantinedPath, const QString& originalPath) {
    return QFile::copy(quarantinedPath, originalPath);
}

bool FileAnalyzer::hideFile(const QString& filePath) {
    DWORD attrs = GetFileAttributesW((LPCWSTR)filePath.utf16());
    if (attrs == INVALID_FILE_ATTRIBUTES) return false;
    return SetFileAttributesW((LPCWSTR)filePath.utf16(), attrs | FILE_ATTRIBUTE_HIDDEN) != 0;
}

bool FileAnalyzer::showFile(const QString& filePath) {
    DWORD attrs = GetFileAttributesW((LPCWSTR)filePath.utf16());
    if (attrs == INVALID_FILE_ATTRIBUTES) return false;
    return SetFileAttributesW((LPCWSTR)filePath.utf16(), attrs & ~FILE_ATTRIBUTE_HIDDEN) != 0;
}

// ========== 辅助方法 ==========

void FileAnalyzer::processFile(const QFileInfo& fileInfo, QList<FileInfo>& files) {
    FileInfo info;
    info.path = fileInfo.absoluteFilePath();
    info.name = fileInfo.fileName();
    info.extension = fileInfo.suffix();
    info.size = fileInfo.size();
    info.createTime = fileInfo.created();
    info.modifyTime = fileInfo.lastModified();
    info.accessTime = fileInfo.lastRead();
    info.isHidden = fileInfo.isHidden();
    info.isSystem = fileInfo.isSymLink() || fileInfo.exists(); // 简化检查
    info.isReadOnly = fileInfo.isReadable();
    info.isExecutable = DANGEROUS_EXTENSIONS.contains(info.extension, Qt::CaseInsensitive);

    // 分析文件类型
    info.fileType = identifyFileType(info.path, info.extension);

    // 风险评估
    info.riskLevel = evaluateRiskLevel(info);

    // 检查可疑性
    info.isSuspicious = isFileSuspicious(info);
    if (info.isSuspicious) {
        info.suspiciousReason = "检测到可疑特征";
    }

    files.append(info);
}

void FileAnalyzer::analyzeFileAttributes(const QFileInfo& fileInfo, FileInfo& info) {
    // 获取文件属性
    DWORD attrs = GetFileAttributesW((LPCWSTR)info.path.utf16());
    info.attributes = "";

    if (attrs != INVALID_FILE_ATTRIBUTES) {
        if (attrs & FILE_ATTRIBUTE_READONLY) info.attributes += "R ";
        if (attrs & FILE_ATTRIBUTE_HIDDEN) info.attributes += "H ";
        if (attrs & FILE_ATTRIBUTE_SYSTEM) info.attributes += "S ";
        if (attrs & FILE_ATTRIBUTE_DIRECTORY) info.attributes += "D ";
        if (attrs & FILE_ATTRIBUTE_ARCHIVE) info.attributes += "A ";
        if (attrs & FILE_ATTRIBUTE_COMPRESSED) info.attributes += "C ";
        if (attrs & FILE_ATTRIBUTE_ENCRYPTED) info.attributes += "E ";
    }

    // 获取文件所有者
    QString owner;
    // 实际实现应该使用GetNamedSecurityInfo
    info.owner = owner;

    info.hashMD5 = calculateMD5(info.path);
    info.hashSHA256 = calculateSHA256(info.path);
}

bool FileAnalyzer::computeFileHash(const QString& filePath, QCryptographicHash::Algorithm algo, QString& hash) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return false;
    }

    QCryptographicHash crypto(algo);
    if (crypto.addData(&file)) {
        hash = crypto.result().toHex();
    }

    file.close();
    return !hash.isEmpty();
}

int FileAnalyzer::evaluateRiskLevel(const FileInfo& file) {
    // 可执行文件高风险
    if (file.isExecutable) {
        // 检查是否在系统目录
        QString pathLower = file.path.toLower();
        if (pathLower.contains("windows\\system32") || pathLower.contains("program files")) {
            return 0; // 可能在系统目录，可能是正常的
        }

        // 检查是否在用户目录
        if (pathLower.contains("users\\") && pathLower.contains("appdata")) {
            return 3; // 高风险
        }

        return 1; // 中等风险
    }

    // 检查危险扩展名
    if (DANGEROUS_EXTENSIONS.contains(file.extension, Qt::CaseInsensitive)) {
        return 2;
    }

    // 检查隐藏文件
    if (file.isHidden && !file.isSystem) {
        return 2;
    }

    return 0; // 默认安全
}

QString FileAnalyzer::identifyFileType(const QString& filePath, const QString& extension) {
    // 基于扩展名的简单类型识别
    QString ext = extension.toLower();

    if (ext.isEmpty()) return "Unknown";

    if (ext == "exe") return "可执行文件";
    if (ext == "dll") return "动态链接库";
    if (ext == "bat" || ext == "cmd") return "批处理文件";
    if (ext == "ps1") return "PowerShell脚本";
    if (ext == "vbs" || ext == "js") return "脚本文件";
    if (ext == "txt") return "文本文件";
    if (ext == "doc" || ext == "docx") return "Word文档";
    if (ext == "xls" || ext == "xlsx") return "Excel表格";
    if (ext == "pdf") return "PDF文档";
    if (ext == "jpg" || ext == "jpeg" || ext == "png") return "图片文件";
    if (ext == "mp3" || ext == "wav" || ext == "flac") return "音频文件";
    if (ext == "mp4" || ext == "avi" || ext == "mkv") return "视频文件";
    if (ext == "zip" || ext == "rar" || ext == "7z") return "压缩文件";
    if (ext == "log") return "日志文件";

    return "其他文件";
}

bool FileAnalyzer::isExecutableBySignature(const QString& filePath) {
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return false;
    }

    // 检查PE文件签名
    unsigned char header[2];
    qint64 bytesRead = file.read((char*)header, 2);
    file.close();

    if (bytesRead == 2) {
        return header[0] == 'M' && header[1] == 'Z'; // MZ header for PE files
    }

    return false;
}
