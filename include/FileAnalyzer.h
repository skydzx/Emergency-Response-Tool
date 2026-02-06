#ifndef FILEANALYZER_H
#define FILEANALYZER_H

#include <QObject>
#include <QString>
#include <QList>
#include <QMap>
#include <QVector>
#include <QDateTime>
#include <QFileInfo>
#include <QDir>
#include <QThread>
#include <atomic>
#include <windows.h>

struct FileInfo {
    QString path;
    QString name;
    QString extension;
    qint64 size;
    QString hashMD5;
    QString hashSHA1;
    QString hashSHA256;
    QDateTime createTime;
    QDateTime modifyTime;
    QDateTime accessTime;
    QString attributes;
    QString owner;
    QString fileType;
    QString description;
    bool isExecutable;
    bool isHidden;
    bool isSystem;
    bool isReadOnly;
    bool isSuspicious;
    QString suspiciousReason;
    int riskLevel;  // 0=安全, 1=低, 2=中, 3=高
    QStringList tags;
    QString group;
};

struct FileScanResult {
    int totalFiles;
    int scannedFiles;
    int suspiciousFiles;
    int hiddenFiles;
    int executableFiles;
    qint64 totalSize;
    QString scanPath;
    QDateTime startTime;
    QDateTime endTime;
    QList<FileInfo> suspiciousFilesList;
    QList<FileInfo> recentlyModifiedFiles;
    QList<FileInfo> largeFiles;
};

class FileAnalyzer : public QObject {
    Q_OBJECT

public:
    explicit FileAnalyzer(QObject *parent = nullptr);
    ~FileAnalyzer();

    // 文件扫描
    FileScanResult scanDirectory(const QString& path, const QStringList& extensions = QStringList());
    FileScanResult scanQuick(const QString& path);
    FileScanResult scanFull(const QString& path);

    // 单文件分析
    FileInfo analyzeFile(const QString& filePath);
    bool isFileSuspicious(const FileInfo& file);

    // 哈希计算
    QString calculateMD5(const QString& filePath);
    QString calculateSHA1(const QString& filePath);
    QString calculateSHA256(const QString& filePath);
    bool calculateAllHashes(const QString& filePath, QString& md5, QString& sha1, QString& sha256);

    // 危险文件检测
    QList<FileInfo> findSuspiciousFiles(const QList<FileInfo>& files);
    QList<FileInfo> findRecentlyModifiedFiles(const QList<FileInfo>& files, const QDateTime& since);
    QList<FileInfo> findLargeFiles(const QList<FileInfo>& files, qint64 minSize);
    QList<FileInfo> findHiddenFiles(const QList<FileInfo>& files);

    // 文件搜索
    QList<FileInfo> searchByName(const QString& pattern);
    QList<FileInfo> searchByExtension(const QString& extension);
    QList<FileInfo> searchByTimeRange(const QDateTime& start, const QDateTime& end);
    QList<FileInfo> searchBySize(qint64 minSize, qint64 maxSize = -1);

    // 恶意特征检测
    bool checkMaliciousPattern(const QString& content);
    bool checkSuspiciousExtension(const QString& extension);
    bool checkDoubleExtension(const QString& filename);
    bool checkKnownMaliciousHash(const QString& hash);

    // 文件操作
    bool deleteFile(const QString& filePath);
    bool quarantineFile(const QString& filePath, const QString& quarantinePath);
    bool restoreFile(const QString& quarantinedPath, const QString& originalPath);
    bool hideFile(const QString& filePath);
    bool showFile(const QString& filePath);

signals:
    void progressUpdated(int percentage, const QString& status);
    void fileFound(const FileInfo& file);
    void suspiciousFileFound(const FileInfo& file);
    void scanCompleted(const FileScanResult& result);
    void errorOccurred(const QString& error);
    void scanCancelled();

private:
    // 危险扩展名
    static const QStringList DANGEROUS_EXTENSIONS;

    // 可疑扩展名
    static const QStringList SUSPICIOUS_EXTENSIONS;

    // 危险文件名模式
    static const QStringList DANGEROUS_PATTERNS;

    // 扫描设置
    QString m_scanPath;
    QStringList m_fileExtensions;
    qint64 m_minFileSize;
    qint64 m_maxFileSize;
    bool m_includeHidden;
    bool m_scanSubdirectories;
    std::atomic<bool> m_cancelled;

    // 内部扫描方法
    void scanDirectoryRecursive(const QDir& dir, QList<FileInfo>& files, int& total, int& current);
    void processFile(const QFileInfo& fileInfo, QList<FileInfo>& files);
    void analyzeFileAttributes(const QFileInfo& fileInfo, FileInfo& info);

    // 哈希计算辅助方法
    bool computeFileHash(const QString& filePath, QCryptographicHash::Algorithm algo, QString& hash);

    // 风险评估
    int evaluateRiskLevel(const FileInfo& file);

    // 文件类型识别
    QString identifyFileType(const QString& filePath, const QString& extension);
    bool isExecutableBySignature(const QString& filePath);
};

#endif // FILEANALYZER_H
