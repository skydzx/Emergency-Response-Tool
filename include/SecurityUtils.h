#ifndef SECURITYUTILS_H
#define SECURITYUTILS_H

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QJsonObject>

class SecurityUtils : public QObject {
    Q_OBJECT

public:
    explicit SecurityUtils(QObject *parent = nullptr);
    ~SecurityUtils();

    // 输入验证
    static bool validateFilePath(const QString& path);
    static bool validateUrl(const QString& url);
    static bool validateIpAddress(const QString& ip);
    static bool validateDomain(const QString& domain);
    static bool validateHash(const QString& hash, const QString& algorithm = "sha256");
    static QString sanitizeInput(const QString& input);
    static QString escapeHtml(const QString& input);

    // 文件安全
    static bool isSafeFile(const QString& filePath);
    static bool isExecutable(const QString& filePath);
    static bool isSymlink(const QString& filePath);
    static qint64 getFileSize(const QString& filePath);
    static QString getFileExtension(const QString& filePath);

    // 路径安全
    static QString canonicalPath(const QString& path);
    static bool isPathTraversal(const QString& path);
    static QString sanitizeFileName(const QString& fileName);

    // 加密解密
    static QByteArray encryptData(const QByteArray& data, const QString& key);
    static QByteArray decryptData(const QByteArray& data, const QString& key);
    static QString hashPassword(const QString& password, const QString& salt = "");
    static bool verifyPassword(const QString& password, const QString& hash, const QString& salt = "");
    static QString generateToken(int length = 32);
    static QString generateSalt(int length = 16);

    // 安全配置
    static bool loadSecurityConfig(const QString& filePath);
    static QJsonObject getSecurityConfig();
    static void setMaxFileSize(qint64 size);
    static void setAllowedExtensions(const QStringList& extensions);
    static void setBlockedExtensions(const QStringList& extensions);

signals:
    void securityAlert(const QString& type, const QString& message);
    void fileBlocked(const QString& filePath, const QString& reason);

private:
    static qint64 m_maxFileSize;
    static QStringList m_allowedExtensions;
    static QStringList m_blockedExtensions;
    static QJsonObject m_securityConfig;
};

#endif // SECURITYUTILS_H
