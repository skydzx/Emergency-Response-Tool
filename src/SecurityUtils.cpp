#include "SecurityUtils.h"
#include <QFileInfo>
#include <QDir>
#include <QCryptographicHash>
#include <QRegularExpression>
#include <QJsonDocument>
#include <QFile>
#include <QDebug>

qint64 SecurityUtils::m_maxFileSize = 100 * 1024 * 1024; // 100MB
QStringList SecurityUtils::m_allowedExtensions;
QStringList SecurityUtils::m_blockedExtensions;
QJsonObject SecurityUtils::m_securityConfig;

SecurityUtils::SecurityUtils(QObject *parent)
    : QObject(parent)
{
}

SecurityUtils::~SecurityUtils()
{
}

// 输入验证
bool SecurityUtils::validateFilePath(const QString& path)
{
    if (path.isEmpty()) return false;

    // 检查长度
    if (path.length() > 260) return false;

    // 检查非法字符
    QString invalidChars = "<>:\"?*|";
    for (const QChar& c : invalidChars) {
        if (path.contains(c)) return false;
    }

    // 检查路径遍历
    if (isPathTraversal(path)) return false;

    // 检查绝对路径（可选）
    // if (!path.startsWith("/") && !path.startsWith("C:\\")) return false;

    return true;
}

bool SecurityUtils::validateUrl(const QString& url)
{
    QRegularExpression urlRegex(
        R"(^(https?|ftp)://[^\s/$.?#].[^\s]*$|^(www\.[^\s]+)$)",
        QRegularExpression::CaseInsensitiveOption
    );
    return urlRegex.match(url).hasMatch();
}

bool SecurityUtils::validateIpAddress(const QString& ip)
{
    QRegularExpression ipv4Regex(
        R"(^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)"
    );
    return ipv4Regex.match(ip).hasMatch();
}

bool SecurityUtils::validateDomain(const QString& domain)
{
    QRegularExpression domainRegex(
        R"(^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$)",
        QRegularExpression::CaseInsensitiveOption
    );
    return domainRegex.match(domain).hasMatch();
}

bool SecurityUtils::validateHash(const QString& hash, const QString& algorithm)
{
    int expectedLength = 0;
    if (algorithm == "md5") expectedLength = 32;
    else if (algorithm == "sha1") expectedLength = 40;
    else if (algorithm == "sha256") expectedLength = 64;
    else if (algorithm == "sha512") expectedLength = 128;

    if (expectedLength == 0) return false;
    if (hash.length() != expectedLength) return false;

    QRegularExpression hashRegex("^[a-fA-F0-9]+$");
    return hashRegex.match(hash).hasMatch();
}

QString SecurityUtils::sanitizeInput(const QString& input)
{
    QString result = input;

    // 移除控制字符
    result.remove(QRegularExpression("[\x00-\x1f\x7f]"));

    // 转义SQL特殊字符
    result.replace("'", "''");
    result.replace(";", "&#59;");
    result.replace("--", "&#45;&#45;");

    // 移除可能的命令注入
    result.replace(";", "");
    result.replace("|", "");
    result.replace("&", "");
    result.replace("$", "");
    result.replace("`", "");
    result.replace("$(", "");
    result.replace("`", "");

    return result.trimmed();
}

QString SecurityUtils::escapeHtml(const QString& input)
{
    QString result = input;
    result.replace("&", "&amp;");
    result.replace("<", "&lt;");
    result.replace(">", "&gt;");
    result.replace("\"", "&quot;");
    result.replace("'", "&#39;");
    return result;
}

// 文件安全
bool SecurityUtils::isSafeFile(const QString& filePath)
{
    QFileInfo fileInfo(filePath);

    if (!fileInfo.exists()) return false;
    if (!fileInfo.isFile()) return false;

    // 检查大小
    if (fileInfo.size() > m_maxFileSize) return false;

    // 检查扩展名
    QString ext = fileInfo.suffix().toLower();
    if (!m_allowedExtensions.isEmpty() && !m_allowedExtensions.contains(ext)) {
        return false;
    }
    if (m_blockedExtensions.contains(ext)) {
        return false;
    }

    return true;
}

bool SecurityUtils::isExecutable(const QString& filePath)
{
    QString ext = getFileExtension(filePath).toLower();
    QStringList execExts = {"exe", "dll", "sys", "bat", "cmd", "ps1", "com", "scr", "pif"};
    return execExts.contains(ext);
}

bool SecurityUtils::isSymlink(const QString& filePath)
{
    QFileInfo fileInfo(filePath);
    return fileInfo.isSymLink();
}

qint64 SecurityUtils::getFileSize(const QString& filePath)
{
    QFileInfo fileInfo(filePath);
    return fileInfo.size();
}

QString SecurityUtils::getFileExtension(const QString& filePath)
{
    QFileInfo fileInfo(filePath);
    return fileInfo.suffix();
}

// 路径安全
QString SecurityUtils::canonicalPath(const QString& path)
{
    QDir dir;
    return dir.cleanPath(path);
}

bool SecurityUtils::isPathTraversal(const QString& path)
{
    // 检查路径遍历攻击
    if (path.contains("..")) {
        QRegularExpression traversalRegex(R"(\.\.[\\/])");
        return traversalRegex.match(path).hasMatch();
    }
    return false;
}

QString SecurityUtils::sanitizeFileName(const QString& fileName)
{
    QString result = fileName;

    // 移除危险字符
    QString dangerChars = "<>:\"?*|/\n\r\t";
    for (const QChar& c : dangerChars) {
        result.remove(c);
    }

    // 限制长度
    if (result.length() > 255) {
        result = result.left(255);
    }

    return result.trimmed();
}

// 加密解密
QByteArray SecurityUtils::encryptData(const QByteArray& data, const QString& key)
{
    Q_UNUSED(data)
    Q_UNUSED(key)
    // 实际实现需要使用加密库
    // 这里返回原始数据的简单混淆
    QByteArray result = data.toBase64();
    return result;
}

QByteArray SecurityUtils::decryptData(const QByteArray& data, const QString& key)
{
    Q_UNUSED(data)
    Q_UNUSED(key)
    // 实际实现需要使用加密库
    return QByteArray::fromBase64(data);
}

QString SecurityUtils::hashPassword(const QString& password, const QString& salt)
{
    QString combined = password + salt;
    QByteArray hash = QCryptographicHash::hash(combined.toUtf8(), QCryptographicHash::Sha256);
    return hash.toHex();
}

bool SecurityUtils::verifyPassword(const QString& password, const QString& hash, const QString& salt)
{
    QString newHash = hashPassword(password, salt);
    return newHash == hash;
}

QString SecurityUtils::generateToken(int length)
{
    const QString chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    QString token;
    QRandomGenerator generator(QRandomGenerator::global()->generate());

    for (int i = 0; i < length; ++i) {
        token += chars[generator.bounded(chars.length())];
    }

    return token;
}

QString SecurityUtils::generateSalt(int length)
{
    return generateToken(length);
}

// 安全配置
bool SecurityUtils::loadSecurityConfig(const QString& filePath)
{
    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly)) {
        return false;
    }

    QByteArray data = file.readAll();
    file.close();

    QJsonParseError error;
    QJsonDocument doc = QJsonDocument::fromJson(data, &error);

    if (error.error != QJsonParseError::NoError) {
        return false;
    }

    m_securityConfig = doc.object();
    return true;
}

QJsonObject SecurityUtils::getSecurityConfig()
{
    return m_securityConfig;
}

void SecurityUtils::setMaxFileSize(qint64 size)
{
    m_maxFileSize = size;
}

void SecurityUtils::setAllowedExtensions(const QStringList& extensions)
{
    m_allowedExtensions = extensions;
}

void SecurityUtils::setBlockedExtensions(const QStringList& extensions)
{
    m_blockedExtensions = extensions;
}
