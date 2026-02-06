#include "LocalizationManager.h"
#include <QApplication>
#include <QDir>
#include <QFileInfo>

LocalizationManager::LocalizationManager(QObject *parent)
    : QObject(parent)
    , m_translator(new QTranslator(this))
{
    initializeLanguageNames();
}

LocalizationManager::~LocalizationManager()
{
    unloadLanguage();
}

bool LocalizationManager::loadLanguage(const QString& languageCode)
{
    if (languageCode == "en" || languageCode.isEmpty()) {
        unloadLanguage();
        return true;
    }

    // 尝试加载内置翻译
    QString resourcePath = ":/translations/emergency_" + languageCode + ".qm";
    if (QFile::exists(resourcePath)) {
        return loadLanguage(languageCode, resourcePath);
    }

    // 尝试加载外部翻译文件
    QStringList searchPaths = {
        "translations",
        "locales",
        "i18n",
        "lang",
        "../translations",
        "../locales"
    };

    for (const QString& path : searchPaths) {
        QString filePath = QString("%1/emergency_%2.qm").arg(path).arg(languageCode);
        if (QFile::exists(filePath)) {
            return loadLanguage(languageCode, filePath);
        }
    }

    return false;
}

bool LocalizationManager::loadLanguage(const QString& languageCode, const QString& filePath)
{
    if (!QFile::exists(filePath)) {
        return false;
    }

    // 卸载当前翻译
    unloadLanguage();

    // 加载新翻译
    if (!m_translator->load(filePath)) {
        return false;
    }

    // 安装翻译器
    if (!QApplication::installTranslator(m_translator)) {
        return false;
    }

    m_currentLanguage = languageCode;
    emit languageChanged(languageCode);
    emit translationChanged();

    return true;
}

void LocalizationManager::unloadLanguage()
{
    if (!m_currentLanguage.isEmpty()) {
        QApplication::removeTranslator(m_translator);
        m_currentLanguage.clear();
    }
}

QString LocalizationManager::currentLanguage() const
{
    return m_currentLanguage;
}

QString LocalizationManager::currentLanguageName() const
{
    return m_languageNames.value(m_currentLanguage, m_currentLanguage);
}

QList<QMap<QString, QString>> LocalizationManager::availableLanguages()
{
    QList<QMap<QString, QString>> languages;

    // 添加系统默认选项
    QMap<QString, QString> systemLang;
    systemLang["code"] = "";
    systemLang["name"] = tr("System Default");
    languages.append(systemLang);

    // 添加支持的语言
    for (auto it = m_languageNames.begin(); it != m_languageNames.end(); ++it) {
        QMap<QString, QString> lang;
        lang["code"] = it.key();
        lang["name"] = it.value();
        languages.append(lang);
    }

    return languages;
}

QString LocalizationManager::languageName(const QString& code)
{
    return m_languageNames.value(code, code);
}

QString LocalizationManager::translate(const QString& context, const QString& source,
                                        const QString& disambiguation, int n)
{
    return QApplication::translate(context.toUtf8().constData(),
                                   source.toUtf8().constData(),
                                   disambiguation.toUtf8().constData(), n);
}

void LocalizationManager::setApplicationFont(const QString& fontFamily, int pointSize)
{
    QFont font;
    if (!fontFamily.isEmpty()) {
        font.setFamily(fontFamily);
    }
    if (pointSize > 0) {
        font.setPointSize(pointSize);
    }
    QApplication::setFont(font);
}

void LocalizationManager::resetApplicationFont()
{
    QApplication::setFont(QFont("Microsoft YaHei", 9));
}

void LocalizationManager::setRightToLeft(bool enable)
{
    if (enable) {
        QApplication::setLayoutDirection(Qt::RightToLeft);
    } else {
        QApplication::setLayoutDirection(Qt::LeftToRight);
    }
}

bool LocalizationManager::isRightToLeft() const
{
    return QApplication::layoutDirection() == Qt::RightToLeft;
}

void LocalizationManager::initializeLanguageNames()
{
    m_languageNames = {
        {"zh_CN", "简体中文"},
        {"zh_TW", "繁體中文"},
        {"en", "English"},
        {"ja", "日本語"},
        {"ko", "한국어"},
        {"ru", "Русский"},
        {"de", "Deutsch"},
        {"fr", "Français"},
        {"es", "Español"},
        {"pt", "Português"}
    };
}
