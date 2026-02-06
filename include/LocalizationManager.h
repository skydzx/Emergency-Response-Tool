#ifndef LOCALIZATIONMANAGER_H
#define LOCALIZATIONMANAGER_H

#include <QObject>
#include <QTranslator>
#include <QLocale>
#include <QMap>

class LocalizationManager : public QObject {
    Q_OBJECT

public:
    explicit LocalizationManager(QObject *parent = nullptr);
    ~LocalizationManager();

    // 语言管理
    bool loadLanguage(const QString& languageCode);
    bool loadLanguage(const QString& languageCode, const QString& filePath);
    void unloadLanguage();
    QString currentLanguage() const;
    QString currentLanguageName() const;

    // 可用语言
    QList<QMap<QString, QString>> availableLanguages();
    QString languageName(const QString& code);

    // 翻译
    QString translate(const QString& context, const QString& source,
                      const QString& disambiguation = QString(),
                      int n = -1);

    // 字体管理
    void setApplicationFont(const QString& fontFamily, int pointSize = -1);
    void resetApplicationFont();

    // RTL支持
    void setRightToLeft(bool enable);
    bool isRightToLeft() const;

signals:
    void languageChanged(const QString& languageCode);
    void translationChanged();

private:
    QTranslator* m_translator;
    QString m_currentLanguage;
    QMap<QString, QString> m_languageNames;

    void initializeLanguageNames();
};

#endif // LOCALIZATIONMANAGER_H
