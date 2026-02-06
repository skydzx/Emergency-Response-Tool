#ifndef THEMEMANAGER_H
#define THEMEMANAGER_H

#include <QObject>
#include <QString>
#include <QColor>
#include <QFont>
#include <QPalette>

struct Theme {
    QString name;
    QString id;
    QColor primaryColor;
    QColor secondaryColor;
    QColor accentColor;
    QColor backgroundColor;
    QColor surfaceColor;
    QColor textColor;
    QColor textSecondaryColor;
    QColor borderColor;
    QColor errorColor;
    QColor warningColor;
    QColor successColor;
    QColor infoColor;
    QColor criticalColor;
    QColor highColor;
    QColor mediumColor;
    QColor lowColor;
    QFont defaultFont;
    QFont titleFont;
    bool darkMode;
    QString styleSheet;
};

class ThemeManager : public QObject {
    Q_OBJECT

public:
    explicit ThemeManager(QObject *parent = nullptr);
    ~ThemeManager();

    // 主题管理
    Theme getCurrentTheme();
    bool setTheme(const QString& themeId);
    bool setTheme(const Theme& theme);
    QList<Theme> availableThemes();
    Theme createTheme(const QString& name, bool darkMode);

    // 颜色管理
    QColor getColor(const QString& role);
    void setColor(const QString& role, const QColor& color);
    QColor getSeverityColor(const QString& severity);
    QColor getStatusColor(const QString& status);

    // 字体管理
    QFont getFont(const QString& role);
    void setFont(const QString& role, const QFont& font);
    void setDefaultFontFamily(const QString& family);
    void setDefaultFontSize(int size);

    // 样式表
    QString generateStyleSheet();
    QString generateDarkStyleSheet();
    QString generateLightStyleSheet();
    bool applyStyleSheet(const QString& styleSheet);
    void reloadStyleSheet();

    // 动画效果
    void setAnimationsEnabled(bool enabled);
    bool animationsEnabled() const;

    // 图标主题
    void setIconTheme(const QString& themeName);
    QString currentIconTheme() const;

signals:
    void themeChanged(const Theme& theme);
    void styleSheetChanged(const QString& styleSheet);
    void colorChanged(const QString& role, const QColor& color);

private:
    Theme m_currentTheme;
    QList<Theme> m_themes;
    bool m_animationsEnabled;
    QString m_iconTheme;

    void initializeThemes();
    void initializeDefaultTheme();
    void initializeDarkTheme();
    void initializeLightTheme();
    QString buildStyleSheet(const Theme& theme);
};

#endif // THEMEMANAGER_H
