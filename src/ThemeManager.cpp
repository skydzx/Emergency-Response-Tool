#include "ThemeManager.h"
#include <QApplication>
#include <QPalette>
#include <QFontDatabase>

ThemeManager::ThemeManager(QObject *parent)
    : QObject(parent)
    , m_animationsEnabled(true)
    , m_iconTheme("default")
{
    initializeThemes();
    setTheme("dark");
}

ThemeManager::~ThemeManager()
{
}

void ThemeManager::initializeThemes()
{
    initializeDefaultTheme();
    initializeDarkTheme();
    initializeLightTheme();
}

void ThemeManager::initializeDefaultTheme()
{
    Theme defaultTheme;
    defaultTheme.name = "Default";
    defaultTheme.id = "default";
    defaultTheme.primaryColor = QColor(33, 150, 243);
    defaultTheme.secondaryColor = QColor(25, 118, 210);
    defaultTheme.accentColor = QColor(3, 169, 244);
    defaultTheme.backgroundColor = QColor(245, 245, 245);
    defaultTheme.surfaceColor = QColor(255, 255, 255);
    defaultTheme.textColor = QColor(33, 33, 33);
    defaultTheme.textSecondaryColor = QColor(117, 117, 117);
    defaultTheme.borderColor = QColor(224, 224, 224);
    defaultTheme.errorColor = QColor(244, 67, 54);
    defaultTheme.warningColor = QColor(255, 193, 7);
    defaultTheme.successColor = QColor(76, 175, 80);
    defaultTheme.infoColor = QColor(23, 162, 184);
    defaultTheme.criticalColor = QColor(220, 53, 69);
    defaultTheme.highColor = QColor(253, 126, 20);
    defaultTheme.mediumColor = QColor(255, 193, 7);
    defaultTheme.lowColor = QColor(23, 162, 184);
    defaultTheme.darkMode = false;
    defaultTheme.defaultFont = QFont("Microsoft YaHei", 9);
    defaultTheme.titleFont = QFont("Microsoft YaHei", 12, QFont::Bold);

    m_themes.append(defaultTheme);
}

void ThemeManager::initializeDarkTheme()
{
    Theme darkTheme;
    darkTheme.name = "Dark";
    darkTheme.id = "dark";
    darkTheme.primaryColor = QColor(66, 133, 244);
    darkTheme.secondaryColor = QColor(52, 152, 219);
    darkTheme.accentColor = QColor(41, 128, 185);
    darkTheme.backgroundColor = QColor(30, 30, 30);
    darkTheme.surfaceColor = QColor(45, 45, 45);
    darkTheme.textColor = QColor(255, 255, 255);
    darkTheme.textSecondaryColor = QColor(180, 180, 180);
    darkTheme.borderColor = QColor(60, 60, 60);
    darkTheme.errorColor = QColor(231, 76, 60);
    darkTheme.warningColor = QColor(241, 196, 15);
    darkTheme.successColor = QColor(46, 204, 113);
    darkTheme.infoColor = QColor(26, 188, 156);
    darkTheme.criticalColor = QColor(231, 76, 60);
    darkTheme.highColor = QColor(230, 126, 34);
    darkTheme.mediumColor = QColor(241, 196, 15);
    darkTheme.lowColor = QColor(26, 188, 156);
    darkTheme.darkMode = true;
    darkTheme.defaultFont = QFont("Microsoft YaHei", 9);
    darkTheme.titleFont = QFont("Microsoft YaHei", 12, QFont::Bold);

    m_themes.append(darkTheme);
}

void ThemeManager::initializeLightTheme()
{
    Theme lightTheme;
    lightTheme.name = "Light";
    lightTheme.id = "light";
    lightTheme.primaryColor = QColor(33, 150, 243);
    lightTheme.secondaryColor = QColor(25, 118, 210);
    lightTheme.accentColor = QColor(3, 169, 244);
    lightTheme.backgroundColor = QColor(250, 250, 250);
    lightTheme.surfaceColor = QColor(255, 255, 255);
    lightTheme.textColor = QColor(33, 33, 33);
    lightTheme.textSecondaryColor = QColor(117, 117, 117);
    lightTheme.borderColor = QColor(224, 224, 224);
    lightTheme.errorColor = QColor(244, 67, 54);
    lightTheme.warningColor = QColor(255, 193, 7);
    lightTheme.successColor = QColor(76, 175, 80);
    lightTheme.infoColor = QColor(23, 162, 184);
    lightTheme.criticalColor = QColor(220, 53, 69);
    lightTheme.highColor = QColor(253, 126, 20);
    lightTheme.mediumColor = QColor(255, 193, 7);
    lightTheme.lowColor = QColor(23, 162, 184);
    lightTheme.darkMode = false;
    lightTheme.defaultFont = QFont("Microsoft YaHei", 9);
    lightTheme.titleFont = QFont("Microsoft YaHei", 12, QFont::Bold);

    m_themes.append(lightTheme);
}

Theme ThemeManager::getCurrentTheme()
{
    return m_currentTheme;
}

bool ThemeManager::setTheme(const QString& themeId)
{
    for (const auto& theme : m_themes) {
        if (theme.id == themeId) {
            return setTheme(theme);
        }
    }
    return false;
}

bool ThemeManager::setTheme(const Theme& theme)
{
    m_currentTheme = theme;

    // 应用颜色
    QPalette palette;
    palette.setColor(QPalette::Window, theme.backgroundColor);
    palette.setColor(QPalette::WindowText, theme.textColor);
    palette.setColor(QPalette::Base, theme.surfaceColor);
    palette.setColor(QPalette::AlternateBase, theme.backgroundColor);
    palette.setColor(QPalette::ToolTipBase, theme.surfaceColor);
    palette.setColor(QPalette::ToolTipText, theme.textColor);
    palette.setColor(QPalette::Text, theme.textColor);
    palette.setColor(QPalette::Button, theme.surfaceColor);
    palette.setColor(QPalette::ButtonText, theme.textColor);
    palette.setColor(QPalette::BrightText, Qt::white);
    palette.setColor(QPalette::Link, theme.primaryColor);
    palette.setColor(QPalette::Highlight, theme.primaryColor);
    palette.setColor(QPalette::HighlightedText, Qt::white);
    QApplication::setPalette(palette);

    // 应用字体
    QApplication::setFont(theme.defaultFont);

    // 应用样式表
    QString styleSheet = buildStyleSheet(theme);
    applyStyleSheet(styleSheet);

    emit themeChanged(theme);
    return true;
}

QList<Theme> ThemeManager::availableThemes()
{
    return m_themes;
}

Theme ThemeManager::createTheme(const QString& name, bool darkMode)
{
    Theme theme;
    theme.name = name;
    theme.id = name.toLower().replace(" ", "_");
    theme.darkMode = darkMode;

    if (darkMode) {
        theme.backgroundColor = QColor(30, 30, 30);
        theme.surfaceColor = QColor(45, 45, 45);
        theme.textColor = QColor(255, 255, 255);
        theme.textSecondaryColor = QColor(180, 180, 180);
        theme.borderColor = QColor(60, 60, 60);
    } else {
        theme.backgroundColor = QColor(245, 245, 245);
        theme.surfaceColor = QColor(255, 255, 255);
        theme.textColor = QColor(33, 33, 33);
        theme.textSecondaryColor = QColor(117, 117, 117);
        theme.borderColor = QColor(224, 224, 224);
    }

    return theme;
}

QColor ThemeManager::getColor(const QString& role)
{
    if (role == "primary") return m_currentTheme.primaryColor;
    if (role == "secondary") return m_currentTheme.secondaryColor;
    if (role == "accent") return m_currentTheme.accentColor;
    if (role == "background") return m_currentTheme.backgroundColor;
    if (role == "surface") return m_currentTheme.surfaceColor;
    if (role == "text") return m_currentTheme.textColor;
    if (role == "textSecondary") return m_currentTheme.textSecondaryColor;
    if (role == "border") return m_currentTheme.borderColor;
    if (role == "error") return m_currentTheme.errorColor;
    if (role == "warning") return m_currentTheme.warningColor;
    if (role == "success") return m_currentTheme.successColor;
    if (role == "info") return m_currentTheme.infoColor;
    return QColor();
}

void ThemeManager::setColor(const QString& role, const QColor& color)
{
    if (role == "primary") m_currentTheme.primaryColor = color;
    else if (role == "secondary") m_currentTheme.secondaryColor = color;
    else if (role == "accent") m_currentTheme.accentColor = color;
    else if (role == "background") m_currentTheme.backgroundColor = color;
    else if (role == "surface") m_currentTheme.surfaceColor = color;
    else if (role == "text") m_currentTheme.textColor = color;
    else if (role == "textSecondary") m_currentTheme.textSecondaryColor = color;
    else if (role == "border") m_currentTheme.borderColor = color;
    else if (role == "error") m_currentTheme.errorColor = color;
    else if (role == "warning") m_currentTheme.warningColor = color;
    else if (role == "success") m_currentTheme.successColor = color;
    else if (role == "info") m_currentTheme.infoColor = color;

    emit colorChanged(role, color);
}

QColor ThemeManager::getSeverityColor(const QString& severity)
{
    if (severity == "critical") return m_currentTheme.criticalColor;
    if (severity == "high") return m_currentTheme.highColor;
    if (severity == "medium") return m_currentTheme.mediumColor;
    if (severity == "low") return m_currentTheme.lowColor;
    return m_currentTheme.infoColor;
}

QColor ThemeManager::getStatusColor(const QString& status)
{
    if (status == "error" || status == "danger") return m_currentTheme.errorColor;
    if (status == "warning") return m_currentTheme.warningColor;
    if (status == "success") return m_currentTheme.successColor;
    if (status == "info") return m_currentTheme.infoColor;
    return m_currentTheme.primaryColor;
}

QFont ThemeManager::getFont(const QString& role)
{
    if (role == "title") return m_currentTheme.titleFont;
    return m_currentTheme.defaultFont;
}

void ThemeManager::setFont(const QString& role, const QFont& font)
{
    if (role == "title") m_currentTheme.titleFont = font;
    else m_currentTheme.defaultFont = font;
}

void ThemeManager::setDefaultFontFamily(const QString& family)
{
    m_currentTheme.defaultFont.setFamily(family);
    m_currentTheme.titleFont.setFamily(family);
}

void ThemeManager::setDefaultFontSize(int size)
{
    m_currentTheme.defaultFont.setPointSize(size);
}

QString ThemeManager::generateStyleSheet()
{
    return buildStyleSheet(m_currentTheme);
}

QString ThemeManager::generateDarkStyleSheet()
{
    return buildStyleSheet(m_themes[1]); // Dark theme
}

QString ThemeManager::generateLightStyleSheet()
{
    return buildStyleSheet(m_themes[2]); // Light theme
}

bool ThemeManager::applyStyleSheet(const QString& styleSheet)
{
    QApplication::setStyleSheet(styleSheet);
    emit styleSheetChanged(styleSheet);
    return true;
}

void ThemeManager::reloadStyleSheet()
{
    applyStyleSheet(buildStyleSheet(m_currentTheme));
}

void ThemeManager::setAnimationsEnabled(bool enabled)
{
    m_animationsEnabled = enabled;
}

bool ThemeManager::animationsEnabled() const
{
    return m_animationsEnabled;
}

void ThemeManager::setIconTheme(const QString& themeName)
{
    m_iconTheme = themeName;
}

QString ThemeManager::currentIconTheme() const
{
    return m_iconTheme;
}

QString ThemeManager::buildStyleSheet(const Theme& theme)
{
    QString ss;

    // 通用样式
    ss += QString(R"(
        /* 全局样式 */
        * {
            font-family: '%1';
            font-size: %2pt;
        }
        QMainWindow, QWidget {
            background-color: %3;
            color: %4;
        }
        QWidget:disabled {
            color: %5;
        }
        QToolTip {
            background-color: %6;
            color: %4;
            border: 1px solid %7;
            border-radius: 4px;
            padding: 5px;
        }
        /* 菜单栏 */
        QMenuBar {
            background-color: %6;
            color: %4;
            border-bottom: 1px solid %7;
        }
        QMenuBar::item:selected {
            background-color: %8;
        }
        /* 菜单 */
        QMenu {
            background-color: %6;
            color: %4;
            border: 1px solid %7;
            border-radius: 4px;
        }
        QMenu::item:selected {
            background-color: %8;
        }
        /* 按钮 */
        QPushButton {
            background-color: %8;
            color: white;
            border: none;
            border-radius: 4px;
            padding: 8px 16px;
            min-width: 80px;
        }
        QPushButton:hover {
            background-color: %9;
        }
        QPushButton:pressed {
            background-color: %10;
        }
        QPushButton:disabled {
            background-color: %11;
            color: %12;
        }
        /* 输入框 */
        QLineEdit, QTextEdit, QPlainTextEdit {
            background-color: %6;
            color: %4;
            border: 1px solid %7;
            border-radius: 4px;
            padding: 6px;
            selection-background-color: %8;
        }
        QLineEdit:focus, QTextEdit:focus {
            border-color: %8;
        }
        /* 标签 */
        QLabel {
            color: %4;
        }
        /* 表格 */
        QTableWidget {
            background-color: %6;
            color: %4;
            border: 1px solid %7;
            gridline-color: %7;
        }
        QTableWidget::item:selected {
            background-color: %8;
            color: white;
        }
        QHeaderView::section {
            background-color: %13;
            color: %4;
            padding: 8px;
            border: 1px solid %7;
        }
        /* 列表 */
        QListWidget, QTreeWidget {
            background-color: %6;
            color: %4;
            border: 1px solid %7;
        }
        QListWidget::item:selected, QTreeWidget::item:selected {
            background-color: %8;
        }
        /* 选项卡 */
        QTabWidget::pane {
            border: 1px solid %7;
            background-color: %6;
        }
        QTabBar::tab {
            background-color: %13;
            color: %4;
            padding: 8px 16px;
            border: 1px solid %7;
            border-bottom: none;
        }
        QTabBar::tab:selected {
            background-color: %6;
            border-bottom: 2px solid %8;
        }
        /* 进度条 */
        QProgressBar {
            background-color: %13;
            border: 1px solid %7;
            border-radius: 4px;
            text-align: center;
            color: %4;
        }
        QProgressBar::chunk {
            background-color: %8;
            border-radius: 2px;
        }
        /* 滚动条 */
        QScrollBar:vertical, QScrollBar:horizontal {
            background-color: %13;
            width: 12px;
            height: 12px;
        }
        QScrollBar::handle {
            background-color: %7;
            border-radius: 6px;
            min-height: 20px;
        }
        QScrollBar::handle:hover {
            background-color: %8;
        }
        QScrollBar::add-line, QScrollBar::sub-line {
            background: none;
            border: none;
        }
        /* 组合框 */
        QComboBox {
            background-color: %6;
            color: %4;
            border: 1px solid %7;
            border-radius: 4px;
            padding: 6px 12px;
        }
        QComboBox::drop-down {
            border: none;
            width: 20px;
        }
        QComboBox::down-arrow {
            image: none;
            border-left: 5px solid transparent;
            border-right: 5px solid transparent;
            border-top: 5px solid %4;
        }
        /* 复选框和单选框 */
        QCheckBox, QRadioButton {
            color: %4;
        }
        QCheckBox::indicator, QRadioButton::indicator {
            width: 18px;
            height: 18px;
        }
        QCheckBox::indicator:checked {
            background-color: %8;
            border: 2px solid %8;
        }
        /* 分组框 */
        QGroupBox {
            color: %4;
            border: 1px solid %7;
            border-radius: 4px;
            margin-top: 10px;
            padding-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px;
        }
        /* 工具箱 */
        QToolBox::tab {
            background-color: %13;
            color: %4;
            padding: 8px;
            border: 1px solid %7;
        }
        QToolBox::tab:selected {
            background-color: %6;
            color: %8;
        }
        /* 状态栏 */
        QStatusBar {
            background-color: %13;
            color: %4;
        }
        /* 停靠窗口 */
        QDockWidget {
            color: %4;
        }
        QDockWidget::title {
            background-color: %13;
            padding: 6px;
            border: 1px solid %7;
        }
        /* 工具栏 */
        QToolBar {
            background-color: %13;
            border-bottom: 1px solid %7;
            spacing: 4px;
            padding: 4px;
        }
        QToolBar::separator {
            background-color: %7;
            width: 1px;
            height: 1px;
        }
    )").arg(theme.defaultFont.family())
      .arg(theme.defaultFont.pointSize())
      .arg(theme.backgroundColor.name())
      .arg(theme.textColor.name())
      .arg(theme.textSecondaryColor.name())
      .arg(theme.surfaceColor.name())
      .arg(theme.borderColor.name())
      .arg(theme.primaryColor.name())
      .arg(theme.secondaryColor.name())
      .arg(theme.accentColor.name())
      .arg(theme.backgroundColor.darker(150).name())
      .arg(theme.textSecondaryColor.name())
      .arg(theme.backgroundColor.lighter(105).name());

    return ss;
}
