#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QTimer>

#include "SystemInfoTab.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    // 菜单动作
    void on_actionAbout_triggered();
    void on_actionSettings_triggered();
    void on_actionExit_triggered();
    void on_actionHelp_triggered();

    // 系统信息
    void on_btnRefreshSystemInfo_clicked();
    void on_btnExportSystemInfo_clicked();

    // 威胁检测
    void on_btnStartScan_clicked();
    void on_btnStopScan_clicked();
    void on_tableWidgetThreats_cellClicked(int row, int column);

    // 日志分析
    void on_btnAnalyzeLog_clicked();
    void on_comboBoxLogType_currentIndexChanged(const QString &text);
    void on_lineEditKeyword_textChanged(const QString &text);

    // 网络分析
    void on_btnRefreshNetwork_clicked();
    void on_btnPortScan_clicked();
    void on_tableWidgetNetwork_cellClicked(int row, int column);

    // 文件分析
    void on_btnSelectDir_clicked();
    void on_btnStartFileScan_clicked();
    void on_tableWidgetFiles_cellClicked(int row, int column);

    // 取证
    void on_btnMemoryDump_clicked();
    void on_btnRegistryExport_clicked();
    void on_btnProcessDump_clicked();
    void on_btnTimelineAnalysis_clicked();
    void on_btnBrowserHistory_clicked();
    void on_btnUSBHistory_clicked();

    // WebShell检测
    void on_btnSelectWebDir_clicked();
    void on_btnStartWebShellScan_clicked();
    void on_comboBoxTool_currentIndexChanged(const QString &text);
    void on_tableWidgetWebShell_cellClicked(int row, int column);

    // 第三方工具
    void on_btnToolProcessExp_clicked();
    void on_btnToolAutoruns_clicked();
    void on_btnToolPCHunter_clicked();
    void on_btnToolWireshark_clicked();
    void on_btnToolNmap_clicked();
    void on_btnToolVolatility_clicked();

    // 报告
    void on_btnGeneratePDF_clicked();
    void on_btnGenerateHTML_clicked();
    void on_btnExportData_clicked();

    // 定时更新
    void updateRealTimeStatus();
    void on_btnQuickScan_clicked();
    void on_btnRealTimeMonitor_toggled(bool checked);

    // Tab切换
    void on_tabWidget_currentChanged(int index);

private:
    Ui::MainWindow *ui;

    // 系统组件
    QSystemTrayIcon *m_systemTray;
    QMenu *m_trayMenu;
    QTimer *m_statusUpdateTimer;

    // Tab组件
    SystemInfoTab *m_systemInfoTab;

    // 当前会话ID
    int m_currentSessionId;

    // 状态
    bool m_isScanning;
    bool m_isMonitoring;

    // 初始化方法
    void setupUi();
    void createMenuBar();
    void createToolBar();
    void createStatusBar();
    void createDockPanels();
    void createSystemTray();
    void connectSignals();
    void initTables();

    // 系统信息
    void collectSystemInfo();
    void updateSystemInfoDisplay();

    // 威胁检测
    void startThreatScan();
    void stopThreatScan();
    void updateThreatResults();

    // 日志分析
    void analyzeLogs();
    void filterLogs(const QString &keyword);

    // 网络分析
    void collectNetworkConnections();
    void updateNetworkDisplay();
    void performPortScan();

    // 文件分析
    void selectScanDirectory();
    void startFileScan();
    void updateFileDisplay();

    // WebShell检测
    void selectWebDirectory();
    void startWebShellScan();
    void updateWebShellDisplay();

    // 取证
    void acquireMemory();
    void exportRegistry();
    void dumpProcess();
    void analyzeTimeline();
    void collectBrowserHistory();
    void collectUSBHistory();
    void updateForensicsOutput(const QString &output);

    // 第三方工具
    void launchTool(const QString &toolName, const QString &toolPath);
    void checkToolAvailability();

    // 报告生成
    void generatePDFReport();
    void generateHTMLReport();
    void exportAllData();

    // 辅助方法
    void showMessage(const QString &title, const QString &message, QSystemTrayIcon::MessageIcon icon = QSystemTrayIcon::Information);
    void logToOutput(const QString &message);
    void updateStatusBar(const QString &message);
    bool confirmAction(const QString &title, const QString &message);

    // 菜单动作
    QAction *m_actionAbout;
    QAction *m_actionSettings;
    QAction *m_actionExit;
    QAction *m_actionHelp;
    QAction *m_actionQuickScan;
    QAction *m_actionRealTimeMonitor;
    QAction *m_actionGenerateReport;
};
#endif // MAINWINDOW_H
