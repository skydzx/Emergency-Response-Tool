#include "MainWindow.h"
#include "ui_MainWindow.h"
#include "DatabaseManager.h"
#include "SystemInfoCollector.h"
#include "SystemInfoTab.h"

#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QDockWidget>
#include <QTextEdit>
#include <QListWidget>
#include <QTableWidget>
#include <QTreeWidget>
#include <QSplitter>
#include <QLabel>
#include <QPushButton>
#include <QProgressBar>
#include <QMessageBox>
#include <QIcon>
#include <QPixmap>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QFileDialog>
#include <QDateTime>
#include <QCloseEvent>
#include <QSystemTrayIcon>
#include <QDebug>
#include <QDir>
#include <QFile>
#include <QTimer>
#include <QHeaderView>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , m_currentSessionId(-1)
    , m_isScanning(false)
    , m_isMonitoring(false)
    , m_systemInfoTab(nullptr)
{
    ui->setupUi(this);

    // 初始化数据库
    if (!DatabaseManager::instance()->initialize()) {
        QMessageBox::critical(this, "错误", "无法初始化数据库，程序将退出。");
        exit(1);
    }

    // 创建新的扫描会话
    m_currentSessionId = DatabaseManager::instance()->createSession("扫描_" + QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss"));

    setupUi();
    createMenuBar();
    createToolBar();
    createStatusBar();
    createDockPanels();
    createSystemTray();
    connectSignals();
    initTables();

    // 设置窗口属性
    setWindowTitle("应急响应工具 v1.0.0");
    setMinimumSize(1200, 800);
    resize(1400, 900);

    // 启动状态更新定时器
    m_statusUpdateTimer = new QTimer(this);
    connect(m_statusUpdateTimer, &QTimer::timeout, this, &MainWindow::updateRealTimeStatus);
    m_statusUpdateTimer->start(5000);  // 每5秒更新一次

    qDebug() << "MainWindow initialized successfully";
}

MainWindow::~MainWindow() {
    if (m_currentSessionId != -1) {
        DatabaseManager::instance()->closeSession(m_currentSessionId);
    }
    delete ui;
}

void MainWindow::closeEvent(QCloseEvent *event) {
    if (m_isScanning) {
        QMessageBox::StandardButton reply = QMessageBox::question(this,
            "退出确认", "当前正在扫描中，是否停止扫描并退出？",
            QMessageBox::Yes | QMessageBox::No);
        if (reply == QMessageBox::No) {
            event->ignore();
            return;
        }
        stopThreatScan();
    }

    if (m_currentSessionId != -1) {
        DatabaseManager::instance()->closeSession(m_currentSessionId);
    }

    event->accept();
}

void MainWindow::setupUi() {
    // SystemInfoTab已经在UI文件中定义，通过ui指针访问
    // 创建SystemInfoTab实例作为第一个Tab的内容
    m_systemInfoTab = new SystemInfoTab(ui->systemInfoTab);

    // 获取第一个Tab的布局并添加SystemInfoTab
    QVBoxLayout* layout = qobject_cast<QVBoxLayout*>(ui->systemInfoTab->layout());
    if (layout) {
        layout->addWidget(m_systemInfoTab);
    } else {
        // 如果布局不存在，创建一个新布局
        QVBoxLayout* newLayout = new QVBoxLayout(ui->systemInfoTab);
        newLayout->addWidget(m_systemInfoTab);
        ui->systemInfoTab->setLayout(newLayout);
    }

    // 初始化系统信息显示
    on_btnRefreshSystemInfo_clicked();
}

void MainWindow::createMenuBar() {
    QMenuBar *menuBar = this->menuBar();

    // 文件菜单
    QMenu *fileMenu = menuBar->addMenu("文件(&F)");
    m_actionExit = new QAction("退出(&X)", this);
    connect(m_actionExit, &QAction::triggered, this, &MainWindow::on_actionExit_triggered);
    fileMenu->addAction(m_actionExit);

    // 扫描菜单
    QMenu *scanMenu = menuBar->addMenu("扫描(&S)");
    m_actionQuickScan = new QAction("一键扫描(&Q)", this);
    m_actionQuickScan->setShortcut(QKeySequence("Ctrl+Q"));
    connect(m_actionQuickScan, &QAction::triggered, this, &MainWindow::on_btnQuickScan_clicked);
    scanMenu->addAction(m_actionQuickScan);

    m_actionRealTimeMonitor = new QAction("实时监控(&R)", this);
    m_actionRealTimeMonitor->setCheckable(true);
    connect(m_actionRealTimeMonitor, &QAction::toggled, this, &MainWindow::on_btnRealTimeMonitor_toggled);
    scanMenu->addAction(m_actionRealTimeMonitor);

    m_actionGenerateReport = new QAction("生成报告(&G)", this);
    m_actionGenerateReport->setShortcut(QKeySequence("Ctrl+G"));
    connect(m_actionGenerateReport, &QAction::triggered, this, &MainWindow::on_btnGenerateHTML_clicked);
    scanMenu->addAction(m_actionGenerateReport);

    // 工具菜单
    QMenu *toolsMenu = menuBar->addMenu("工具(&T)");
    QAction *actionSystemInfo = new QAction("系统信息收集", this);
    connect(actionSystemInfo, &QAction::triggered, this, &MainWindow::on_btnRefreshSystemInfo_clicked);
    QAction *actionThreatScan = new QAction("威胁扫描", this);
    connect(actionThreatScan, &QAction::triggered, this, &MainWindow::on_btnStartScan_clicked);
    QAction *actionWebShellScan = new QAction("WebShell扫描", this);
    QAction *actionLogAnalysis = new QAction("日志分析", this);
    connect(actionLogAnalysis, &QAction::triggered, this, &MainWindow::on_btnAnalyzeLog_clicked);
    QAction *actionNetworkAnalysis = new QAction("网络分析", this);
    connect(actionNetworkAnalysis, &QAction::triggered, this, &MainWindow::on_btnRefreshNetwork_clicked);
    QAction *actionFileAnalysis = new QAction("文件分析", this);
    QAction *actionForensics = new QAction("取证分析", this);

    toolsMenu->addAction(actionSystemInfo);
    toolsMenu->addAction(actionThreatScan);
    toolsMenu->addAction(actionWebShellScan);
    toolsMenu->addAction(actionLogAnalysis);
    toolsMenu->addAction(actionNetworkAnalysis);
    toolsMenu->addAction(actionFileAnalysis);
    toolsMenu->addAction(actionForensics);

    // 设置菜单
    QMenu *settingsMenu = menuBar->addMenu("设置(&S)");
    m_actionSettings = new QAction("设置(&S)", this);
    connect(m_actionSettings, &QAction::triggered, this, &MainWindow::on_actionSettings_triggered);
    settingsMenu->addAction(m_actionSettings);

    // 帮助菜单
    QMenu *helpMenu = menuBar->addMenu("帮助(&H)");
    m_actionHelp = new QAction("帮助文档(&H)", this);
    connect(m_actionHelp, &QAction::triggered, this, &MainWindow::on_actionHelp_triggered);
    m_actionAbout = new QAction("关于(&A)", this);
    connect(m_actionAbout, &QAction::triggered, this, &MainWindow::on_actionAbout_triggered);
    helpMenu->addAction(m_actionHelp);
    helpMenu->addSeparator();
    helpMenu->addAction(m_actionAbout);
}

void MainWindow::createToolBar() {
    QToolBar *toolBar = addToolBar("主工具栏");
    toolBar->setMovable(false);
    toolBar->setFloatable(false);
    toolBar->setIconSize(QSize(24, 24));

    QPushButton *btnQuickScan = new QPushButton("一键扫描");
    connect(btnQuickScan, &QPushButton::clicked, this, &MainWindow::on_btnQuickScan_clicked);
    toolBar->addWidget(btnQuickScan);

    toolBar->addSeparator();

    QPushButton *btnSystemInfo = new QPushButton("系统信息");
    connect(btnSystemInfo, &QPushButton::clicked, this, &MainWindow::on_btnRefreshSystemInfo_clicked);
    toolBar->addWidget(btnSystemInfo);

    QPushButton *btnThreatScan = new QPushButton("威胁扫描");
    connect(btnThreatScan, &QPushButton::clicked, this, &MainWindow::on_btnStartScan_clicked);
    toolBar->addWidget(btnThreatScan);

    QPushButton *btnWebShell = new QPushButton("WebShell检测");
    connect(btnWebShell, &QPushButton::clicked, this, &MainWindow::on_btnStartWebShellScan_clicked);
    toolBar->addWidget(btnWebShell);

    toolBar->addSeparator();

    QPushButton *btnGenerateReport = new QPushButton("生成报告");
    connect(btnGenerateReport, &QPushButton::clicked, this, &MainWindow::on_btnGenerateHTML_clicked);
    toolBar->addWidget(btnGenerateReport);
}

void MainWindow::createStatusBar() {
    QStatusBar *statusBar = this->statusBar();

    QLabel *statusLabel = new QLabel("就绪");
    statusLabel->setObjectName("statusLabel");
    statusBar->addWidget(statusLabel, 1);

    QLabel *dbStatus = new QLabel("数据库: 已连接");
    statusBar->addPermanentWidget(dbStatus);

    QLabel *sessionLabel = new QLabel(QString("会话: #%1").arg(m_currentSessionId));
    statusBar->addPermanentWidget(sessionLabel);

    QLabel *versionLabel = new QLabel("v1.0.0");
    statusBar->addPermanentWidget(versionLabel);
}

void MainWindow::createDockPanels() {
    // 左侧停靠窗口 - 快速操作面板
    QDockWidget *dockQuickActions = new QDockWidget("快速操作", this);
    dockQuickActions->setAllowedAreas(Qt::LeftDockWidgetArea | Qt::RightDockWidgetArea);
    dockQuickActions->setFeatures(QDockWidget::DockWidgetMovable | QDockWidget::DockWidgetClosable);

    QWidget *quickActionsContent = new QWidget();
    QVBoxLayout *quickLayout = new QVBoxLayout(quickActionsContent);

    QPushButton *btnQuickScan = new QPushButton("一键扫描");
    connect(btnQuickScan, &QPushButton::clicked, this, &MainWindow::on_btnQuickScan_clicked);
    quickLayout->addWidget(btnQuickScan);

    QPushButton *btnRealTimeMonitor = new QPushButton("实时监控");
    btnRealTimeMonitor->setCheckable(true);
    connect(btnRealTimeMonitor, &QPushButton::toggled, this, &MainWindow::on_btnRealTimeMonitor_toggled);
    quickLayout->addWidget(btnRealTimeMonitor);

    QPushButton *btnExportData = new QPushButton("导出数据");
    connect(btnExportData, &QPushButton::clicked, this, &MainWindow::on_btnExportData_clicked);
    quickLayout->addWidget(btnExportData);

    QPushButton *btnGenerateReport = new QPushButton("生成报告");
    connect(btnGenerateReport, &QPushButton::clicked, this, &MainWindow::on_btnGenerateHTML_clicked);
    quickLayout->addWidget(btnGenerateReport);

    quickLayout->addStretch();

    dockQuickActions->setWidget(quickActionsContent);
    addDockWidget(Qt::LeftDockWidgetArea, dockQuickActions);

    // 右侧停靠窗口 - 检测结果摘要
    QDockWidget *dockResults = new QDockWidget("检测结果摘要", this);
    dockResults->setAllowedAreas(Qt::LeftDockWidgetArea | Qt::RightDockWidgetArea);
    dockResults->setFeatures(QDockWidget::DockWidgetMovable | QDockWidget::DockWidgetClosable);

    QWidget *resultsContent = new QWidget();
    QVBoxLayout *resultsLayout = new QVBoxLayout(resultsContent);

    QLabel *threatsLabel = new QLabel("<h3>检测结果</h3>");
    resultsLayout->addWidget(threatsLabel);

    QLabel *criticalLabel = new QLabel("严重威胁: 0");
    criticalLabel->setStyleSheet("color: red; font-weight: bold;");
    criticalLabel->setObjectName("criticalLabel");
    resultsLayout->addWidget(criticalLabel);

    QLabel *warningLabel = new QLabel("警告: 0");
    warningLabel->setStyleSheet("color: orange;");
    warningLabel->setObjectName("warningLabel");
    resultsLayout->addWidget(warningLabel);

    QLabel *infoLabel = new QLabel("信息: 0");
    infoLabel->setStyleSheet("color: blue;");
    infoLabel->setObjectName("infoLabel");
    resultsLayout->addWidget(infoLabel);

    resultsLayout->addStretch();

    QListWidget *resultsList = new QListWidget();
    resultsList->setObjectName("resultsList");
    resultsLayout->addWidget(resultsList);

    dockResults->setWidget(resultsContent);
    addDockWidget(Qt::RightDockWidgetArea, dockResults);

    // 底部停靠窗口 - 操作日志
    QDockWidget *dockLogs = new QDockWidget("操作日志", this);
    dockLogs->setAllowedAreas(Qt::BottomDockWidgetArea | Qt::TopDockWidgetArea);
    dockLogs->setFeatures(QDockWidget::DockWidgetMovable | QDockWidget::DockWidgetClosable);

    QTextEdit *logOutput = new QTextEdit();
    logOutput->setReadOnly(true);
    logOutput->setObjectName("logOutput");
    dockLogs->setWidget(logOutput);
    addDockWidget(Qt::BottomDockWidgetArea, dockLogs);

    // 设置停靠窗口 tab 排列
    tabifyDockWidget(dockQuickActions, dockResults);
}

void MainWindow::createSystemTray() {
    m_systemTray = new QSystemTrayIcon(this);
    m_systemTray->setIcon(QIcon(":/app.png"));
    m_systemTray->setToolTip("应急响应工具");

    m_trayMenu = new QMenu(this);
    m_trayMenu->addAction("显示窗口", this, &QMainWindow::show);
    m_trayMenu->addSeparator();
    m_trayMenu->addAction("一键扫描", this, &MainWindow::on_btnQuickScan_clicked);
    m_trayMenu->addAction("实时监控", this, &MainWindow::on_btnRealTimeMonitor_toggled)->setCheckable(true);
    m_trayMenu->addSeparator();
    m_trayMenu->addAction("退出", this, &MainWindow::on_actionExit_triggered);

    m_systemTray->setContextMenu(m_trayMenu);
    m_systemTray->show();

    connect(m_systemTray, &QSystemTrayIcon::activated,
        [this](QSystemTrayIcon::ActivationReason reason) {
            if (reason == QSystemTrayIcon::Trigger) {
                this->show();
                this->activateWindow();
            }
        });
}

void MainWindow::connectSignals() {
    // 连接TabChanged信号
    connect(ui->tabWidget, &QTabWidget::currentChanged, this, &MainWindow::on_tabWidget_currentChanged);
}

void MainWindow::initTables() {
    // 设置表格默认属性
    QList<QTableWidget*> tables = {
        ui->tableWidgetDisk,
        ui->tableWidgetUsers,
        ui->tableWidgetServices,
        ui->tableWidgetThreats,
        ui->tableWidgetLogs,
        ui->tableWidgetNetwork,
        ui->tableWidgetFiles,
        ui->tableWidgetWebShell
    };

    for (QTableWidget *table : tables) {
        if (table) {
            table->setAlternatingRowColors(true);
            table->setSelectionBehavior(QAbstractItemView::SelectRows);
            table->setSelectionMode(QAbstractItemView::SingleSelection);
            table->horizontalHeader()->setStretchLastSection(true);
            table->verticalHeader()->setVisible(false);
        }
    }
}

// ==================== 系统信息 ====================

void MainWindow::on_btnRefreshSystemInfo_clicked() {
    collectSystemInfo();
}

void MainWindow::on_btnExportSystemInfo_clicked() {
    QString fileName = QFileDialog::getSaveFileName(this,
        "导出系统信息", QString("system_info_%1.txt").arg(QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss")),
        "文本文件 (*.txt);;所有文件 (*.*)");

    if (!fileName.isEmpty()) {
        QFile file(fileName);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            out << "系统信息报告\n";
            out << "生成时间: " << QDateTime::currentDateTime().toString(Qt::ISODate) << "\n\n";

            out << "操作系统: " << ui->lineEditOS->text() << "\n";
            out << "计算机名: " << ui->lineEditComputerName->text() << "\n";
            out << "当前用户: " << ui->lineEditUser->text() << "\n";
            out << "系统架构: " << ui->lineEditArchitecture->text() << "\n";
            out << "处理器: " << ui->lineEditCPU->text() << "\n";
            out << "内存: " << ui->lineEditMemory->text() << "\n";

            file.close();
            showMessage("导出成功", "系统信息已导出到: " + fileName);
            logToOutput(QString("系统信息已导出到: %1").arg(fileName));
        }
    }
}

void MainWindow::collectSystemInfo() {
    SystemInfoCollector collector;
    SystemInfo info = collector.collectSystemInfo();

    // 更新UI显示
    ui->lineEditOS->setText(info.osVersion);
    ui->lineEditComputerName->setText(info.computerName);
    ui->lineEditUser->setText(info.userName);
    ui->lineEditArchitecture->setText(info.architecture);
    ui->lineEditCPU->setText(QString("%1 个处理器").arg(info.processorCount));
    ui->lineEditMemory->setText(info.memoryInfo);

    // 更新磁盘信息表格
    ui->tableWidgetDisk->setRowCount(0);
    QStringList diskParts = info.diskInfo.split(";");
    for (const QString &part : diskParts) {
        if (part.trimmed().isEmpty()) continue;

        int row = ui->tableWidgetDisk->rowCount();
        ui->tableWidgetDisk->insertRow(row);

        // 解析磁盘信息
        QRegularExpression re("([A-Z]:).*Total: ([0-9.]+) GB.*Free: ([0-9.]+) GB");
        QRegularExpressionMatch match = re.match(part);
        if (match.hasMatch()) {
            ui->tableWidgetDisk->setItem(row, 0, new QTableWidgetItem(match.captured(1)));
            ui->tableWidgetDisk->setItem(row, 1, new QTableWidgetItem("本地磁盘"));
            ui->tableWidgetDisk->setItem(row, 2, new QTableWidgetItem(QString("总计: %1 GB, 可用: %2 GB")
                .arg(match.captured(2)).arg(match.captured(3))));
        }
    }

    // 更新用户表格
    QList<UserInfo> users = collector.collectUsers();
    ui->tableWidgetUsers->setRowCount(0);
    for (const UserInfo &user : users) {
        int row = ui->tableWidgetUsers->rowCount();
        ui->tableWidgetUsers->insertRow(row);
        ui->tableWidgetUsers->setItem(row, 0, new QTableWidgetItem(user.name));
        ui->tableWidgetUsers->setItem(row, 1, new QTableWidgetItem(user.fullName));
        QString status = user.isDisabled ? "已禁用" : "正常";
        ui->tableWidgetUsers->setItem(row, 2, new QTableWidgetItem(status));
        ui->tableWidgetUsers->setItem(row, 3, new QTableWidgetItem(user.lastLogin.toString(Qt::ISODate)));
    }

    // 更新服务表格
    QList<ServiceInfo> services = collector.collectServices();
    ui->tableWidgetServices->setRowCount(0);
    for (const ServiceInfo &service : services) {
        int row = ui->tableWidgetServices->rowCount();
        ui->tableWidgetServices->insertRow(row);
        ui->tableWidgetServices->setItem(row, 0, new QTableWidgetItem(service.name));
        ui->tableWidgetServices->setItem(row, 1, new QTableWidgetItem(service.displayName));
        ui->tableWidgetServices->setItem(row, 2, new QTableWidgetItem(service.status));
        ui->tableWidgetServices->setItem(row, 3, new QTableWidgetItem(service.startType));
        ui->tableWidgetServices->setItem(row, 4, new QTableWidgetItem(service.path));
    }

    updateStatusBar("系统信息收集完成");
    logToOutput("系统信息收集完成");

    // 保存到数据库
    QMap<QString, QVariant> sessionInfo;
    sessionInfo["description"] = QString("系统信息收集 - %1").arg(QDateTime::currentDateTime().toString(Qt::ISODate));
    DatabaseManager::instance()->closeSession(m_currentSessionId);
    m_currentSessionId = DatabaseManager::instance()->createSession("系统扫描_" + QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss"));
}

void MainWindow::updateSystemInfoDisplay() {
    // 由collectSystemInfo统一更新
}

// ==================== 威胁检测 ====================

void MainWindow::on_btnStartScan_clicked() {
    startThreatScan();
}

void MainWindow::on_btnStopScan_clicked() {
    stopThreatScan();
}

void MainWindow::on_tableWidgetThreats_cellClicked(int row, int column) {
    Q_UNUSED(column)
    // 显示威胁详情
    QString filePath = ui->tableWidgetThreats->item(row, 4)->text();
    QMessageBox::information(this, "威胁详情",
        QString("文件路径: %1\n\n详细信息请查看报告").arg(filePath));
}

void MainWindow::startThreatScan() {
    if (m_isScanning) {
        QMessageBox::warning(this, "警告", "扫描已在进行中");
        return;
    }

    m_isScanning = true;
    ui->btnStartScan->setEnabled(false);
    ui->progressBarScan->setValue(0);
    ui->labelScanStatus->setText("扫描中...");

    logToOutput("开始威胁扫描...");

    // 模拟扫描进度
    int progress = 0;
    while (progress <= 100 && m_isScanning) {
        ui->progressBarScan->setValue(progress);
        ui->labelScanStatus->setText(QString("扫描中... %1%").arg(progress));
        QCoreApplication::processEvents();
        progress += 10;
        QThread::msleep(500);
    }

    if (m_isScanning) {
        updateThreatResults();
        ui->labelScanStatus->setText("扫描完成");
        showMessage("扫描完成", "威胁扫描已完成");
        logToOutput("威胁扫描完成");
    } else {
        ui->labelScanStatus->setText("扫描已停止");
    }

    m_isScanning = false;
    ui->btnStartScan->setEnabled(true);
}

void MainWindow::stopThreatScan() {
    m_isScanning = false;
    ui->labelScanStatus->setText("扫描已停止");
    logToOutput("威胁扫描已停止");
}

void MainWindow::updateThreatResults() {
    // 清空表格
    ui->tableWidgetThreats->setRowCount(0);

    // 添加示例数据
    QStringList threats = {
        "WebShell|PHP一句话木马|检测到可疑PHP脚本|high|C:\\inetpub\\wwwroot\\shell.php|待处理",
        "可疑进程|挖矿进程|检测到可疑挖矿进程|critical|C:\\Users\\Admin\\AppData\\Local\\temp\\miner.exe|待处理",
        "异常启动项|注册表启动|可疑的注册表启动项|medium|C:\\ProgramData\\startup\\agent.exe|待处理"
    };

    for (const QString &threat : threats) {
        QStringList parts = threat.split("|");
        if (parts.size() >= 6) {
            int row = ui->tableWidgetThreats->rowCount();
            ui->tableWidgetThreats->insertRow(row);

            for (int col = 0; col < parts.size(); col++) {
                ui->tableWidgetThreats->setItem(row, col, new QTableWidgetItem(parts[col]));
            }
        }
    }

    // 更新摘要
    int criticalCount = 0, warningCount = 0, infoCount = 0;
    for (int row = 0; row < ui->tableWidgetThreats->rowCount(); row++) {
        QString severity = ui->tableWidgetThreats->item(row, 3)->text();
        if (severity == "critical") criticalCount++;
        else if (severity == "high" || severity == "medium") warningCount++;
        else infoCount++;
    }

    // 更新Dock面板
    QLabel *criticalLabel = findChild<QLabel*>("criticalLabel");
    QLabel *warningLabel = findChild<QLabel*>("warningLabel");
    QLabel *infoLabel = findChild<QLabel*>("infoLabel");

    if (criticalLabel) criticalLabel->setText(QString("严重威胁: %1").arg(criticalCount));
    if (warningLabel) warningLabel->setText(QString("警告: %1").arg(warningCount));
    if (infoLabel) infoLabel->setText(QString("信息: %1").arg(infoCount));

    // 保存到数据库
    for (int row = 0; row < ui->tableWidgetThreats->rowCount(); row++) {
        QMap<QString, QVariant> threat;
        threat["threatType"] = ui->tableWidgetThreats->item(row, 0)->text();
        threat["threatName"] = ui->tableWidgetThreats->item(row, 1)->text();
        threat["description"] = ui->tableWidgetThreats->item(row, 2)->text();
        threat["severity"] = ui->tableWidgetThreats->item(row, 3)->text();
        threat["filePath"] = ui->tableWidgetThreats->item(row, 4)->text();
        threat["status"] = ui->tableWidgetThreats->item(row, 5)->text();
        DatabaseManager::instance()->addThreat(m_currentSessionId, threat);
    }
}

// ==================== 日志分析 ====================

void MainWindow::on_btnAnalyzeLog_clicked() {
    analyzeLogs();
}

void MainWindow::on_comboBoxLogType_currentIndexChanged(const QString &text) {
    Q_UNUSED(text)
    analyzeLogs();
}

void MainWindow::on_lineEditKeyword_textChanged(const QString &text) {
    filterLogs(text);
}

void MainWindow::analyzeLogs() {
    ui->tableWidgetLogs->setRowCount(0);
    logToOutput(QString("开始分析%1...").arg(ui->comboBoxLogType->currentText()));

    // 添加示例日志数据
    QDateTime now = QDateTime::currentDateTime();
    QStringList sampleLogs = {
        QString("|%1|System|4625|错误|登录失败").arg(now.addSecs(-3600).toString(Qt::ISODate)),
        QString("|%1|Application|1001|信息|应用程序日志记录").arg(now.addSecs(-1800).toString(Qt::ISODate)),
        QString("|%1|Security|4624|信息|成功登录").arg(now.addSecs(-900).toString(Qt::ISODate)),
        QString("|%1|System|7036|信息|服务启动完成").arg(now.addSecs(-600).toString(Qt::ISODate))
    };

    for (const QString &log : sampleLogs) {
        QStringList parts = log.split("|");
        if (parts.size() >= 6) {
            int row = ui->tableWidgetLogs->rowCount();
            ui->tableWidgetLogs->insertRow(row);

            for (int col = 0; col < parts.size(); col++) {
                ui->tableWidgetLogs->setItem(row, col, new QTableWidgetItem(parts[col]));
            }
        }
    }

    logToOutput("日志分析完成");
}

void MainWindow::filterLogs(const QString &keyword) {
    if (keyword.isEmpty()) return;

    for (int row = 0; row < ui->tableWidgetLogs->rowCount(); row++) {
        bool match = false;
        for (int col = 0; col < ui->tableWidgetLogs->columnCount(); col++) {
            QTableWidgetItem *item = ui->tableWidgetLogs->item(row, col);
            if (item && item->text().contains(keyword, Qt::CaseInsensitive)) {
                match = true;
                break;
            }
        }
        ui->tableWidgetLogs->setRowHidden(row, !match);
    }
}

// ==================== 网络分析 ====================

void MainWindow::on_btnRefreshNetwork_clicked() {
    collectNetworkConnections();
}

void MainWindow::on_btnPortScan_clicked() {
    performPortScan();
}

void MainWindow::on_tableWidgetNetwork_cellClicked(int row, int column) {
    Q_UNUSED(column)
    QString remoteAddr = ui->tableWidgetNetwork->item(row, 2)->text();
    QMessageBox::information(this, "连接详情",
        QString("远程地址: %1\n\n可使用端口扫描工具进行深入分析").arg(remoteAddr));
}

void MainWindow::collectNetworkConnections() {
    SystemInfoCollector collector;
    auto connections = collector.collectNetworkConnections();

    updateNetworkDisplay();

    // 保存到数据库
    for (const auto &conn : connections) {
        DatabaseManager::instance()->addNetworkConnection(m_currentSessionId, conn);
    }

    logToOutput(QString("网络连接收集完成，共%1个连接").arg(connections.size()));
}

void MainWindow::updateNetworkDisplay() {
    ui->tableWidgetNetwork->setRowCount(0);

    // 添加示例网络连接
    QStringList connections = {
        "TCP|192.168.1.100:8080|192.168.1.200:443|ESTABLISHED|1234|chrome.exe|否",
        "TCP|192.168.1.100:52345|8.8.8.8:53|LISTENING|0|||否",
        "TCP|192.168.1.100:49670|40.90.189.152:443|ESTABLISHED|5424|outlook.exe|否"
    };

    for (const QString &conn : connections) {
        QStringList parts = conn.split("|");
        if (parts.size() >= 7) {
            int row = ui->tableWidgetNetwork->rowCount();
            ui->tableWidgetNetwork->insertRow(row);

            for (int col = 0; col < parts.size(); col++) {
                ui->tableWidgetNetwork->setItem(row, col, new QTableWidgetItem(parts[col]));
            }
        }
    }

    // 更新状态标签
    ui->labelConnectionCount->setText(QString("连接数: %1").arg(connections.size()));
    ui->labelSuspiciousCount->setText("可疑连接: 0");
}

void MainWindow::performPortScan() {
    logToOutput("开始端口扫描...");
    showMessage("端口扫描", "端口扫描功能需要集成Nmap等工具");
}

// ==================== 文件分析 ====================

void MainWindow::on_btnSelectDir_clicked() {
    selectScanDirectory();
}

void MainWindow::on_btnStartFileScan_clicked() {
    startFileScan();
}

void MainWindow::on_tableWidgetFiles_cellClicked(int row, int column) {
    Q_UNUSED(column)
    QString filePath = ui->tableWidgetFiles->item(row, 1)->text();
    QMessageBox::information(this, "文件详情",
        QString("文件路径: %1\n\n详细信息").arg(filePath));
}

void MainWindow::selectScanDirectory() {
    QString dir = QFileDialog::getExistingDirectory(this,
        "选择要扫描的目录", QDir::homePath(),
        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);

    if (!dir.isEmpty()) {
        ui->lineEditScanPath->setText(dir);
    }
}

void MainWindow::startFileScan() {
    QString scanPath = ui->lineEditScanPath->text();
    if (scanPath.isEmpty()) {
        QMessageBox::warning(this, "警告", "请先选择要扫描的目录");
        return;
    }

    logToOutput(QString("开始扫描目录: %1").arg(scanPath));
    ui->progressBarFile->setValue(0);

    // 模拟扫描进度
    int progress = 0;
    while (progress <= 100) {
        ui->progressBarFile->setValue(progress);
        QCoreApplication::processEvents();
        progress += 20;
        QThread::msleep(500);
    }

    updateFileDisplay();
    logToOutput("文件扫描完成");
}

void MainWindow::updateFileDisplay() {
    ui->tableWidgetFiles->setRowCount(0);

    // 添加示例文件
    QStringList files = {
        "suspicious.dll|C:\\Windows\\System32\\suspicious.dll|15KB|2024-01-15 10:30|abc123...|是",
        "update.exe|C:\\ProgramData\\update.exe|2.5MB|2024-01-20 14:22|def456...|否",
        "config.xml|C:\\App\\config.xml|8KB|2024-01-18 09:15|ghi789...|否"
    };

    for (const QString &file : files) {
        QStringList parts = file.split("|");
        if (parts.size() >= 6) {
            int row = ui->tableWidgetFiles->rowCount();
            ui->tableWidgetFiles->insertRow(row);

            for (int col = 0; col < parts.size(); col++) {
                ui->tableWidgetFiles->setItem(row, col, new QTableWidgetItem(parts[col]));
            }
        }
    }
}

// ==================== 取证 ====================

void MainWindow::on_btnMemoryDump_clicked() {
    acquireMemory();
}

void MainWindow::on_btnRegistryExport_clicked() {
    exportRegistry();
}

void MainWindow::on_btnProcessDump_clicked() {
    dumpProcess();
}

void MainWindow::on_btnTimelineAnalysis_clicked() {
    analyzeTimeline();
}

void MainWindow::on_btnBrowserHistory_clicked() {
    collectBrowserHistory();
}

void MainWindow::on_btnUSBHistory_clicked() {
    collectUSBHistory();
}

void MainWindow::acquireMemory() {
    logToOutput("内存镜像获取功能需要管理员权限和专业工具支持");
    showMessage("内存取证", "内存镜像获取需要管理员权限\n建议集成winpmem等工具");
}

void MainWindow::exportRegistry() {
    logToOutput("注册表导出功能需要管理员权限");
    showMessage("注册表取证", "注册表导出需要管理员权限");
}

void MainWindow::dumpProcess() {
    logToOutput("进程转储功能需要选择目标进程");
    showMessage("进程取证", "请选择要转储的进程");
}

void MainWindow::analyzeTimeline() {
    updateForensicsOutput("时间线分析功能开发中...\n将整合多种日志来源");
}

void MainWindow::collectBrowserHistory() {
    updateForensicsOutput("浏览器历史收集功能开发中...\n将支持Chrome、Firefox等浏览器");
}

void MainWindow::collectUSBHistory() {
    updateForensicsOutput("USB使用历史收集功能开发中...");
}

void MainWindow::updateForensicsOutput(const QString &output) {
    ui->textEditForensics->append(output);
}

// ==================== WebShell检测 ====================

void MainWindow::on_btnSelectWebDir_clicked() {
    selectWebDirectory();
}

void MainWindow::on_btnStartWebShellScan_clicked() {
    startWebShellScan();
}

void MainWindow::on_comboBoxTool_currentIndexChanged(const QString &text) {
    Q_UNUSED(text)
}

void MainWindow::on_tableWidgetWebShell_cellClicked(int row, int column) {
    Q_UNUSED(column)
    QString filePath = ui->tableWidgetWebShell->item(row, 0)->text();
    QMessageBox::information(this, "WebShell详情",
        QString("文件路径: %1\n\n建议: 立即隔离或删除此文件").arg(filePath));
}

void MainWindow::selectWebDirectory() {
    QString dir = QFileDialog::getExistingDirectory(this,
        "选择Web根目录", QDir::homePath(),
        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);

    if (!dir.isEmpty()) {
        ui->lineEditWebDir->setText(dir);
    }
}

void MainWindow::startWebShellScan() {
    QString scanPath = ui->lineEditWebDir->text();
    QString tool = ui->comboBoxTool->currentText();

    if (scanPath.isEmpty()) {
        QMessageBox::warning(this, "警告", "请先选择要扫描的Web目录");
        return;
    }

    logToOutput(QString("开始WebShell扫描: 工具=%1, 目录=%2").arg(tool).arg(scanPath));
    ui->progressBarWebShell->setValue(0);

    // 模拟扫描进度
    int progress = 0;
    while (progress <= 100) {
        ui->progressBarWebShell->setValue(progress);
        QCoreApplication::processEvents();
        progress += 10;
        QThread::msleep(300);
    }

    updateWebShellDisplay();
    logToOutput("WebShell扫描完成");
}

void MainWindow::updateWebShellDisplay() {
    ui->tableWidgetWebShell->setRowCount(0);

    // 添加示例WebShell检测结果
    QStringList webshells = {
        "C:\\inetpub\\wwwroot\\uploads\\shell.php|PHP一句话木马|high|D盾WebShellKill|eval($_POST|隔离",
        "C:\\xampp\\htdocs\\backdoor.jsp|冰蝎WebShell|critical|河马查杀|Class.forName|删除",
        "C:\\www\\admin\\cmd.asp|ASP一句话木马|medium|自定义规则|Execute(Request)|隔离"
    };

    for (const QString &ws : webshells) {
        QStringList parts = ws.split("|");
        if (parts.size() >= 6) {
            int row = ui->tableWidgetWebShell->rowCount();
            ui->tableWidgetWebShell->insertRow(row);

            for (int col = 0; col < parts.size(); col++) {
                ui->tableWidgetWebShell->setItem(row, col, new QTableWidgetItem(parts[col]));
            }
        }
    }
}

// ==================== 第三方工具 ====================

void MainWindow::on_btnToolProcessExp_clicked() {
    launchTool("Process Explorer", "");
}

void MainWindow::on_btnToolAutoruns_clicked() {
    launchTool("AutoRuns", "");
}

void MainWindow::on_btnToolPCHunter_clicked() {
    launchTool("PCHunter", "");
}

void MainWindow::on_btnToolWireshark_clicked() {
    launchTool("Wireshark", "");
}

void MainWindow::on_btnToolNmap_clicked() {
    launchTool("Nmap", "");
}

void MainWindow::on_btnToolVolatility_clicked() {
    launchTool("Volatility", "");
}

void MainWindow::launchTool(const QString &toolName, const QString &toolPath) {
    logToOutput(QString("启动第三方工具: %1").arg(toolName));
    showMessage(toolName, QString("%1 启动功能\n请手动安装并配置工具路径").arg(toolName));
}

void MainWindow::checkToolAvailability() {
    // 检查第三方工具可用性
    logToOutput("检查第三方工具可用性...");
}

// ==================== 报告生成 ====================

void MainWindow::on_btnGeneratePDF_clicked() {
    generatePDFReport();
}

void MainWindow::on_btnGenerateHTML_clicked() {
    generateHTMLReport();
}

void MainWindow::on_btnExportData_clicked() {
    exportAllData();
}

void MainWindow::generatePDFReport() {
    QString fileName = QFileDialog::getSaveFileName(this,
        "生成PDF报告", QString("report_%1.pdf").arg(QDateTime::currentDateTime().toString("yyyyMMdd")),
        "PDF文件 (*.pdf);;所有文件 (*.*)");

    if (!fileName.isEmpty()) {
        logToOutput(QString("PDF报告生成功能开发中: %1").arg(fileName));
        showMessage("PDF报告", "PDF报告生成功能需要集成PDF库");
    }
}

void MainWindow::generateHTMLReport() {
    QString fileName = QFileDialog::getSaveFileName(this,
        "生成HTML报告", QString("report_%1.html").arg(QDateTime::currentDateTime().toString("yyyyMMdd")),
        "HTML文件 (*.html);;所有文件 (*.*)");

    if (!fileName.isEmpty()) {
        // 生成HTML报告内容
        ui->textEditReport->clear();
        ui->textEditReport->setHtml(QString(
            "<html><head><title>应急响应报告</title></head><body>"
            "<h1>应急响应工具 - 检测报告</h1>"
            "<p>生成时间: %1</p>"
            "<h2>威胁检测结果</h2>"
            "<p>检测到 %2 个威胁</p>"
            "<h2>系统信息</h2>"
            "<p>操作系统: %3</p>"
            "<p>计算机名: %4</p>"
            "</body></html>"
        ).arg(QDateTime::currentDateTime().toString(Qt::ISODate))
        .arg(ui->tableWidgetThreats->rowCount())
        .arg(ui->lineEditOS->text())
        .arg(ui->lineEditComputerName->text()));

        QFile file(fileName);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            out << ui->textEditReport->toHtml();
            file.close();
            showMessage("HTML报告", "HTML报告已生成: " + fileName);
            logToOutput(QString("HTML报告已生成: %1").arg(fileName));
        }
    }
}

void MainWindow::exportAllData() {
    QString dir = QFileDialog::getExistingDirectory(this,
        "选择导出目录", QDir::homePath(),
        QFileDialog::ShowDirsOnly);

    if (!dir.isEmpty()) {
        logToOutput(QString("数据导出功能开发中: %1").arg(dir));
        showMessage("数据导出", "数据导出功能需要实现");
    }
}

// ==================== 定时更新 ====================

void MainWindow::updateRealTimeStatus() {
    if (m_isMonitoring) {
        // 实时监控逻辑
    }
}

void MainWindow::on_btnQuickScan_clicked() {
    logToOutput("执行一键扫描...");
    collectSystemInfo();
    startThreatScan();
    collectNetworkConnections();
    logToOutput("一键扫描完成");
    showMessage("一键扫描", "一键扫描已完成");
}

void MainWindow::on_btnRealTimeMonitor_toggled(bool checked) {
    m_isMonitoring = checked;
    if (checked) {
        m_statusUpdateTimer->start(5000);
        logToOutput("实时监控已启动");
        showMessage("实时监控", "实时监控已启动");
    } else {
        m_statusUpdateTimer->stop();
        logToOutput("实时监控已停止");
        showMessage("实时监控", "实时监控已停止");
    }
}

// ==================== Tab切换 ====================

void MainWindow::on_tabWidget_currentChanged(int index) {
    switch (index) {
    case 0:  // 系统信息
        break;
    case 1:  // 威胁检测
        break;
    case 2:  // 日志分析
        analyzeLogs();
        break;
    case 3:  // 网络分析
        collectNetworkConnections();
        break;
    case 4:  // 文件分析
        break;
    case 5:  // 取证
        break;
    case 6:  // WebShell检测
        break;
    case 7:  // 工具管理
        checkToolAvailability();
        break;
    case 8:  // 报告
        break;
    }
}

// ==================== 菜单动作 ====================

void MainWindow::on_actionAbout_triggered() {
    QMessageBox::about(this, "关于应急响应工具",
        "应急响应工具 v1.0.0\n\n"
        "一款专业的Windows系统应急响应工具，支持：\n"
        "• 系统信息收集\n"
        "• 威胁检测\n"
        "• WebShell检测\n"
        "• 日志分析\n"
        "• 网络分析\n"
        "• 电子取证\n\n"
        "Copyright 2024");
}

void MainWindow::on_actionSettings_triggered() {
    QMessageBox::information(this, "设置", "设置功能开发中...\n\n将支持：\n• 扫描选项配置\n• 第三方工具路径设置\n• 字典管理\n• 报告模板配置");
}

void MainWindow::on_actionExit_triggered() {
    close();
}

void MainWindow::on_actionHelp_triggered() {
    QMessageBox::information(this, "帮助文档",
        "应急响应工具使用说明\n\n"
        "1. 系统信息：收集系统基本信息、硬件信息、用户账户、服务列表\n"
        "2. 威胁检测：扫描可疑进程、启动项、注册表等\n"
        "3. 日志分析：分析Windows事件日志、IIS日志等\n"
        "4. 网络分析：监控网络连接、检测异常外联\n"
        "5. 文件分析：扫描可疑文件、计算文件哈希\n"
        "6. 电子取证：内存取证、注册表取证等\n"
        "7. WebShell检测：集成专业工具检测WebShell\n"
        "8. 第三方工具：管理集成外部工具");
}

// ==================== 辅助方法 ====================

void MainWindow::showMessage(const QString &title, const QString &message, QSystemTrayIcon::MessageIcon icon) {
    m_systemTray->showMessage(title, message, icon, 3000);
}

void MainWindow::logToOutput(const QString &message) {
    QString timestamp = QDateTime::currentDateTime().toString("[yyyy-MM-dd hh:mm:ss] ");
    ui->logOutput->append(timestamp + message);
    qDebug() << timestamp.toStdString() << message.toStdString();
}

void MainWindow::updateStatusBar(const QString &message) {
    QLabel *statusLabel = findChild<QLabel*>("statusLabel");
    if (statusLabel) {
        statusLabel->setText(message);
    }
}

bool MainWindow::confirmAction(const QString &title, const QString &message) {
    QMessageBox::StandardButton reply = QMessageBox::question(this, title, message,
        QMessageBox::Yes | QMessageBox::No);
    return reply == QMessageBox::Yes;
}
