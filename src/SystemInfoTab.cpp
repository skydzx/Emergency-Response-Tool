/**
 * @file SystemInfoTab.cpp
 * @brief System Information Tab Implementation
 * @version 1.0.0
 */

#include "SystemInfoTab.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QFile>
#include <QTextStream>
#include <QMenu>
#include <QAction>
#include <QDesktopServices>
#include <QUrl>

SystemInfoTab::SystemInfoTab(QWidget *parent)
    : QWidget(parent)
    , m_collector(new SystemInfoCollector(this))
    , m_isCollecting(false)
{
    setupUi();
    setupConnections();
}

SystemInfoTab::~SystemInfoTab() {
}

void SystemInfoTab::setupUi() {
    // 主布局
    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(5, 5, 5, 5);
    mainLayout->setSpacing(5);

    // 顶部工具栏
    QHBoxLayout* toolbarLayout = new QHBoxLayout();

    m_btnRefresh = new QPushButton(this);
    m_btnRefresh->setText("刷新");
    m_btnRefresh->setIcon(QIcon::fromTheme("view-refresh"));
    toolbarLayout->addWidget(m_btnRefresh);

    m_btnExport = new QPushButton(this);
    m_btnExport->setText("导出");
    m_btnExport->setIcon(QIcon::fromTheme("document-export"));
    toolbarLayout->addWidget(m_btnExport);

    toolbarLayout->addStretch();

    m_searchEdit = new QLineEdit(this);
    m_searchEdit->setPlaceholderText("搜索...");
    m_searchEdit->setMaximumWidth(200);
    toolbarLayout->addWidget(m_searchEdit);

    m_filterCombo = new QComboBox(this);
    m_filterCombo->addItems({"全部", "进程", "服务", "用户", "启动项"});
    m_filterCombo->setMaximumWidth(100);
    toolbarLayout->addWidget(m_filterCombo);

    mainLayout->addLayout(toolbarLayout);

    // 进度条
    QHBoxLayout* progressLayout = new QHBoxLayout();
    m_progressBar = new QProgressBar(this);
    m_progressBar->setMaximumHeight(15);
    m_progressBar->setMaximumWidth(200);
    m_progressBar->setValue(0);
    progressLayout->addWidget(m_progressBar);

    m_progressLabel = new QLabel(this);
    m_progressLabel->setMaximumWidth(300);
    m_progressLabel->setText("就绪");
    progressLayout->addWidget(m_progressLabel);
    progressLayout->addStretch();
    mainLayout->addLayout(progressLayout);

    // 系统信息概览组
    setupSystemInfoUI();
    mainLayout->addWidget(m_systemInfoGroup);

    // 树形列表（用于显示详细信息）
    QSplitter* splitter = new QSplitter(Qt::Vertical, this);

    // 进程列表
    setupProcessUI();
    splitter->addWidget(m_processTree);

    // 服务列表
    setupServiceUI();
    splitter->addWidget(m_serviceTree);

    // 用户列表
    setupUserUI();
    splitter->addWidget(m_userTree);

    // 启动项列表
    setupStartupUI();
    splitter->addWidget(m_startupTree);

    splitter->setSizes({150, 100, 100, 100});
    mainLayout->addWidget(splitter);

    setLayout(mainLayout);
}

void SystemInfoTab::setupConnections() {
    connect(m_btnRefresh, &QPushButton::clicked, this, &SystemInfoTab::onBtnRefreshClicked);
    connect(m_btnExport, &QPushButton::clicked, this, &SystemInfoTab::onBtnExportClicked);

    connect(m_collector, &SystemInfoCollector::progressUpdated,
            this, &SystemInfoTab::onProgressUpdated);
    connect(m_collector, &SystemInfoCollector::infoCollected,
            this, &SystemInfoTab::onInfoCollected);
    connect(m_collector, &SystemInfoCollector::errorOccurred,
            this, &SystemInfoTab::onErrorOccurred);

    connect(m_processTree, &QTreeWidget::itemClicked,
            this, &SystemInfoTab::onProcessItemClicked);
    connect(m_serviceTree, &QTreeWidget::itemClicked,
            this, &SystemInfoTab::onServiceItemClicked);
    connect(m_userTree, &QTreeWidget::itemClicked,
            this, &SystemInfoTab::onUserItemClicked);
    connect(m_startupTree, &QTreeWidget::itemClicked,
            this, &SystemInfoTab::onStartupItemClicked);

    // 搜索过滤
    connect(m_searchEdit, &QLineEdit::textChanged, [this](const QString& text) {
        Q_UNUSED(text)
        // TODO: 实现搜索过滤功能
    });
}

void SystemInfoTab::setupSystemInfoUI() {
    m_systemInfoGroup = new QGroupBox("系统信息概览", this);
    QGridLayout* layout = new QGridLayout();

    m_osVersionLabel = new QLabel(this);
    m_osVersionLabel->setText("待获取");
    layout->addWidget(new QLabel("操作系统:", this), 0, 0);
    layout->addWidget(m_osVersionLabel, 0, 1);

    m_computerNameLabel = new QLabel(this);
    m_computerNameLabel->setText("待获取");
    layout->addWidget(new QLabel("计算机名:", this), 0, 2);
    layout->addWidget(m_computerNameLabel, 0, 3);

    m_userNameLabel = new QLabel(this);
    m_userNameLabel->setText("待获取");
    layout->addWidget(new QLabel("当前用户:", this), 1, 0);
    layout->addWidget(m_userNameLabel, 1, 1);

    m_processorCountLabel = new QLabel(this);
    m_processorCountLabel->setText("待获取");
    layout->addWidget(new QLabel("处理器:", this), 1, 2);
    layout->addWidget(m_processorCountLabel, 1, 3);

    m_memoryInfoLabel = new QLabel(this);
    m_memoryInfoLabel->setText("待获取");
    layout->addWidget(new QLabel("内存:", this), 2, 0);
    layout->addWidget(m_memoryInfoLabel, 2, 1);

    m_diskInfoLabel = new QLabel(this);
    m_diskInfoLabel->setText("待获取");
    m_diskInfoLabel->setWordWrap(true);
    layout->addWidget(new QLabel("磁盘:", this), 2, 2);
    layout->addWidget(m_diskInfoLabel, 2, 3);

    m_archLabel = new QLabel(this);
    m_archLabel->setText("待获取");
    layout->addWidget(new QLabel("系统架构:", this), 3, 0);
    layout->addWidget(m_archLabel, 3, 1);

    m_lastUpdateLabel = new QLabel(this);
    m_lastUpdateLabel->setText("待获取");
    layout->addWidget(new QLabel("最后更新:", this), 3, 2);
    layout->addWidget(m_lastUpdateLabel, 3, 3);

    layout->setColumnStretch(1, 1);
    layout->setColumnStretch(3, 1);

    m_systemInfoGroup->setLayout(layout);
}

void SystemInfoTab::setupProcessUI() {
    QGroupBox* group = new QGroupBox("进程信息", this);
    QVBoxLayout* layout = new QVBoxLayout();

    m_processTree = new QTreeWidget(this);
    m_processTree->setHeaderLabels({"PID", "名称", "路径", "用户", "内存(KB)", "状态", "可疑"});
    m_processTree->setColumnWidth(0, 60);
    m_processTree->setColumnWidth(1, 150);
    m_processTree->setColumnWidth(2, 250);
    m_processTree->setColumnWidth(3, 100);
    m_processTree->setColumnWidth(4, 80);
    m_processTree->setColumnWidth(5, 60);
    m_processTree->setAlternatingRowColors(true);
    m_processTree->setContextMenuPolicy(Qt::CustomContextMenu);

    layout->addWidget(m_processTree);
    group->setLayout(layout);
}

void SystemInfoTab::setupServiceUI() {
    QGroupBox* group = new QGroupBox("服务信息", this);
    QVBoxLayout* layout = new QVBoxLayout();

    m_serviceTree = new QTreeWidget(this);
    m_serviceTree->setHeaderLabels({"名称", "显示名称", "状态", "启动类型", "路径", "可疑"});
    m_serviceTree->setColumnWidth(0, 150);
    m_serviceTree->setColumnWidth(1, 150);
    m_serviceTree->setColumnWidth(2, 60);
    m_serviceTree->setColumnWidth(3, 80);
    m_serviceTree->setColumnWidth(4, 200);
    m_serviceTree->setAlternatingRowColors(true);

    layout->addWidget(m_serviceTree);
    group->setLayout(layout);
}

void SystemInfoTab::setupUserUI() {
    QGroupBox* group = new QGroupBox("用户信息", this);
    QVBoxLayout* layout = new QVBoxLayout();

    m_userTree = new QTreeWidget(this);
    m_userTree->setHeaderLabels({"用户名", "全名", "域", "类型", "状态", "最后登录", "可疑"});
    m_userTree->setColumnWidth(0, 100);
    m_userTree->setColumnWidth(1, 100);
    m_userTree->setColumnWidth(2, 80);
    m_userTree->setColumnWidth(3, 60);
    m_userTree->setColumnWidth(4, 80);
    m_userTree->setColumnWidth(5, 120);
    m_userTree->setAlternatingRowColors(true);

    layout->addWidget(m_userTree);
    group->setLayout(layout);
}

void SystemInfoTab::setupStartupUI() {
    QGroupBox* group = new QGroupBox("启动项信息", this);
    QVBoxLayout* layout = new QVBoxLayout();

    m_startupTree = new QTreeWidget(this);
    m_startupTree->setHeaderLabels({"名称", "类型", "路径", "位置", "发布者", "可疑"});
    m_startupTree->setColumnWidth(0, 150);
    m_startupTree->setColumnWidth(1, 80);
    m_startupTree->setColumnWidth(2, 250);
    m_startupTree->setColumnWidth(3, 200);
    m_startupTree->setColumnWidth(4, 100);
    m_startupTree->setAlternatingRowColors(true);

    layout->addWidget(m_startupTree);
    group->setLayout(layout);
}

void SystemInfoTab::collectSystemInfo() {
    setBusyIndicator(true);
    updateStatusLabel("正在收集系统信息...");

    SystemInfo info = m_collector->collectSystemInfo();
    displaySystemInfo(info);

    emit scanCompleted("system", 1);
}

void SystemInfoTab::collectProcesses() {
    updateStatusLabel("正在收集进程信息...");

    QList<ProcessInfo> processes = m_collector->collectProcesses();
    m_processes = processes;
    displayProcesses(processes);

    emit scanCompleted("processes", processes.size());
}

void SystemInfoTab::collectServices() {
    updateStatusLabel("正在收集服务信息...");

    QList<ServiceInfo> services = m_collector->collectServices();
    m_services = services;
    displayServices(services);

    emit scanCompleted("services", services.size());
}

void SystemInfoTab::collectUsers() {
    updateStatusLabel("正在收集用户信息...");

    QList<UserInfo> users = m_collector->collectUsers();
    m_users = users;
    displayUsers(users);

    emit scanCompleted("users", users.size());
}

void SystemInfoTab::collectStartupItems() {
    updateStatusLabel("正在收集启动项信息...");

    QList<StartupInfo> items = m_collector->collectStartupItems();
    m_startupItems = items;
    displayStartupItems(items);

    emit scanCompleted("startup", items.size());
}

void SystemInfoTab::refreshAll() {
    if (m_isCollecting) {
        return;
    }

    m_isCollecting = true;
    m_btnRefresh->setEnabled(false);

    // 清空现有数据
    m_processTree->clear();
    m_serviceTree->clear();
    m_userTree->clear();
    m_startupTree->clear();

    // 收集所有信息
    collectSystemInfo();
    collectProcesses();
    collectServices();
    collectUsers();
    collectStartupItems();

    m_isCollecting = false;
    m_btnRefresh->setEnabled(true);
    setBusyIndicator(false);
    updateStatusLabel("就绪");
}

void SystemInfoTab::displaySystemInfo(const SystemInfo& info) {
    m_osVersionLabel->setText(info.osVersion);
    m_computerNameLabel->setText(info.computerName);
    m_userNameLabel->setText(info.userName);
    m_processorCountLabel->setText(QString::number(info.processorCount));
    m_memoryInfoLabel->setText(info.memoryInfo);
    m_diskInfoLabel->setText(info.diskInfo);
    m_archLabel->setText(info.architecture);
    m_lastUpdateLabel->setText(info.systemTime.toString("yyyy-MM-dd hh:mm:ss"));
}

void SystemInfoTab::displayProcesses(const QList<ProcessInfo>& processes) {
    m_processTree->clear();

    for (const ProcessInfo& process : processes) {
        addProcessToTree(process, m_processTree);
    }

    m_processTree->expandAll();
}

void SystemInfoTab::displayServices(const QList<ServiceInfo>& services) {
    m_serviceTree->clear();

    for (const ServiceInfo& service : services) {
        addServiceToTree(service, m_serviceTree);
    }

    m_serviceTree->expandAll();
}

void SystemInfoTab::displayUsers(const QList<UserInfo>& users) {
    m_userTree->clear();

    for (const UserInfo& user : users) {
        addUserToTree(user, m_userTree);
    }

    m_userTree->expandAll();
}

void SystemInfoTab::displayStartupItems(const QList<StartupInfo>& items) {
    m_startupTree->clear();

    for (const StartupInfo& item : items) {
        addStartupToTree(item, m_startupTree);
    }

    m_startupTree->expandAll();
}

void SystemInfoTab::addProcessToTree(const ProcessInfo& process, QTreeWidget* tree) {
    QTreeWidgetItem* item = new QTreeWidgetItem(tree);
    item->setText(0, QString::number(process.pid));
    item->setText(1, process.name);
    item->setText(2, process.path);
    item->setText(3, process.user);
    item->setText(4, QString::number(process.memoryUsage));
    item->setText(5, process.isSuspended ? "已暂停" : "运行中");

    if (process.isSuspicious) {
        item->setText(6, "是");
        item->setForeground(6, QColor(Qt::red));
    } else {
        item->setText(6, "否");
        item->setForeground(6, QColor(Qt::darkGreen));
    }

    // 保存完整数据
    item->setData(0, Qt::UserRole, QVariant::fromValue(process));
}

void SystemInfoTab::addServiceToTree(const ServiceInfo& service, QTreeWidget* tree) {
    QTreeWidgetItem* item = new QTreeWidgetItem(tree);
    item->setText(0, service.name);
    item->setText(1, service.displayName);
    item->setText(2, service.status);
    item->setText(3, service.startType);
    item->setText(4, service.path);

    if (service.isSuspicious) {
        item->setText(5, "是");
        item->setForeground(5, QColor(Qt::red));
    } else {
        item->setText(5, "否");
        item->setForeground(5, QColor(Qt::darkGreen));
    }

    item->setData(0, Qt::UserRole, QVariant::fromValue(service));
}

void SystemInfoTab::addUserToTree(const UserInfo& user, QTreeWidget* tree) {
    QTreeWidgetItem* item = new QTreeWidgetItem(tree);
    item->setText(0, user.name);
    item->setText(1, user.fullName);
    item->setText(2, user.domain);
    item->setText(3, user.userType);
    item->setText(4, user.isDisabled ? "已禁用" : "正常");
    item->setText(5, user.lastLogin.isValid() ? user.lastLogin.toString("yyyy-MM-dd") : "未知");

    if (user.name == "Administrator" && !user.isDisabled) {
        item->setText(6, "建议检查");
        item->setForeground(6, QColor(Qt::darkYellow));
    } else {
        item->setText(6, "否");
        item->setForeground(6, QColor(Qt::darkGreen));
    }

    item->setData(0, Qt::UserRole, QVariant::fromValue(user));
}

void SystemInfoTab::addStartupToTree(const StartupInfo& item, QTreeWidget* tree) {
    QTreeWidgetItem* treeItem = new QTreeWidgetItem(tree);
    treeItem->setText(0, item.name);
    treeItem->setText(1, item.type);
    treeItem->setText(2, item.path);
    treeItem->setText(3, item.location);
    treeItem->setText(4, item.publisher);

    if (item.isSuspicious) {
        treeItem->setText(5, "是");
        treeItem->setForeground(5, QColor(Qt::red));
    } else {
        treeItem->setText(5, "否");
        treeItem->setForeground(5, QColor(Qt::darkGreen));
    }

    treeItem->setData(0, Qt::UserRole, QVariant::fromValue(item));
}

void SystemInfoTab::updateStatusLabel(const QString& text) {
    m_progressLabel->setText(text);
}

void SystemInfoTab::setBusyIndicator(bool busy) {
    if (busy) {
        m_progressBar->setRange(0, 0);
        m_progressBar->setValue(0);
    } else {
        m_progressBar->setRange(0, 100);
        m_progressBar->setValue(100);
    }
}

void SystemInfoTab::onBtnRefreshClicked() {
    refreshAll();
}

void SystemInfoTab::onBtnExportClicked() {
    QString fileName = QFileDialog::getSaveFileName(this,
        "导出系统信息",
        QString("system_info_%1.json").arg(QDate::currentDate().toString("yyyyMMdd")),
        "JSON Files (*.json);;Text Files (*.txt);;CSV Files (*.csv)");

    if (fileName.isEmpty()) {
        return;
    }

    QJsonObject root;
    root["exportTime"] = QDateTime::currentDateTime().toString(Qt::ISODate).toUtf8().constData();
    root["computerName"] = m_computerNameLabel->text().toUtf8().constData();
    root["userName"] = m_userNameLabel->text().toUtf8().constData();

    // 导出进程信息
    QJsonArray processesArray;
    for (const ProcessInfo& process : m_processes) {
        QJsonObject proc;
        proc["pid"] = process.pid;
        proc["name"] = process.name.toUtf8().constData();
        proc["path"] = process.path.toUtf8().constData();
        proc["user"] = process.user.toUtf8().constData();
        proc["memoryUsage"] = process.memoryUsage;
        proc["isSuspicious"] = process.isSuspicious;
        if (process.isSuspicious) {
            proc["reason"] = process.suspiciousReason.toUtf8().constData();
        }
        processesArray.append(proc);
    }
    root["processes"] = processesArray;

    // 导出服务信息
    QJsonArray servicesArray;
    for (const ServiceInfo& service : m_services) {
        QJsonObject svc;
        svc["name"] = service.name.toUtf8().constData();
        svc["displayName"] = service.displayName.toUtf8().constData();
        svc["status"] = service.status.toUtf8().constData();
        svc["startType"] = service.startType.toUtf8().constData();
        svc["path"] = service.path.toUtf8().constData();
        svc["isSuspicious"] = service.isSuspicious;
        if (service.isSuspicious) {
            svc["reason"] = service.suspiciousReason.toUtf8().constData();
        }
        servicesArray.append(svc);
    }
    root["services"] = servicesArray;

    // 导出用户信息
    QJsonArray usersArray;
    for (const UserInfo& user : m_users) {
        QJsonObject usr;
        usr["name"] = user.name.toUtf8().constData();
        usr["fullName"] = user.fullName.toUtf8().constData();
        usr["domain"] = user.domain.toUtf8().constData();
        usr["userType"] = user.userType.toUtf8().constData();
        usr["isDisabled"] = user.isDisabled;
        usersArray.append(usr);
    }
    root["users"] = usersArray;

    // 导出启动项信息
    QJsonArray startupArray;
    for (const StartupInfo& item : m_startupItems) {
        QJsonObject si;
        si["name"] = item.name.toUtf8().constData();
        si["type"] = item.type.toUtf8().constData();
        si["path"] = item.path.toUtf8().constData();
        si["location"] = item.location.toUtf8().constData();
        si["isSuspicious"] = item.isSuspicious;
        if (item.isSuspicious) {
            si["reason"] = item.suspiciousReason.toUtf8().constData();
        }
        startupArray.append(si);
    }
    root["startupItems"] = startupArray;

    QJsonDocument doc(root);

    QFile file(fileName);
    if (file.open(QIODevice::WriteOnly)) {
        file.write(doc.toJson(QJsonDocument::Indented));
        file.close();

        QMessageBox::information(this, "导出成功",
            QString("系统信息已导出到:\n%1").arg(fileName));
    } else {
        QMessageBox::warning(this, "导出失败",
            QString("无法写入文件:\n%1").arg(fileName));
    }
}

void SystemInfoTab::onProgressUpdated(int percentage, const QString& status) {
    m_progressBar->setValue(percentage);
    m_progressLabel->setText(status);
}

void SystemInfoTab::onInfoCollected(const QString& infoType, const QVariant& data) {
    Q_UNUSED(infoType)
    Q_UNUSED(data)
    // 处理收集到的信息
}

void SystemInfoTab::onErrorOccurred(const QString& error) {
    QMessageBox::warning(this, "收集错误", error);
    setBusyIndicator(false);
}

void SystemInfoTab::onProcessItemClicked(QTreeWidgetItem* item, int column) {
    Q_UNUSED(column)
    ProcessInfo process = item->data(0, Qt::UserRole).value<ProcessInfo>();

    // 显示进程详细信息
    QString details = QString(
        "<h3>进程详细信息</h3>"
        "<table>"
        "<tr><td><b>PID:</b></td><td>%1</td></tr>"
        "<tr><td><b>名称:</b></td><td>%2</td></tr>"
        "<tr><td><b>路径:</b></td><td>%3</td></tr>"
        "<tr><td><b>命令行:</b></td><td>%4</td></tr>"
        "<tr><td><b>用户:</b></td><td>%5</td></tr>"
        "<tr><td><b>内存使用:</b></td><td>%6 KB</td></tr>"
        "<tr><td><b>状态:</b></td><td>%7</td></tr>"
        "<tr><td><b>可疑:</b></td><td>%8</td></tr>"
        "</table>"
    ).arg(process.pid)
     .arg(process.name)
     .arg(process.path)
     .arg(process.commandLine)
     .arg(process.user)
     .arg(process.memoryUsage)
     .arg(process.isSuspended ? "已暂停" : "运行中")
     .arg(process.isSuspicious ? QString("<font color='red'>是 - %1</font>").arg(process.suspiciousReason) : "否");

    QMessageBox::information(this, "进程详情", details);
}

void SystemInfoTab::onServiceItemClicked(QTreeWidgetItem* item, int column) {
    Q_UNUSED(column)
    ServiceInfo service = item->data(0, Qt::UserRole).value<ServiceInfo>();

    QString details = QString(
        "<h3>服务详细信息</h3>"
        "<table>"
        "<tr><td><b>名称:</b></td><td>%1</td></tr>"
        "<tr><td><b>显示名称:</b></td><td>%2</td></tr>"
        "<tr><td><b>描述:</b></td><td>%3</td></tr>"
        "<tr><td><b>路径:</b></td><td>%4</td></tr>"
        "<tr><td><b>启动类型:</b></td><td>%5</td></tr>"
        "<tr><td><b>状态:</b></td><td>%6</td></tr>"
        "<tr><td><b>可疑:</b></td><td>%7</td></tr>"
        "</table>"
    ).arg(service.name)
     .arg(service.displayName)
     .arg(service.description)
     .arg(service.path)
     .arg(service.startType)
     .arg(service.status)
     .arg(service.isSuspicious ? QString("<font color='red'>是 - %1</font>").arg(service.suspiciousReason) : "否");

    QMessageBox::information(this, "服务详情", details);
}

void SystemInfoTab::onUserItemClicked(QTreeWidgetItem* item, int column) {
    Q_UNUSED(column)
    UserInfo user = item->data(0, Qt::UserRole).value<UserInfo>();

    QString details = QString(
        "<h3>用户详细信息</h3>"
        "<table>"
        "<tr><td><b>用户名:</b></td><td>%1</td></tr>"
        "<tr><td><b>全名:</b></td><td>%2</td></tr>"
        "<tr><td><b>域:</b></td><td>%3</td></tr>"
        "<tr><td><b>SID:</b></td><td>%4</td></tr>"
        "<tr><td><b>类型:</b></td><td>%5</td></tr>"
        "<tr><td><b>状态:</b></td><td>%6</td></tr>"
        "<tr><td><b>最后登录:</b></td><td>%7</td></tr>"
        "<tr><td><b>配置文件:</b></td><td>%8</td></tr>"
        "</table>"
    ).arg(user.name)
     .arg(user.fullName)
     .arg(user.domain)
     .arg(user.sid)
     .arg(user.userType)
     .arg(user.isDisabled ? "已禁用" : "正常")
     .arg(user.lastLogin.isValid() ? user.lastLogin.toString("yyyy-MM-dd hh:mm:ss") : "未知")
     .arg(user.profilePath);

    QMessageBox::information(this, "用户详情", details);
}

void SystemInfoTab::onStartupItemClicked(QTreeWidgetItem* item, int column) {
    Q_UNUSED(column)
    StartupInfo startup = item->data(0, Qt::UserRole).value<StartupInfo>();

    QString details = QString(
        "<h3>启动项详细信息</h3>"
        "<table>"
        "<tr><td><b>名称:</b></td><td>%1</td></tr>"
        "<tr><td><b>类型:</b></td><td>%2</td></tr>"
        "<tr><b>路径:</b></td><td>%3</td></tr>"
        "<tr><td><b>位置:</b></td><td>%4</td></tr>"
        "<tr><td><b>发布者:</b></td><td>%5</td></tr>"
        "<tr><td><b>可疑:</b></td><td>%6</td></tr>"
        "</table>"
    ).arg(startup.name)
     .arg(startup.type)
     .arg(startup.path)
     .arg(startup.location)
     .arg(startup.publisher)
     .arg(startup.isSuspicious ? QString("<font color='red'>是 - %1</font>").arg(startup.suspiciousReason) : "否");

    QMessageBox::information(this, "启动项详情", details);
}
