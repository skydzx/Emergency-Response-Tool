#ifndef SYSTEMINFOTAB_H
#define SYSTEMINFOTAB_H

#include <QWidget>
#include <QPushButton>
#include <QLabel>
#include <QTableWidget>
#include <QTreeWidget>
#include <QProgressBar>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QSplitter>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QHeaderView>
#include <QThread>
#include <QTimer>
#include <QDateTime>

#include "SystemInfoCollector.h"

class SystemInfoTab : public QWidget {
    Q_OBJECT

public:
    explicit SystemInfoTab(QWidget *parent = nullptr);
    ~SystemInfoTab();

    // 初始化UI
    void setupUi();

    // 收集系统信息
    void collectSystemInfo();
    void collectProcesses();
    void collectServices();
    void collectUsers();
    void collectStartupItems();
    void collectScheduledTasks();

    // 刷新所有信息
    void refreshAll();

signals:
    void scanStarted(const QString& taskName);
    void scanCompleted(const QString& taskName, int resultCount);
    void scanError(const QString& taskName, const QString& error);
    void threatFound(const QString& threatType, const QString& details);

private slots:
    void onBtnRefreshClicked();
    void onBtnExportClicked();
    void onProgressUpdated(int percentage, const QString& status);
    void onInfoCollected(const QString& infoType, const QVariant& data);
    void onErrorOccurred(const QString& error);
    void onProcessItemClicked(QTreeWidgetItem* item, int column);
    void onServiceItemClicked(QTreeWidgetItem* item, int column);
    void onUserItemClicked(QTreeWidgetItem* item, int column);
    void onStartupItemClicked(QTreeWidgetItem* item, int column);

private:
    void setupSystemInfoUI();
    void setupProcessUI();
    void setupServiceUI();
    void setupUserUI();
    void setupStartupUI();

    void displaySystemInfo(const SystemInfo& info);
    void displayProcesses(const QList<ProcessInfo>& processes);
    void displayServices(const QList<ServiceInfo>& services);
    void displayUsers(const QList<UserInfo>& users);
    void displayStartupItems(const QList<StartupInfo>& items);

    void addProcessToTree(const ProcessInfo& process, QTreeWidget* tree);
    void addServiceToTree(const ServiceInfo& service, QTreeWidget* tree);
    void addUserToTree(const UserInfo& user, QTreeWidget* tree);
    void addStartupToTree(const StartupInfo& item, QTreeWidget* tree);

    void updateStatusLabel(const QString& text);
    void setBusyIndicator(bool busy);

private:
    SystemInfoCollector* m_collector;

    // 系统信息UI
    QGroupBox* m_systemInfoGroup;
    QLabel* m_osVersionLabel;
    QLabel* m_computerNameLabel;
    QLabel* m_userNameLabel;
    QLabel* m_processorCountLabel;
    QLabel* m_memoryInfoLabel;
    QLabel* m_diskInfoLabel;
    QLabel* m_archLabel;
    QLabel* m_lastUpdateLabel;

    // 按钮
    QPushButton* m_btnRefresh;
    QPushButton* m_btnExport;
    QPushButton* m_btnSelectAll;
    QPushButton* m_btnDeselectAll;

    // 进度条
    QProgressBar* m_progressBar;
    QLabel* m_progressLabel;

    // 树形列表
    QTreeWidget* m_processTree;
    QTreeWidget* m_serviceTree;
    QTreeWidget* m_userTree;
    QTreeWidget* m_startupTree;

    // 搜索框
    QLineEdit* m_searchEdit;
    QComboBox* m_filterCombo;

    // 数据存储
    QList<ProcessInfo> m_processes;
    QList<ServiceInfo> m_services;
    QList<UserInfo> m_users;
    QList<StartupInfo> m_startupItems;

    bool m_isCollecting;
};

#endif // SYSTEMINFOTAB_H
