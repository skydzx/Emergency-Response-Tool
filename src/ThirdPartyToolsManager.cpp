/**
 * @file ThirdPartyToolsManager.cpp
 * @brief Third-Party Security Tools Management Implementation
 * @version 1.0.0
 */

#include "ThirdPartyToolsManager.h"
#include <QFile>
#include <QTextStream>
#include <QDebug>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDir>
#include <QProcess>
#include <QFileInfo>
#include <QSettings>

ThirdPartyToolsManager::ThirdPartyToolsManager(QObject *parent)
    : QObject(parent)
    , m_currentProcess(nullptr)
{
    initializeTools();
}

ThirdPartyToolsManager::~ThirdPartyToolsManager() {
    if (m_currentProcess) {
        m_currentProcess->kill();
        delete m_currentProcess;
    }
}

// ========== 工具管理 ==========

QList<ToolInfo> ThirdPartyToolsManager::getAllTools() {
    return m_tools;
}

QList<ToolInfo> ThirdPartyToolsManager::getInstalledTools() {
    QList<ToolInfo> installed;
    for (const ToolInfo& tool : m_tools) {
        if (tool.isInstalled) {
            installed.append(tool);
        }
    }
    return installed;
}

QList<ToolInfo> ThirdPartyToolsManager::getEnabledTools() {
    QList<ToolInfo> enabled;
    for (const ToolInfo& tool : m_tools) {
        if (tool.isEnabled && tool.isInstalled) {
            enabled.append(tool);
        }
    }
    return enabled;
}

QList<ToolInfo> ThirdPartyToolsManager::getToolsByCategory(const QString& category) {
    QList<ToolInfo> tools;
    for (const ToolInfo& tool : m_tools) {
        if (tool.category == category) {
            tools.append(tool);
        }
    }
    return tools;
}

ToolInfo ThirdPartyToolsManager::getTool(int toolId) {
    for (const ToolInfo& tool : m_tools) {
        if (tool.id == toolId) {
            return tool;
        }
    }
    return ToolInfo();
}

ToolInfo ThirdPartyToolsManager::getToolByName(const QString& name) {
    for (const ToolInfo& tool : m_tools) {
        if (tool.name == name) {
            return tool;
        }
    }
    return ToolInfo();
}

// ========== 工具安装 ==========

bool ThirdPartyToolsManager::installTool(int toolId) {
    ToolInfo tool = getTool(toolId);
    if (tool.id == 0) {
        emit errorOccurred("工具不存在");
        return false;
    }

    // 检查路径
    if (tool.path.isEmpty()) {
        emit errorOccurred("工具路径未配置");
        return false;
    }

    // 检查工具是否存在
    if (!QFile::exists(tool.path)) {
        emit errorOccurred(QString("工具文件不存在: %1").arg(tool.path));
        return false;
    }

    // 更新状态
    for (ToolInfo& t : m_tools) {
        if (t.id == toolId) {
            t.isInstalled = true;
            t.status = "installed";
            emit toolInstalled(t);
            return true;
        }
    }

    return false;
}

bool ThirdPartyToolsManager::uninstallTool(int toolId) {
    for (ToolInfo& tool : m_tools) {
        if (tool.id == toolId) {
            tool.isInstalled = false;
            tool.status = "not_installed";
            emit toolUninstalled(tool);
            return true;
        }
    }
    return false;
}

bool ThirdPartyToolsManager::downloadTool(int toolId) {
    ToolInfo tool = getTool(toolId);
    if (tool.downloadUrl.isEmpty()) {
        emit errorOccurred("此工具不支持自动下载");
        return false;
    }

    emit downloadProgress(tool.name, 0);

    // TODO: 实现下载功能
    // 需要使用QNetworkAccessManager下载文件

    emit downloadProgress(tool.name, 100);
    emit downloadCompleted(tool.name, tool.path);

    return true;
}

bool ThirdPartyToolsManager::configureTool(int toolId, const QJsonObject& config) {
    return saveToolConfig(toolId, config);
}

bool ThirdPartyToolsManager::checkToolAvailability(int toolId) {
    ToolInfo tool = getTool(toolId);
    if (tool.id == 0) {
        return false;
    }

    bool available = checkToolPath(tool.path);

    for (ToolInfo& t : m_tools) {
        if (t.id == toolId) {
            t.isInstalled = available;
            t.status = available ? "available" : "not_found";
            t.lastCheckTime = QDateTime::currentDateTime().toString(Qt::ISODate);
            emit toolStatusChanged(t);
            return available;
        }
    }

    return false;
}

bool ThirdPartyToolsManager::updateTool(int toolId) {
    Q_UNUSED(toolId)
    // 更新工具版本
    return false;
}

// ========== 工具运行 ==========

bool ThirdPartyToolsManager::runTool(int toolId) {
    return runToolWithArgs(toolId, QStringList());
}

bool ThirdPartyToolsManager::runToolWithArgs(int toolId, const QStringList& args) {
    ToolInfo tool = getTool(toolId);
    if (tool.id == 0) {
        emit errorOccurred("工具不存在");
        return false;
    }

    if (!tool.isInstalled) {
        emit errorOccurred("工具未安装");
        return false;
    }

    ToolResult result;
    result.toolId = toolId;
    result.toolName = tool.name;
    result.startTime = QDateTime::currentDateTime();
    result.success = false;

    // 构建命令
    QString command = buildCommand(tool, args);
    if (command.isEmpty()) {
        result.errorMessage = "无法构建命令";
        emit toolErrorOccurred(tool, result.errorMessage);
        return false;
    }

    // 执行
    if (executeTool(command, args, result)) {
        result.success = true;
    }

    result.endTime = QDateTime::currentDateTime();
    m_lastResults[toolId] = result;
    m_toolResults.append(result);

    emit toolExecutionCompleted(tool, result);

    return result.success;
}

bool ThirdPartyToolsManager::runToolAsync(int toolId) {
    ToolInfo tool = getTool(toolId);
    if (tool.id == 0 || !tool.isInstalled) {
        return false;
    }

    if (m_currentProcess) {
        delete m_currentProcess;
    }

    m_currentProcess = new QProcess(this);

    QString command = buildCommand(tool);
    m_currentProcess->start(command);

    connect(m_currentProcess, &QProcess::readyReadStandardOutput, [this, tool]() {
        QString output = m_currentProcess->readAllStandardOutput();
        emit toolOutputReceived(tool, output);
    });

    connect(m_currentProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            [this, tool](int exitCode, QProcess::ExitStatus status) {
                emit toolExecutionCompleted(tool, ToolResult());
            });

    return true;
}

bool ThirdPartyToolsManager::stopTool(int toolId) {
    Q_UNUSED(toolId)
    if (m_currentProcess) {
        m_currentProcess->kill();
        return true;
    }
    return false;
}

bool ThirdPartyToolsManager::stopAllTools() {
    stopTool(0);
    return true;
}

ToolResult ThirdPartyToolsManager::getLastResult(int toolId) {
    return m_lastResults.value(toolId, ToolResult());
}

QList<ToolResult> ThirdPartyToolsManager::getToolResults(int toolId) {
    QList<ToolResult> results;
    for (const ToolResult& result : m_toolResults) {
        if (result.toolId == toolId) {
            results.append(result);
        }
    }
    return results;
}

// ========== 工具配置 ==========

QJsonObject ThirdPartyToolsManager::getToolConfig(int toolId) {
    return loadToolConfig(toolId);
}

bool ThirdPartyToolsManager::saveToolConfig(int toolId, const QJsonObject& config) {
    return saveToolConfigToFile(toolId, config);
}

bool ThirdPartyToolsManager::resetToolConfig(int toolId) {
    Q_UNUSED(toolId)
    return false;
}

QString ThirdPartyToolsManager::getToolOutputPath(int toolId) {
    ToolInfo tool = getTool(toolId);
    return tool.outputPath;
}

bool ThirdPartyToolsManager::setToolOutputPath(int toolId, const QString& path) {
    for (ToolInfo& tool : m_tools) {
        if (tool.id == toolId) {
            tool.outputPath = path;
            return true;
        }
    }
    return false;
}

// ========== 工具分类 ==========

QList<ToolCategory> ThirdPartyToolsManager::getCategories() {
    QList<ToolCategory> categories;

    categories.append({"Process Analysis", "process", "进程分析工具", 0, 0});
    categories.append({"Memory Forensics", "memory", "内存取证工具", 0, 0});
    categories.append({"Network Analysis", "network", "网络分析工具", 0, 0});
    categories.append({"Digital Forensics", "forensics", "数字取证工具", 0, 0});
    categories.append({"Web Security", "web", "Web安全工具", 0, 0});
    categories.append({"System Tools", "system", "系统工具", 0, 0});

    return categories;
}

QList<ToolCategory> ThirdPartyToolsManager::getCategoriesWithTools() {
    QList<ToolCategory> categories = getCategories();

    for (ToolCategory& category : categories) {
        QList<ToolInfo> tools = getToolsByCategory(category.name);
        category.toolCount = tools.size();
        category.tools = tools;

        int installed = 0;
        for (const ToolInfo& tool : tools) {
            if (tool.isInstalled) {
                installed++;
            }
        }
        category.installedCount = installed;
    }

    return categories;
}

QString ThirdPartyToolsManager::getCategoryIcon(const QString& category) {
    QMap<QString, QString> icons = {
        {"Process Analysis", "process"},
        {"Memory Forensics", "memory"},
        {"Network Analysis", "network"},
        {"Digital Forensics", "forensics"},
        {"Web Security", "web"},
        {"System Tools", "system"}
    };
    return icons.value(category, "default");
}

// ========== 初始化工具列表 ==========

void ThirdPartyToolsManager::initializeTools() {
    initializeProcessTools();
    initializeMemoryTools();
    initializeNetworkTools();
    initializeForensicsTools();
    initializeWebSecurityTools();
    initializeSystemTools();
}

void ThirdPartyToolsManager::initializeProcessTools() {
    // Process Explorer
    {
        ToolInfo tool;
        tool.id = 1;
        tool.name = "Process Explorer";
        tool.category = "Process Analysis";
        tool.description = "微软官方进程管理工具，可查看进程详细信息、句柄、DLL";
        tool.version = "17.05";
        tool.path = "C:\\Tools\\ProcessExplorer\\procexp64.exe";
        tool.downloadUrl = "https://docs.microsoft.com/en-us/sysinternals/downloads/process-explorer";
        tool.supportedOS = {"Windows 7+", "Windows Server 2008+"};
        tool.arguments = {"-accepteula"};
        tool.scanOptions = {"Handles", "DLLs", "TCP/IP"};
        tool.icon = "process";
        tool.isInstalled = false;
        tool.isEnabled = true;
        tool.isPortable = true;
        tool.status = "not_installed";
        tool.tags = {"Microsoft", "Sysinternals", "Process"};
        m_tools.append(tool);
    }

    // Process Hacker
    {
        ToolInfo tool;
        tool.id = 2;
        tool.name = "Process Hacker";
        tool.category = "Process Analysis";
        tool.description = "开源进程查看和管理工具，支持查看网络连接、修改进程优先级等";
        tool.version = "3.0";
        tool.path = "C:\\Tools\\ProcessHacker\\ProcessHacker.exe";
        tool.downloadUrl = "https://processhacker.sourceforge.io/downloads.php";
        tool.supportedOS = {"Windows 7+", "Windows Server 2012+"};
        tool.arguments = {};
        tool.scanOptions = {"Processes", "Services", "Network", "Disks"};
        tool.icon = "process";
        tool.isInstalled = false;
        tool.isEnabled = true;
        tool.isPortable = true;
        tool.status = "not_installed";
        tool.tags = {"Open Source", "Process", "Network"};
        m_tools.append(tool);
    }

    // Autoruns
    {
        ToolInfo tool;
        tool.id = 3;
        tool.name = "Autoruns";
        tool.category = "Process Analysis";
        tool.description = "微软Autoruns工具，显示所有自动启动位置";
        tool.version = "14.07";
        tool.path = "C:\\Tools\\Autoruns\\autoruns64.exe";
        tool.downloadUrl = "https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns";
        tool.supportedOS = {"Windows 7+", "Windows Server 2008+"};
        tool.arguments = {"-accepteula", "-c"};
        tool.scanOptions = {"Logon", "Services", "Drivers", "WMI", "Codecs"};
        tool.icon = "autorun";
        tool.isInstalled = false;
        tool.isEnabled = true;
        tool.isPortable = true;
        tool.status = "not_installed";
        tool.tags = {"Microsoft", "Sysinternals", "Startup"};
        m_tools.append(tool);
    }

    // PCHunter
    {
        ToolInfo tool;
        tool.id = 4;
        tool.name = "PCHunter";
        tool.category = "Process Analysis";
        tool.description = "强大的内核级工具，可查看隐藏进程、驱动、钩子等";
        tool.version = "1.5";
        tool.path = "C:\\Tools\\PCHunter\\PCHunter64.exe";
        tool.downloadUrl = "";
        tool.supportedOS = {"Windows XP SP3+", "Windows Server 2003+"};
        tool.arguments = {};
        tool.scanOptions = {"Processes", "Drivers", "Hooks", "SSDT"};
        tool.icon = "kernel";
        tool.isInstalled = false;
        tool.isEnabled = true;
        tool.isPortable = true;
        tool.status = "not_installed";
        tool.tags = {"Chinese", "Kernel", "Rootkit"};
        m_tools.append(tool);
    }
}

void ThirdPartyToolsManager::initializeMemoryTools() {
    // Volatility
    {
        ToolInfo tool;
        tool.id = 10;
        tool.name = "Volatility 3";
        tool.category = "Memory Forensics";
        tool.description = "高级内存取证框架，支持多种操作系统";
        tool.version = "2.4";
        tool.path = "C:\\Tools\\Volatility3\\vol.py";
        tool.downloadUrl = "https://www.volatilityfoundation.org/23";
        tool.supportedOS = {"Windows XP - 10", "Linux", "macOS"};
        tool.arguments = {"-f", "<memory_file>"};
        tool.scanOptions = {"pslist", "netscan", "malfind", "yarascan"};
        tool.icon = "memory";
        tool.isInstalled = false;
        tool.isEnabled = true;
        tool.isPortable = true;
        tool.status = "not_installed";
        tool.tags = {"Python", "Memory", "Forensics"};
        m_tools.append(tool);
    }

    // WinPmem
    {
        ToolInfo tool;
        tool.id = 11;
        tool.name = "WinPmem";
        tool.category = "Memory Forensics";
        tool.description = " Rekall开发的内存获取工具";
        tool.version = "4.0";
        tool.path = "C:\\Tools\\WinPmem\\winpmem.exe";
        tool.downloadUrl = "https://github.com/google/rekall/releases";
        tool.supportedOS = {"Windows 7+", "Windows Server 2012+"};
        tool.arguments = {"-o", "<output_file>"};
        tool.scanOptions = {"raw", "aff4", "lime"};
        tool.icon = "memory";
        tool.isInstalled = false;
        tool.isEnabled = true;
        tool.isPortable = true;
        tool.status = "not_installed";
        tool.tags = {"Google", "Rekall", "Memory Acquisition"};
        m_tools.append(tool);
    }
}

void ThirdPartyToolsManager::initializeNetworkTools() {
    // Wireshark
    {
        ToolInfo tool;
        tool.id = 20;
        tool.name = "Wireshark";
        tool.category = "Network Analysis";
        tool.description = "开源网络协议分析器";
        tool.version = "4.0";
        tool.path = "C:\\Program Files\\Wireshark\\Wireshark.exe";
        tool.downloadUrl = "https://www.wireshark.org/download.html";
        tool.supportedOS = {"Windows 7+", "macOS", "Linux"};
        tool.arguments = {};
        tool.scanOptions = {"Capture", "Display Filters", "Statistics"};
        tool.icon = "network";
        tool.isInstalled = false;
        tool.isEnabled = true;
        tool.isPortable = false;
        tool.status = "not_installed";
        tool.tags = {"Open Source", "Protocol", "Capture"};
        m_tools.append(tool);
    }

    // Nmap
    {
        ToolInfo tool;
        tool.id = 21;
        tool.name = "Nmap";
        tool.category = "Network Analysis";
        tool.description = "开源网络扫描和安全审计工具";
        tool.version = "7.93";
        tool.path = "C:\\Program Files\\Nmap\\nmap.exe";
        tool.downloadUrl = "https://nmap.org/download.html";
        tool.supportedOS = {"Windows 7+", "macOS", "Linux"};
        tool.arguments = {"-sV", "-sC", "-O"};
        tool.scanOptions = {"Port Scan", "Service Detection", "OS Detection"};
        tool.icon = "network";
        tool.isInstalled = false;
        tool.isEnabled = true;
        tool.isPortable = true;
        tool.status = "not_installed";
        tool.tags = {"Open Source", "Port Scan", "Security Audit"};
        m_tools.append(tool);
    }

    // TCPView
    {
        ToolInfo tool;
        tool.id = 22;
        tool.name = "TCPView";
        tool.category = "Network Analysis";
        tool.description = "微软Sysinternals工具，显示TCP/UDP连接详细信息";
        tool.version = "4.16";
        tool.path = "C:\\Tools\\TCPView\\tcpview.exe";
        tool.downloadUrl = "https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview";
        tool.supportedOS = {"Windows 7+", "Windows Server 2008+"};
        tool.arguments = {"-accepteula"};
        tool.scanOptions = {"TCP", "UDP", "Connections"};
        tool.icon = "network";
        tool.isInstalled = false;
        tool.isEnabled = true;
        tool.isPortable = true;
        tool.status = "not_installed";
        tool.tags = {"Microsoft", "Sysinternals", "Network"};
        m_tools.append(tool);
    }
}

void ThirdPartyToolsManager::initializeForensicsTools() {
    // FTK Imager
    {
        ToolInfo tool;
        tool.id = 30;
        tool.name = "FTK Imager";
        tool.category = "Digital Forensics";
        tool.description = "AccessData开发的免费取证镜像工具";
        tool.version = "4.5";
        tool.path = "C:\\Program Files\\AccessData\\FTK Imager\\FTK Imager.exe";
        tool.downloadUrl = "https://accessdata.com/productdownload/FTK/FTK-Imager.zip";
        tool.supportedOS = {"Windows 7+", "Windows Server 2008+"};
        tool.arguments = {};
        tool.scanOptions = {"Disk Image", "Memory Image", "Evidence"};
        tool.icon = "forensics";
        tool.isInstalled = false;
        tool.isEnabled = true;
        tool.isPortable = true;
        tool.status = "not_installed";
        tool.tags = {"AccessData", "Forensics", "Imaging"};
        m_tools.append(tool);
    }

    // Autopsy
    {
        ToolInfo tool;
        tool.id = 31;
        tool.name = "Autopsy";
        tool.category = "Digital Forensics";
        tool.description = "开源数字取证平台，基于The Sleuth Kit";
        tool.version = "4.20";
        tool.path = "C:\\Program Files\\Autopsy\\bin\\autopsy.exe";
        tool.downloadUrl = "https://www.autopsy.com/download/";
        tool.supportedOS = {"Windows 7+", "macOS", "Linux"};
        tool.arguments = {};
        tool.scanOptions = {"File Analysis", "Timeline", "Registry", "Web Artifacts"};
        tool.icon = "forensics";
        tool.isInstalled = false;
        tool.isEnabled = true;
        tool.isPortable = false;
        tool.status = "not_installed";
        tool.tags = {"Open Source", "The Sleuth Kit", "Forensics"};
        m_tools.append(tool);
    }

    // Registry Explorer
    {
        ToolInfo tool;
        tool.id = 32;
        tool.name = "Registry Explorer";
        tool.category = "Digital Forensics";
        tool.description = "Eric Zimmerman开发的注册表分析工具";
        tool.version = "2.0";
        tool.path = "C:\\Tools\\RegistryExplorer\\RegistryExplorer.exe";
        tool.downloadUrl = "https://github.com/EricZimmerman/Registry";
        tool.supportedOS = {"Windows 7+", "Windows Server 2012+"};
        tool.arguments = {"-i", "<registry_hive>"};
        tool.scanOptions = {"Registry Hives", "MRU", "Run Keys"};
        tool.icon = "registry";
        tool.isInstalled = false;
        tool.isEnabled = true;
        tool.isPortable = true;
        tool.status = "not_installed";
        tool.tags = {"Eric Zimmerman", "Registry", "Forensics"};
        m_tools.append(tool);
    }
}

void ThirdPartyToolsManager::initializeWebSecurityTools() {
    // Burp Suite
    {
        ToolInfo tool;
        tool.id = 40;
        tool.name = "Burp Suite";
        tool.category = "Web Security";
        tool.description = "Web应用安全测试平台";
        tool.version = "2023";
        tool.path = "C:\\Program Files\\BurpSuite\\burp.exe";
        tool.downloadUrl = "https://portswigger.net/burp";
        tool.supportedOS = {"Windows 7+", "macOS", "Linux"};
        tool.arguments = {};
        tool.scanOptions = {"Proxy", "Scanner", "Intruder", "Repeater"};
        tool.icon = "web";
        tool.isInstalled = false;
        tool.isEnabled = true;
        tool.isPortable = false;
        tool.status = "not_installed";
        tool.tags = {"PortSwigger", "Web Security", "Penetration Testing"};
        m_tools.append(tool);
    }

    // OWASP ZAP
    {
        ToolInfo tool;
        tool.id = 41;
        tool.name = "OWASP ZAP";
        tool.category = "Web Security";
        tool.description = "开源Web应用安全扫描器";
        tool.version = "2.13";
        tool.path = "C:\\Program Files\\OWASP\\Zed Attack Proxy\\zap.bat";
        tool.downloadUrl = "https://www.zaproxy.org/download/";
        tool.supportedOS = {"Windows 7+", "macOS", "Linux"};
        tool.arguments = {};
        tool.scanOptions = {"Proxy", "Active Scan", "Passive Scan"};
        tool.icon = "web";
        tool.isInstalled = false;
        tool.isEnabled = true;
        tool.isPortable = true;
        tool.status = "not_installed";
        tool.tags = {"OWASP", "Open Source", "Web Security"};
        m_tools.append(tool);
    }
}

void ThirdPartyToolsManager::initializeSystemTools() {
    // Sysinternals Suite
    {
        ToolInfo tool;
        tool.id = 50;
        tool.name = "Sysinternals Suite";
        tool.category = "System Tools";
        tool.description = "微软Sysinternals工具箱，包含70+系统工具";
        tool.version = "2023";
        tool.path = "C:\\Tools\\Sysinternals";
        tool.downloadUrl = "https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite";
        tool.supportedOS = {"Windows XP+", "Windows Server 2003+"};
        tool.arguments = {};
        tool.scanOptions = {"Process", "Security", "Network", "Disk"};
        tool.icon = "system";
        tool.isInstalled = false;
        tool.isEnabled = true;
        tool.isPortable = true;
        tool.status = "not_installed";
        tool.tags = {"Microsoft", "Sysinternals", "System"};
        m_tools.append(tool);
    }

    // NirSoft Suite
    {
        ToolInfo tool;
        tool.id = 51;
        tool.name = "NirSoft Suite";
        tool.category = "System Tools";
        tool.description = "NirSoft工具箱，包含100+系统实用工具";
        tool.version = "2023";
        tool.path = "C:\\Tools\\NirSoft";
        tool.downloadUrl = "https://www.nirsoft.net/utils/index.html";
        tool.supportedOS = {"Windows XP+", "Windows Server 2003+"};
        tool.arguments = {};
        tool.scanOptions = {"Password", "Network", "System", "Security"};
        tool.icon = "system";
        tool.isInstalled = false;
        tool.isEnabled = true;
        tool.isPortable = true;
        tool.status = "not_installed";
        tool.tags = {"NirSoft", "Utilities", "Password"};
        m_tools.append(tool);
    }
}

// ========== 辅助方法 ==========

bool ThirdPartyToolsManager::checkToolPath(const QString& path) {
    return QFile::exists(path);
}

bool ThirdPartyToolsManager::checkToolVersion(const QString& path, QString& version) {
    Q_UNUSED(path)
    version = "";
    return false;
}

QString ThirdPartyToolsManager::buildCommand(const ToolInfo& tool, const QStringList& args) {
    QString command;

    // 根据工具类型构建命令
    if (tool.path.endsWith(".exe", Qt::CaseInsensitive)) {
        command = "\"" + tool.path + "\"";
        for (const QString& arg : args) {
            command += " " + arg;
        }
    } else if (tool.path.endsWith(".bat", Qt::CaseInsensitive)) {
        command = "cmd /c \"" + tool.path + "\"";
        for (const QString& arg : args) {
            command += " " + arg;
        }
    } else if (tool.path.endsWith(".py", Qt::CaseInsensitive)) {
        command = "python \"" + tool.path + "\"";
        for (const QString& arg : args) {
            command += " " + arg;
        }
    }

    return command;
}

QString ThirdPartyToolsManager::parseOutputFormat(const QString& format) {
    Q_UNUSED(format)
    return "text";
}

bool ThirdPartyToolsManager::executeTool(const QString& command, const QStringList& args, ToolResult& result) {
    QProcess process;
    result.outputFile = getToolOutputPath(result.toolId);

    process.start(command + " " + args.join(" "));
    process.waitForFinished(60000); // 60秒超时

    result.exitCode = process.exitCode();
    result.output = process.readAllStandardOutput();

    return result.exitCode == 0;
}

QString ThirdPartyToolsManager::getConfigPath() {
    return "config/third_party_tools.json";
}

QJsonObject ThirdPartyToolsManager::loadConfig() {
    QFile file(getConfigPath());
    if (!file.open(QIODevice::ReadOnly)) {
        return QJsonObject();
    }

    QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    file.close();
    return doc.object();
}

bool ThirdPartyToolsManager::saveConfig(const QJsonObject& config) {
    QFile file(getConfigPath());
    if (!file.open(QIODevice::WriteOnly)) {
        return false;
    }

    QJsonDocument doc(config);
    file.write(doc.toJson(QJsonDocument::Indented));
    file.close();
    return true;
}

QJsonObject ThirdPartyToolsManager::loadToolConfig(int toolId) {
    QJsonObject config = loadConfig();
    QString key = QString("tool_%1").arg(toolId);
    return config[key].toObject();
}

bool ThirdPartyToolsManager::saveToolConfigToFile(int toolId, const QJsonObject& config) {
    QJsonObject allConfig = loadConfig();
    QString key = QString("tool_%1").arg(toolId);
    allConfig[key] = config;
    return saveConfig(allConfig);
}

bool ThirdPartyToolsManager::downloadFile(const QString& url, const QString& path, int& progress) {
    Q_UNUSED(url)
    Q_UNUSED(path)
    progress = 100;
    return true;
}

bool ThirdPartyToolsManager::extractArchive(const QString& archivePath, const QString& destPath) {
    Q_UNUSED(archivePath)
    Q_UNUSED(destPath)
    return true;
}

void ThirdPartyToolsManager::createToolTemplate() {
    // 工具模板创建
}
