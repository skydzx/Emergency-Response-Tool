#include "PerformanceOptimizer.h"
#include <QApplication>
#include <QThread>
#include <QFile>
#include <QDir>
#include <QDebug>

PerformanceOptimizer* PerformanceOptimizer::m_instance = nullptr;
QMutex PerformanceOptimizer::m_mutex;

PerformanceOptimizer* PerformanceOptimizer::instance()
{
    if (m_instance == nullptr) {
        QMutexLocker locker(&m_mutex);
        if (m_instance == nullptr) {
            m_instance = new PerformanceOptimizer();
        }
    }
    return m_instance;
}

PerformanceOptimizer::PerformanceOptimizer(QObject *parent)
    : QObject(parent)
    , m_cacheEnabled(true)
    , m_cacheSize(0)
    , m_maxCacheSize(100 * 1024 * 1024) // 100MB
    , m_maxThreadCount(0)
    , m_memoryLimit(0)
    , m_readBufferSize(8192)
    , m_fileMappingEnabled(true)
    , m_databaseCacheSize(10000)
    , m_tasksPaused(false)
{
    initializeDefaults();
}

PerformanceOptimizer::~PerformanceOptimizer()
{
}

void PerformanceOptimizer::initializeDefaults()
{
    // 根据系统资源自动计算最优线程数
    m_maxThreadCount = calculateOptimalThreads();

    // 设置合理的内存限制
    m_memoryLimit = getAvailableMemory() / 2;
}

void PerformanceOptimizer::setCacheEnabled(bool enabled)
{
    m_cacheEnabled = enabled;
}

bool PerformanceOptimizer::isCacheEnabled() const
{
    return m_cacheEnabled;
}

void PerformanceOptimizer::clearCache()
{
    m_cacheSize = 0;
    emit cacheCleared();
}

void PerformanceOptimizer::setCacheSize(size_t maxSize)
{
    m_maxCacheSize = maxSize;
}

size_t PerformanceOptimizer::getCacheSize() const
{
    return m_cacheSize;
}

int PerformanceOptimizer::getOptimalThreadCount() const
{
    return m_maxThreadCount;
}

void PerformanceOptimizer::setMaxThreadCount(int count)
{
    m_maxThreadCount = qMax(1, count);
}

int PerformanceOptimizer::getMaxThreadCount() const
{
    return m_maxThreadCount;
}

void PerformanceOptimizer::setMemoryLimit(size_t limit)
{
    m_memoryLimit = limit;
}

size_t PerformanceOptimizer::getMemoryUsage() const
{
#if defined(Q_OS_WIN)
    // Windows内存使用获取
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(memInfo);
    GlobalMemoryStatusEx(&memInfo);
    return memInfo.ullTotalPhys - memInfo.ullAvailPhys;
#elif defined(Q_OS_LINUX)
    // Linux内存使用获取
    QFile file("/proc/self/status");
    if (file.open(QIODevice::ReadOnly)) {
        QString content = file.readAll();
        file.close();
        QStringList lines = content.split("\n");
        for (const QString& line : lines) {
            if (line.startsWith("VmRSS:")) {
                QString value = line.split(":")[1].trimmed();
                return value.split(" ")[0].toULongLong() * 1024;
            }
        }
    }
#endif
    return 0;
}

size_t PerformanceOptimizer::getAvailableMemory() const
{
#if defined(Q_OS_WIN)
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(memInfo);
    GlobalMemoryStatusEx(&memInfo);
    return memInfo.ullAvailPhys;
#elif defined(Q_OS_LINUX)
    QFile file("/proc/meminfo");
    if (file.open(QIODevice::ReadOnly)) {
        QString content = file.readAll();
        file.close();
        QStringList lines = content.split("\n");
        for (const QString& line : lines) {
            if (line.startsWith("MemAvailable:")) {
                QString value = line.split(":")[1].trimmed();
                return value.split(" ")[0].toULongLong() * 1024;
            }
        }
    }
#endif
    return 512 * 1024 * 1024; // 默认512MB
}

void PerformanceOptimizer::trimMemory()
{
#if defined(Q_OS_WIN)
    SetProcessWorkingSetSize(GetCurrentProcess(), (SIZE_T)-1, (SIZE_T)-1);
#endif
}

void PerformanceOptimizer::setReadBufferSize(size_t size)
{
    m_readBufferSize = size;
}

size_t PerformanceOptimizer::getReadBufferSize() const
{
    return m_readBufferSize;
}

void PerformanceOptimizer::enableFileMapping(bool enable)
{
    m_fileMappingEnabled = enable;
}

bool PerformanceOptimizer::isFileMappingEnabled() const
{
    return m_fileMappingEnabled;
}

void PerformanceOptimizer::setDatabaseCacheSize(int size)
{
    m_databaseCacheSize = size;
}

void PerformanceOptimizer::optimizeDatabase(const QString& dbPath)
{
    Q_UNUSED(dbPath)
    // 数据库优化查询
}

void PerformanceOptimizer::vacuumDatabase(const QString& dbPath)
{
    Q_UNUSED(dbPath)
    // 数据库VACUUM操作
}

bool PerformanceOptimizer::scheduleTask(const QString& taskId, int priority, const QJsonObject& params)
{
    Q_UNUSED(taskId)
    Q_UNUSED(priority)
    Q_UNUSED(params)
    return true;
}

bool PerformanceOptimizer::cancelTask(const QString& taskId)
{
    Q_UNUSED(taskId)
    return true;
}

void PerformanceOptimizer::pauseAllTasks()
{
    m_tasksPaused = true;
}

void PerformanceOptimizer::resumeAllTasks()
{
    m_tasksPaused = false;
}

double PerformanceOptimizer::getCpuUsage() const
{
    // 简化的CPU使用率计算
    return 0.0;
}

double PerformanceOptimizer::getMemoryUsagePercent() const
{
    size_t total = getAvailableMemory() + getMemoryUsage();
    if (total == 0) return 0.0;
    return (double)getMemoryUsage() / total * 100.0;
}

double PerformanceOptimizer::getDiskIoUsage() const
{
    return 0.0;
}

double PerformanceOptimizer::getNetworkUsage() const
{
    return 0.0;
}

QJsonObject PerformanceOptimizer::getPerformanceStats() const
{
    QJsonObject stats;
    stats["cpuUsage"] = getCpuUsage();
    stats["memoryUsage"] = getMemoryUsage();
    stats["memoryUsagePercent"] = getMemoryUsagePercent();
    stats["diskIoUsage"] = getDiskIoUsage();
    stats["networkUsage"] = getNetworkUsage();
    stats["threadCount"] = m_maxThreadCount;
    stats["cacheSize"] = (qint64)m_cacheSize;
    stats["cacheEnabled"] = m_cacheEnabled;
    return stats;
}

int PerformanceOptimizer::calculateOptimalThreads() const
{
    // 根据CPU核心数和系统负载计算最优线程数
    int cores = QThread::idealThreadCount();
    if (cores < 1) cores = 2;

    // 考虑I/O密集型任务，使用较多的线程
    return qMin(cores * 2, 16);
}
