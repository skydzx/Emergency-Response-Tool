#ifndef PERFORMANCEOPTIMIZER_H
#define PERFORMANCEOPTIMIZER_H

#include <QObject>
#include <QString>
#include <QJsonObject>
#include <QThread>
#include <QMutex>
#include <QWaitCondition>

class PerformanceOptimizer : public QObject {
    Q_OBJECT

public:
    explicit PerformanceOptimizer(QObject *parent = nullptr);
    ~PerformanceOptimizer();

    // 单例获取
    static PerformanceOptimizer* instance();

    // 缓存管理
    void setCacheEnabled(bool enabled);
    bool isCacheEnabled() const;
    void clearCache();
    void setCacheSize(size_t maxSize);
    size_t getCacheSize() const;

    // 线程池管理
    int getOptimalThreadCount() const;
    void setMaxThreadCount(int count);
    int getMaxThreadCount() const;

    // 内存管理
    void setMemoryLimit(size_t limit);
    size_t getMemoryUsage() const;
    void trimMemory();

    // I/O优化
    void setReadBufferSize(size_t size);
    size_t getReadBufferSize() const;
    void enableFileMapping(bool enable);
    bool isFileMappingEnabled() const;

    // 数据库优化
    void setDatabaseCacheSize(int size);
    void optimizeDatabase(const QString& dbPath);
    void vacuumDatabase(const QString& dbPath);

    // 任务调度
    bool scheduleTask(const QString& taskId, int priority, const QJsonObject& params);
    bool cancelTask(const QString& taskId);
    void pauseAllTasks();
    void resumeAllTasks();

    // 性能监控
    double getCpuUsage() const;
    double getMemoryUsage() const;
    double getDiskIoUsage() const;
    double getNetworkUsage() const;
    QJsonObject getPerformanceStats() const;

signals:
    void performanceWarning(const QString& metric, double value);
    void taskCompleted(const QString& taskId);
    void cacheCleared();

private:
    static PerformanceOptimizer* m_instance;
    static QMutex m_mutex;

    bool m_cacheEnabled;
    size_t m_cacheSize;
    size_t m_maxCacheSize;

    int m_maxThreadCount;
    size_t m_memoryLimit;
    size_t m_readBufferSize;
    bool m_fileMappingEnabled;

    int m_databaseCacheSize;

    bool m_tasksPaused;

    void initializeDefaults();
    size_t getAvailableMemory() const;
    int calculateOptimalThreads() const;
};

#endif // PERFORMANCEOPTIMIZER_H
