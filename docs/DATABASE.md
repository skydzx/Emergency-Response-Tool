# 数据库设计文档

## 概述

应急响应工具使用SQLite作为本地数据库，存储系统信息、威胁检测结果、日志记录、WebShell检测结果等数据。

## 数据库结构

### 1. scan_sessions (扫描会话表)

存储每次扫描/分析会话的基本信息。

| 字段 | 类型 | 描述 |
|------|------|------|
| id | INTEGER | 主键，自增 |
| session_name | TEXT | 会话名称 |
| start_time | DATETIME | 开始时间 |
| end_time | DATETIME | 结束时间 |
| status | TEXT | 状态(running/completed) |
| description | TEXT | 描述 |
| created_at | DATETIME | 创建时间 |

### 2. processes (进程信息表)

存储系统进程信息。

| 字段 | 类型 | 描述 |
|------|------|------|
| id | INTEGER | 主键 |
| session_id | INTEGER | 外键，关联会话 |
| pid | INTEGER | 进程ID |
| name | TEXT | 进程名 |
| path | TEXT | 进程路径 |
| command_line | TEXT | 命令行 |
| user | TEXT | 所属用户 |
| memory_usage | INTEGER | 内存使用(KB) |
| cpu_usage | REAL | CPU使用率 |
| is_signed | BOOLEAN | 是否签名 |
| is_verified | BOOLEAN | 是否验证 |
| is_suspicious | BOOLEAN | 是否可疑 |
| suspicious_reason | TEXT | 可疑原因 |

### 3. network_connections (网络连接表)

存储网络连接信息。

| 字段 | 类型 | 描述 |
|------|------|------|
| id | INTEGER | 主键 |
| session_id | INTEGER | 外键 |
| local_address | TEXT | 本地地址 |
| local_port | INTEGER | 本地端口 |
| remote_address | TEXT | 远程地址 |
| remote_port | INTEGER | 远程端口 |
| protocol | TEXT | 协议(TCP/UDP) |
| state | TEXT | 状态 |
| process_id | INTEGER | 关联进程ID |
| process_name | TEXT | 进程名 |
| is_suspicious | BOOLEAN | 是否可疑 |

### 4. files (文件信息表)

存储文件扫描结果。

| 字段 | 类型 | 描述 |
|------|------|------|
| id | INTEGER | 主键 |
| session_id | INTEGER | 外键 |
| path | TEXT | 文件路径 |
| name | TEXT | 文件名 |
| size | INTEGER | 文件大小 |
| hash_md5 | TEXT | MD5哈希 |
| hash_sha256 | TEXT | SHA256哈希 |
| hash_sha1 | TEXT | SHA1哈希 |
| create_time | DATETIME | 创建时间 |
| modify_time | DATETIME | 修改时间 |
| is_suspicious | BOOLEAN | 是否可疑 |
| suspicious_reason | TEXT | 可疑原因 |
| file_type | TEXT | 文件类型 |

### 5. threats (威胁检测结果表)

存储威胁检测结果。

| 字段 | 类型 | 描述 |
|------|------|------|
| id | INTEGER | 主键 |
| session_id | INTEGER | 外键 |
| threat_type | TEXT | 威胁类型 |
| threat_name | TEXT | 威胁名称 |
| description | TEXT | 描述 |
| severity | TEXT | 严重程度 |
| file_path | TEXT | 文件路径 |
| process_id | INTEGER | 进程ID |
| detection_time | DATETIME | 检测时间 |
| status | TEXT | 状态 |
| remediation | TEXT | 处理建议 |
| reference | TEXT | 参考信息 |

### 6. log_entries (日志条目表)

存储日志分析结果。

| 字段 | 类型 | 描述 |
|------|------|------|
| id | INTEGER | 主键 |
| session_id | INTEGER | 外键 |
| log_type | TEXT | 日志类型 |
| timestamp | DATETIME | 时间戳 |
| source | TEXT | 来源 |
| event_id | INTEGER | 事件ID |
| level | TEXT | 级别 |
| message | TEXT | 消息 |
| raw_data | TEXT | 原始数据 |
| is_anomaly | BOOLEAN | 是否异常 |
| anomaly_reason | TEXT | 异常原因 |

### 7. webshell_threats (WebShell检测结果表)

存储WebShell检测结果。

| 字段 | 类型 | 描述 |
|------|------|------|
| id | INTEGER | 主键 |
| session_id | INTEGER | 外键 |
| file_path | TEXT | 文件路径 |
| threat_type | TEXT | 威胁类型 |
| description | TEXT | 描述 |
| severity | TEXT | 严重程度 |
| detection_tool | TEXT | 检测工具 |
| signature | TEXT | 匹配特征 |
| file_hash | TEXT | 文件哈希 |
| file_content | TEXT | 文件内容 |
| is_confirmed | BOOLEAN | 是否确认 |
| detection_time | DATETIME | 检测时间 |
| tags | TEXT | 标签 |

### 8. webshell_rules (WebShell检测规则表)

存储WebShell检测规则。

| 字段 | 类型 | 描述 |
|------|------|------|
| id | INTEGER | 主键 |
| rule_name | TEXT | 规则名称 |
| rule_pattern | TEXT | 匹配模式 |
| rule_type | TEXT | 规则类型 |
| severity | TEXT | 严重程度 |
| description | TEXT | 描述 |
| category | TEXT | 分类 |
| is_enabled | BOOLEAN | 是否启用 |
| match_count | INTEGER | 匹配次数 |
| created_time | DATETIME | 创建时间 |
| updated_time | DATETIME | 更新时间 |

### 9. webshell_tools (WebShell检测工具表)

存储第三方WebShell检测工具配置。

| 字段 | 类型 | 描述 |
|------|------|------|
| id | INTEGER | 主键 |
| tool_name | TEXT | 工具名称 |
| tool_path | TEXT | 工具路径 |
| tool_version | TEXT | 版本 |
| is_available | BOOLEAN | 是否可用 |
| last_check_time | DATETIME | 最后检查 |
| scan_options | TEXT | 扫描选项 |
| supported_extensions | TEXT | 支持扩展名 |

### 10. builtin_dictionary (内置字典表)

存储内置恶意特征字典。

| 字段 | 类型 | 描述 |
|------|------|------|
| id | INTEGER | 主键 |
| category | TEXT | 分类 |
| name | TEXT | 名称 |
| pattern | TEXT | 匹配模式 |
| type | TEXT | 类型 |
| description | TEXT | 描述 |
| hash | TEXT | 哈希 |
| suffix | TEXT | 后缀 |
| process_name | TEXT | 进程名 |
| file_name | TEXT | 文件名 |
| severity | TEXT | 严重程度 |
| tags | TEXT | 标签 |
| update_time | DATETIME | 更新时间 |
| is_enabled | BOOLEAN | 是否启用 |

## 索引设计

为提高查询性能，创建了以下索引：

```sql
CREATE INDEX idx_sessions_status ON scan_sessions(status);
CREATE INDEX idx_sessions_time ON scan_sessions(start_time);
CREATE INDEX idx_processes_pid ON processes(pid);
CREATE INDEX idx_processes_name ON processes(name);
CREATE INDEX idx_processes_suspicious ON processes(is_suspicious);
CREATE INDEX idx_network_remote ON network_connections(remote_address, remote_port);
CREATE INDEX idx_files_hash_sha256 ON files(hash_sha256);
CREATE INDEX idx_threats_severity ON threats(severity);
CREATE INDEX idx_logs_anomaly ON log_entries(is_anomaly);
CREATE INDEX idx_webshell_severity ON webshell_threats(severity);
```

## 使用说明

### 初始化数据库

```cpp
DatabaseManager* db = DatabaseManager::instance();
db->initialize("data/emergency_response.db");
```

### 创建会话

```cpp
int sessionId = db->createSession("系统扫描");
```

### 添加进程信息

```cpp
QMap<QString, QVariant> process;
process["pid"] = 1234;
process["name"] = "suspicious.exe";
process["path"] = "C:\\temp\\suspicious.exe";
process["isSuspicious"] = true;
process["suspiciousReason"] = "未签名且位于临时目录";

db->addProcess(sessionId, process);
```

### 查询可疑进程

```cpp
auto processes = db->getProcesses(sessionId);
for (const auto& p : processes) {
    if (p["isSuspicious"].toBool()) {
        qDebug() << "发现可疑进程:" << p["name"];
    }
}
```

### 获取威胁统计

```cpp
auto threats = db->getThreats(sessionId);
int criticalCount = 0;
for (const auto& t : threats) {
    if (t["severity"].toString() == "critical") {
        criticalCount++;
    }
}
```

## 性能优化建议

1. **定期清理历史数据**：使用 `cleanupOldData(days)` 方法清理旧会话
2. **批量插入**：大量数据时使用事务提高性能
3. **合理使用索引**：根据查询模式添加适当的索引
4. **分页查询**：大量数据时使用LIMIT和OFFSET进行分页
