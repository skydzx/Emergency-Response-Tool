-- Emergency Response Tool Database Schema
-- SQLite Database Initialization Script
-- Version: 1.0.0
-- Date: 2024

-- ============================================
-- 1. 扫描会话表
-- ============================================
CREATE TABLE IF NOT EXISTS scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_name TEXT NOT NULL,
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    status TEXT DEFAULT 'running',
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_sessions_status ON scan_sessions(status);
CREATE INDEX IF NOT EXISTS idx_sessions_time ON scan_sessions(start_time);

-- ============================================
-- 2. 进程信息表
-- ============================================
CREATE TABLE IF NOT EXISTS processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    pid INTEGER,
    name TEXT,
    path TEXT,
    command_line TEXT,
    user TEXT,
    session_id_str TEXT,
    memory_usage INTEGER,
    cpu_usage REAL,
    start_time DATETIME,
    is_suspended BOOLEAN DEFAULT FALSE,
    parent_pid TEXT,
    description TEXT,
    company TEXT,
    file_hash TEXT,
    is_signed BOOLEAN,
    is_verified BOOLEAN,
    is_suspicious BOOLEAN DEFAULT FALSE,
    suspicious_reason TEXT,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_processes_pid ON processes(pid);
CREATE INDEX IF NOT EXISTS idx_processes_name ON processes(name);
CREATE INDEX IF NOT EXISTS idx_processes_suspicious ON processes(is_suspicious);
CREATE INDEX IF NOT EXISTS idx_processes_session ON processes(session_id);

-- ============================================
-- 3. 网络连接表
-- ============================================
CREATE TABLE IF NOT EXISTS network_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    local_address TEXT,
    local_port INTEGER,
    remote_address TEXT,
    remote_port INTEGER,
    protocol TEXT,
    state TEXT,
    process_id INTEGER,
    process_name TEXT,
    owner TEXT,
    is_suspicious BOOLEAN DEFAULT FALSE,
    suspicious_reason TEXT,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_network_local ON network_connections(local_address, local_port);
CREATE INDEX IF NOT EXISTS idx_network_remote ON network_connections(remote_address, remote_port);
CREATE INDEX IF NOT EXISTS idx_network_protocol ON network_connections(protocol);
CREATE INDEX IF NOT EXISTS idx_network_suspicious ON network_connections(is_suspicious);
CREATE INDEX IF NOT EXISTS idx_network_session ON network_connections(session_id);

-- ============================================
-- 4. 文件信息表
-- ============================================
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    path TEXT,
    name TEXT,
    size INTEGER,
    hash_md5 TEXT,
    hash_sha256 TEXT,
    hash_sha1 TEXT,
    create_time DATETIME,
    modify_time DATETIME,
    access_time DATETIME,
    attributes TEXT,
    owner TEXT,
    is_suspicious BOOLEAN DEFAULT FALSE,
    suspicious_reason TEXT,
    file_type TEXT,
    description TEXT,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
CREATE INDEX IF NOT EXISTS idx_files_hash ON files(hash_md5);
CREATE INDEX IF NOT EXISTS idx_files_hash_sha256 ON files(hash_sha256);
CREATE INDEX IF NOT EXISTS idx_files_suspicious ON files(is_suspicious);
CREATE INDEX IF NOT EXISTS idx_files_session ON files(session_id);

-- ============================================
-- 5. 威胁检测结果表
-- ============================================
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    threat_type TEXT,
    threat_name TEXT,
    description TEXT,
    severity TEXT,
    file_path TEXT,
    process_id INTEGER,
    detection_time DATETIME,
    status TEXT DEFAULT 'detected',
    remediation TEXT,
    reference TEXT,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_threats_type ON threats(threat_type);
CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_session ON threats(session_id);

-- ============================================
-- 6. 日志记录表
-- ============================================
CREATE TABLE IF NOT EXISTS log_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    log_type TEXT,
    timestamp DATETIME,
    source TEXT,
    event_id INTEGER,
    level TEXT,
    message TEXT,
    raw_data TEXT,
    is_anomaly BOOLEAN DEFAULT FALSE,
    anomaly_reason TEXT,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_logs_type ON log_entries(log_type);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON log_entries(timestamp);
CREATE INDEX IF NOT EXISTS idx_logs_level ON log_entries(level);
CREATE INDEX IF NOT EXISTS idx_logs_anomaly ON log_entries(is_anomaly);
CREATE INDEX IF NOT EXISTS idx_logs_session ON log_entries(session_id);

-- ============================================
-- 7. WebShell检测结果表
-- ============================================
CREATE TABLE IF NOT EXISTS webshell_threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    file_path TEXT NOT NULL,
    threat_type TEXT,
    description TEXT,
    severity TEXT,
    detection_tool TEXT,
    signature TEXT,
    file_hash TEXT,
    file_content TEXT,
    is_confirmed BOOLEAN DEFAULT FALSE,
    detection_time DATETIME,
    tags TEXT,
    scan_options TEXT,
    recommendation TEXT,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_webshell_path ON webshell_threats(file_path);
CREATE INDEX IF NOT EXISTS idx_webshell_type ON webshell_threats(threat_type);
CREATE INDEX IF NOT EXISTS idx_webshell_severity ON webshell_threats(severity);
CREATE INDEX IF NOT EXISTS idx_webshell_tool ON webshell_threats(detection_tool);
CREATE INDEX IF NOT EXISTS idx_webshell_session ON webshell_threats(session_id);

-- ============================================
-- 8. WebShell检测规则表
-- ============================================
CREATE TABLE IF NOT EXISTS webshell_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT NOT NULL,
    rule_pattern TEXT NOT NULL,
    rule_type TEXT,
    severity TEXT,
    description TEXT,
    category TEXT,
    is_enabled BOOLEAN DEFAULT TRUE,
    match_count INTEGER DEFAULT 0,
    created_time DATETIME,
    updated_time DATETIME
);

CREATE INDEX IF NOT EXISTS idx_rules_name ON webshell_rules(rule_name);
CREATE INDEX IF NOT EXISTS idx_rules_type ON webshell_rules(rule_type);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON webshell_rules(is_enabled);

-- ============================================
-- 9. WebShell检测工具配置表
-- ============================================
CREATE TABLE IF NOT EXISTS webshell_tools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name TEXT NOT NULL,
    tool_path TEXT,
    tool_version TEXT,
    is_available BOOLEAN DEFAULT FALSE,
    last_check_time DATETIME,
    scan_options TEXT,
    supported_extensions TEXT,
    description TEXT
);

CREATE INDEX IF NOT EXISTS idx_tools_name ON webshell_tools(tool_name);
CREATE INDEX IF NOT EXISTS idx_tools_available ON webshell_tools(is_available);

-- ============================================
-- 10. 内置字典表
-- ============================================
CREATE TABLE IF NOT EXISTS builtin_dictionary (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT,
    name TEXT,
    pattern TEXT,
    type TEXT,
    description TEXT,
    hash TEXT,
    suffix TEXT,
    process_name TEXT,
    file_name TEXT,
    severity TEXT,
    tags TEXT,
    update_time DATETIME,
    is_enabled BOOLEAN DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_dict_category ON builtin_dictionary(category);
CREATE INDEX IF NOT EXISTS idx_dict_name ON builtin_dictionary(name);
CREATE INDEX IF NOT EXISTS idx_dict_enabled ON builtin_dictionary(is_enabled);

-- ============================================
-- 11. 第三方工具配置表
-- ============================================
CREATE TABLE IF NOT EXISTS third_party_tools (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name TEXT NOT NULL,
    tool_category TEXT,
    tool_path TEXT,
    tool_version TEXT,
    is_installed BOOLEAN DEFAULT FALSE,
    is_enabled BOOLEAN DEFAULT TRUE,
    last_check_time DATETIME,
    configuration TEXT,
    description TEXT
);

CREATE INDEX IF NOT EXISTS idx_tptools_name ON third_party_tools(tool_name);
CREATE INDEX IF NOT EXISTS idx_tptools_category ON third_party_tools(tool_category);
CREATE INDEX IF NOT EXISTS idx_tptools_installed ON third_party_tools(is_installed);

-- ============================================
-- 12. 取证数据表
-- ============================================
CREATE TABLE IF NOT EXISTS forensics_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER,
    data_type TEXT,
    data_name TEXT,
    data_path TEXT,
    data_content TEXT,
    acquisition_time DATETIME,
    data_size INTEGER,
    checksum TEXT,
    description TEXT,
    FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
);

CREATE INDEX IF NOT EXISTS idx_forensics_type ON forensics_data(data_type);
CREATE INDEX IF NOT EXISTS idx_forensics_session ON forensics_data(session_id);

-- ============================================
-- 13. 报告模板表
-- ============================================
CREATE TABLE IF NOT EXISTS report_templates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    template_name TEXT NOT NULL,
    template_type TEXT,
    template_content TEXT,
    is_default BOOLEAN DEFAULT FALSE,
    created_time DATETIME,
    updated_time DATETIME
);

CREATE INDEX IF NOT EXISTS idx_templates_name ON report_templates(template_name);
CREATE INDEX IF NOT EXISTS idx_templates_type ON report_templates(template_type);

-- ============================================
-- 14. 系统配置表
-- ============================================
CREATE TABLE IF NOT EXISTS system_config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    config_key TEXT UNIQUE NOT NULL,
    config_value TEXT,
    config_type TEXT,
    description TEXT,
    updated_time DATETIME
);

CREATE INDEX IF NOT EXISTS idx_config_key ON system_config(config_key);

-- ============================================
-- 初始化默认配置
-- ============================================
INSERT OR REPLACE INTO system_config (config_key, config_value, config_type, description, updated_time)
VALUES
    ('db_version', '1.0.0', 'version', '数据库版本', datetime('now')),
    ('auto_backup', 'true', 'boolean', '是否自动备份', datetime('now')),
    ('max_session_history', '30', 'integer', '最大保存会话数', datetime('now')),
    ('log_retention_days', '90', 'integer', '日志保留天数', datetime('now'));

-- ============================================
-- 插入默认WebShell检测规则
-- ============================================
INSERT OR IGNORE INTO webshell_rules (rule_name, rule_pattern, rule_type, severity, description, category, is_enabled, created_time)
VALUES
    ('PHP_eval_POST', 'eval\\(\\$_POST\\[.+\\]\\)', 'php', 'high', 'PHP eval一句话木马', 'php_eval', 1, datetime('now')),
    ('PHP_assert_POST', 'assert\\(\\s*\\$\\{', 'php', 'high', 'PHP assert可变变量', 'php_assert', 1, datetime('now')),
    ('JSP_Runtime_exec', 'Class\\.forName\\(\"java\\.lang\\.Runtime\"\\)', 'jsp', 'high', 'JSP Runtime执行', 'jsp_exec', 1, datetime('now')),
    ('ASP_script_execute', 'Execute\\(\\$_POST\\[.+\\]\\)', 'asp', 'high', 'ASP脚本执行', 'asp_exec', 1, datetime('now'));

-- ============================================
-- 插入默认WebShell检测工具
-- ============================================
INSERT OR IGNORE INTO webshell_tools (tool_name, tool_path, tool_version, is_available, description)
VALUES
    ('D盾WebShellKill', 'C:\\Program Files\\D盾\\WebShellKill.exe', '', 0, 'D盾WebShellKill专业WebShell检测工具'),
    ('河马查杀', 'C:\\Program Files\\河马\\hippo.exe', '', 0, '河马WebShell查杀工具');

PRINT 'Database schema initialization completed successfully!';
