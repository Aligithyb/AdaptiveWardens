-- Sessions Table
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    source_ip TEXT NOT NULL,
    source_port INTEGER,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP,
    protocol TEXT CHECK(protocol IN ('ssh', 'http')),
    username TEXT,
    password TEXT,
    status TEXT CHECK(status IN ('active', 'closed', 'timeout')),
    command_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sessions_ip ON sessions(source_ip);
CREATE INDEX idx_sessions_time ON sessions(start_time);
CREATE INDEX idx_sessions_status ON sessions(status);

-- Filesystem Table
CREATE TABLE IF NOT EXISTS filesystem (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    path TEXT NOT NULL,
    file_type TEXT CHECK(file_type IN ('file', 'directory', 'symlink')),
    content BLOB,
    size INTEGER DEFAULT 0,
    permissions TEXT DEFAULT '644',
    owner TEXT DEFAULT 'root',
    group_name TEXT DEFAULT 'root',
    created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    modified_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    accessed_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    UNIQUE(session_id, path)
);

CREATE INDEX idx_filesystem_session ON filesystem(session_id);
CREATE INDEX idx_filesystem_path ON filesystem(path);

-- Processes Table
CREATE TABLE IF NOT EXISTS processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    pid INTEGER NOT NULL,
    ppid INTEGER DEFAULT 1,
    name TEXT NOT NULL,
    cmdline TEXT,
    username TEXT DEFAULT 'root',
    status TEXT CHECK(status IN ('running', 'sleeping', 'stopped', 'zombie')),
    cpu_percent REAL DEFAULT 0.0,
    mem_percent REAL DEFAULT 0.0,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    UNIQUE(session_id, pid)
);

CREATE INDEX idx_processes_session ON processes(session_id);
CREATE INDEX idx_processes_pid ON processes(pid);

-- System Logs Table
CREATE TABLE IF NOT EXISTS system_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    log_source TEXT, -- auth.log, syslog, kern.log, etc.
    log_level TEXT CHECK(log_level IN ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')),
    message TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_logs_session ON system_logs(session_id);
CREATE INDEX idx_logs_timestamp ON system_logs(timestamp);

-- Command History Table
CREATE TABLE IF NOT EXISTS command_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    sequence_number INTEGER NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    command TEXT NOT NULL,
    output TEXT,
    exit_code INTEGER DEFAULT 0,
    duration_ms INTEGER,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_history_session ON command_history(session_id);
CREATE INDEX idx_history_seq ON command_history(session_id, sequence_number);

-- Environment Variables Table
CREATE TABLE IF NOT EXISTS environment_vars (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT,
    scope TEXT DEFAULT 'session', -- 'global', 'session', 'user'
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    UNIQUE(session_id, key, scope)
);

-- Network Connections Table
CREATE TABLE IF NOT EXISTS network_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    protocol TEXT, -- tcp, udp
    local_address TEXT,
    local_port INTEGER,
    remote_address TEXT,
    remote_port INTEGER,
    state TEXT,
    pid INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

-- IOCs (Indicators of Compromise) Table
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    ioc_type TEXT CHECK(ioc_type IN ('ip', 'domain', 'url', 'hash', 'email', 'filename', 'command')),
    value TEXT NOT NULL,
    confidence REAL DEFAULT 0.5, -- 0.0 to 1.0
    context TEXT, -- where it was found
    extracted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_iocs_session ON iocs(session_id);
CREATE INDEX idx_iocs_type ON iocs(ioc_type);
CREATE INDEX idx_iocs_value ON iocs(value);

-- MITRE ATT&CK Techniques Table
CREATE TABLE IF NOT EXISTS attack_techniques (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    technique_id TEXT NOT NULL, -- T1059.004
    technique_name TEXT,
    tactic TEXT, -- Execution, Persistence, etc.
    confidence REAL DEFAULT 0.5,
    evidence TEXT, -- command or behavior that triggered
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_attack_session ON attack_techniques(session_id);
CREATE INDEX idx_attack_technique ON attack_techniques(technique_id);

-- State Snapshots Table (for rollback)
CREATE TABLE IF NOT EXISTS state_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    snapshot_data TEXT, -- JSON dump of entire state
    snapshot_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    checksum TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX idx_snapshots_session ON state_snapshots(session_id);
