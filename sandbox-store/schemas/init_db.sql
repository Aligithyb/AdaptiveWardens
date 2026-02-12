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
-- Add other tables from the implementation guide...
-- (Filesystem, Processes, Logs, Commands, IOCs, ATT&CK, etc.)
