import sqlite3
import json
import os
import hashlib
from datetime import datetime
from typing import Optional, Dict, List, Any
from contextlib import contextmanager
import logging

logger = logging.getLogger(__name__)

class SandboxDatabase:
    """
    Manages all database operations for the sandbox state store.
    Implements ACID transactions and state consistency.
    """
    
    def __init__(self, db_path: str = "/data/honeypot.db"):
        self.db_path = db_path
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections with automatic cleanup."""
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row  # Access columns by name
        try:
            yield conn
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()
    
    def init_database(self):
        # Get schema path from environment or use default
        import os
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        schema_path = os.path.join(base_dir, 'schemas', 'init_db.sql')
        
        if not os.path.exists(schema_path):
            logger.warning(f"Schema file not found at {schema_path}")
            return
        
        with open(schema_path, 'r') as f:
            schema = f.read()
        
        with self.get_connection() as conn:
            conn.executescript(schema)
        
        logger.info(f"Database initialized from {schema_path}")
    
    # ==================== SESSION MANAGEMENT ====================
    
    def create_session(self, session_id: str, source_ip: str, 
                       protocol: str, username: str = None, 
                       password: str = None) -> bool:
        """Create a new honeypot session."""
        try:
            with self.get_connection() as conn:
                conn.execute("""
                    INSERT INTO sessions 
                    (session_id, source_ip, protocol, username, password, status)
                    VALUES (?, ?, ?, ?, ?, 'active')
                """, (session_id, source_ip, protocol, username, password))
                conn.commit()
                
                # Initialize default filesystem for this session
                self._init_default_filesystem(conn, session_id)
                
                # Initialize default processes
                self._init_default_processes(conn, session_id)
                
                # Initialize default environment
                self._init_default_environment(conn, session_id)
                
                conn.commit()
                logger.info(f"Created session {session_id} from {source_ip}")
                return True
        except sqlite3.IntegrityError:
            logger.warning(f"Session {session_id} already exists")
            return False
    
    def _init_default_filesystem(self, conn, session_id: str):
        """Create realistic default Linux filesystem structure."""
        default_dirs = [
            ('/home', 'directory', '755', 'root', 'root'),
            ('/home/ubuntu', 'directory', '755', 'ubuntu', 'ubuntu'),
            ('/root', 'directory', '700', 'root', 'root'),
            ('/etc', 'directory', '755', 'root', 'root'),
            ('/var', 'directory', '755', 'root', 'root'),
            ('/var/log', 'directory', '755', 'root', 'root'),
            ('/var/www', 'directory', '755', 'www-data', 'www-data'),
            ('/tmp', 'directory', '1777', 'root', 'root'),
            ('/usr', 'directory', '755', 'root', 'root'),
            ('/usr/bin', 'directory', '755', 'root', 'root'),
            ('/usr/local', 'directory', '755', 'root', 'root'),
        ]
        
        default_files = [
            ('/etc/passwd', 'file', 'root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n', '644'),
            ('/etc/shadow', 'file', 'root:$6$....:18000:0:99999:7:::\n', '000'),
            ('/etc/hostname', 'file', 'ubuntu-server\n', '644'),
            ('/etc/hosts', 'file', '127.0.0.1 localhost\n127.0.1.1 ubuntu-server\n', '644'),
            ('/home/ubuntu/.bashrc', 'file', '# .bashrc\nexport PS1="\\u@\\h:\\w\\$ "\n', '644'),
            ('/root/.bash_history', 'file', '', '600'),
        ]
        
        for path, file_type, perms, owner, group in default_dirs:
            conn.execute("""
                INSERT OR IGNORE INTO filesystem 
                (session_id, path, file_type, permissions, owner, group_name, size)
                VALUES (?, ?, ?, ?, ?, ?, 0)
            """, (session_id, path, file_type, perms, owner, group))
        
        for path, file_type, content, perms in default_files:
            conn.execute("""
                INSERT OR IGNORE INTO filesystem 
                (session_id, path, file_type, content, permissions, owner, group_name, size)
                VALUES (?, ?, ?, ?, ?, 'root', 'root', ?)
            """, (session_id, path, file_type, content, perms, len(content)))
    
    def _init_default_processes(self, conn, session_id: str):
        """Create realistic process list."""
        default_processes = [
            (1, 0, 'systemd', '/sbin/init', 'root', 'running', 0.1, 0.5),
            (2, 0, 'kthreadd', '', 'root', 'sleeping', 0.0, 0.0),
            (134, 1, 'sshd', '/usr/sbin/sshd -D', 'root', 'running', 0.0, 0.2),
            (567, 1, 'cron', '/usr/sbin/cron -f', 'root', 'running', 0.0, 0.1),
            (892, 1, 'nginx', 'nginx: master process', 'root', 'running', 0.1, 0.3),
        ]
        
        for pid, ppid, name, cmdline, user, status, cpu, mem in default_processes:
            conn.execute("""
                INSERT OR IGNORE INTO processes 
                (session_id, pid, ppid, name, cmdline, username, status, cpu_percent, mem_percent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (session_id, pid, ppid, name, cmdline, user, status, cpu, mem))
    
    def _init_default_environment(self, conn, session_id: str):
        """Create default environment variables."""
        default_env = {
            'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'HOME': '/root',
            'USER': 'root',
            'SHELL': '/bin/bash',
            'TERM': 'xterm-256color',
            'LANG': 'en_US.UTF-8',
        }
        
        for key, value in default_env.items():
            conn.execute("""
                INSERT OR IGNORE INTO environment_vars 
                (session_id, key, value, scope)
                VALUES (?, ?, ?, 'session')
            """, (session_id, key, value))
    
    def close_session(self, session_id: str):
        """Mark session as closed."""
        with self.get_connection() as conn:
            conn.execute("""
                UPDATE sessions 
                SET status = 'closed', end_time = CURRENT_TIMESTAMP
                WHERE session_id = ?
            """, (session_id,))
            conn.commit()
        logger.info(f"Closed session {session_id}")
    
    # ==================== FILESYSTEM OPERATIONS ====================
    
    def read_file(self, session_id: str, path: str) -> Optional[str]:
        """Read file content from sandbox filesystem."""
        with self.get_connection() as conn:
            result = conn.execute("""
                SELECT content FROM filesystem 
                WHERE session_id = ? AND path = ? AND file_type = 'file'
            """, (session_id, path)).fetchone()
            
            if result:
                return result['content']
            return None
    
    def write_file(self, session_id: str, path: str, content: str, 
                    permissions: str = '644') -> bool:
        """Write or update file in sandbox filesystem."""
        try:
            with self.get_connection() as conn:
                # Check if file exists
                existing = conn.execute("""
                    SELECT id FROM filesystem 
                    WHERE session_id = ? AND path = ?
                """, (session_id, path)).fetchone()
                
                now = datetime.now().isoformat()
                
                if existing:
                    # Update existing file
                    conn.execute("""
                        UPDATE filesystem 
                        SET content = ?, size = ?, modified_time = ?, accessed_time = ?
                        WHERE session_id = ? AND path = ?
                    """, (content, len(content), now, now, session_id, path))
                else:
                    # Create new file
                    conn.execute("""
                        INSERT INTO filesystem 
                        (session_id, path, file_type, content, size, permissions, 
                         owner, group_name, created_time, modified_time, accessed_time)
                        VALUES (?, ?, 'file', ?, ?, ?, 'root', 'root', ?, ?, ?)
                    """, (session_id, path, content, len(content), permissions, 
                          now, now, now))
                
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error writing file {path}: {e}")
            return False
    
    def list_directory(self, session_id: str, path: str) -> List[Dict]:
        """List directory contents."""
        if not path.endswith('/'):
            path += '/'
        
        with self.get_connection() as conn:
            results = conn.execute("""
                SELECT path, file_type, size, permissions, owner, group_name, 
                       modified_time
                FROM filesystem 
                WHERE session_id = ? AND path LIKE ? AND path != ?
            """, (session_id, f"{path}%", path)).fetchall()
            
            entries = []
            for row in results:
                # Only include direct children, not nested subdirectories
                rel_path = row['path'][len(path):]
                if '/' not in rel_path or rel_path.endswith('/'):
                    entries.append({
                        'name': rel_path.rstrip('/'),
                        'type': row['file_type'],
                        'size': row['size'],
                        'permissions': row['permissions'],
                        'owner': row['owner'],
                        'group': row['group_name'],
                        'modified': row['modified_time']
                    })
            
            return entries
    
    def file_exists(self, session_id: str, path: str) -> bool:
        """Check if file or directory exists."""
        with self.get_connection() as conn:
            result = conn.execute("""
                SELECT 1 FROM filesystem 
                WHERE session_id = ? AND path = ?
            """, (session_id, path)).fetchone()
            return result is not None
    
    # ==================== PROCESS MANAGEMENT ====================
    
    def add_process(self, session_id: str, pid: int, name: str, 
                    cmdline: str = '', ppid: int = 1) -> bool:
        """Add a fake process to the process table."""
        try:
            with self.get_connection() as conn:
                conn.execute("""
                    INSERT INTO processes 
                    (session_id, pid, ppid, name, cmdline, username, status)
                    VALUES (?, ?, ?, ?, ?, 'root', 'running')
                """, (session_id, pid, ppid, name, cmdline))
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            logger.warning(f"Process PID {pid} already exists in session {session_id}")
            return False
    
    def list_processes(self, session_id: str) -> List[Dict]:
        """Get list of all processes for a session."""
        with self.get_connection() as conn:
            results = conn.execute("""
                SELECT pid, ppid, name, cmdline, username, status, 
                       cpu_percent, mem_percent, start_time
                FROM processes 
                WHERE session_id = ?
                ORDER BY pid
            """, (session_id,)).fetchall()
            
            return [dict(row) for row in results]
    
    def kill_process(self, session_id: str, pid: int) -> bool:
        """Remove a process (simulate kill command)."""
        with self.get_connection() as conn:
            conn.execute("""
                DELETE FROM processes 
                WHERE session_id = ? AND pid = ?
            """, (session_id, pid))
            conn.commit()
            return True
    
    # ==================== COMMAND HISTORY ====================
    
    def add_command(self, session_id: str, command: str, output: str = '', 
                    exit_code: int = 0, duration_ms: int = 0):
        """Record a command in history."""
        with self.get_connection() as conn:
            # Get next sequence number
            seq_result = conn.execute("""
                SELECT COALESCE(MAX(sequence_number), 0) + 1 as next_seq
                FROM command_history 
                WHERE session_id = ?
            """, (session_id,)).fetchone()
            
            next_seq = seq_result['next_seq']
            
            conn.execute("""
                INSERT INTO command_history 
                (session_id, sequence_number, command, output, exit_code, duration_ms)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (session_id, next_seq, command, output, exit_code, duration_ms))
            
            # Update session command count
            conn.execute("""
                UPDATE sessions 
                SET command_count = command_count + 1
                WHERE session_id = ?
            """, (session_id,))
            
            conn.commit()
    
    def get_command_history(self, session_id: str, limit: int = 100) -> List[Dict]:
        """Retrieve command history for a session."""
        with self.get_connection() as conn:
            results = conn.execute("""
                SELECT sequence_number, timestamp, command, output, exit_code, duration_ms
                FROM command_history 
                WHERE session_id = ?
                ORDER BY sequence_number DESC
                LIMIT ?
            """, (session_id, limit)).fetchall()
            
            return [dict(row) for row in results]
    
    # ==================== LOGS ====================
    
    def add_log(self, session_id: str, log_source: str, log_level: str, 
                message: str):
        """Add a system log entry."""
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO system_logs 
                (session_id, log_source, log_level, message)
                VALUES (?, ?, ?, ?)
            """, (session_id, log_source, log_level, message))
            conn.commit()
    
    def get_logs(self, session_id: str, source: str = None, 
                 limit: int = 100) -> List[Dict]:
        """Retrieve system logs."""
        with self.get_connection() as conn:
            if source:
                results = conn.execute("""
                    SELECT timestamp, log_source, log_level, message
                    FROM system_logs 
                    WHERE session_id = ? AND log_source = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (session_id, source, limit)).fetchall()
            else:
                results = conn.execute("""
                    SELECT timestamp, log_source, log_level, message
                    FROM system_logs 
                    WHERE session_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (session_id, limit)).fetchall()
            
            return [dict(row) for row in results]
    
    # ==================== IOCs ====================
    
    def add_ioc(self, session_id: str, ioc_type: str, value: str, 
                confidence: float = 0.5, context: str = ''):
        """Record an Indicator of Compromise."""
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO iocs 
                (session_id, ioc_type, value, confidence, context)
                VALUES (?, ?, ?, ?, ?)
            """, (session_id, ioc_type, value, confidence, context))
            conn.commit()
    
    def get_iocs(self, session_id: str = None, ioc_type: str = None) -> List[Dict]:
        """Retrieve IOCs with optional filtering."""
        with self.get_connection() as conn:
            query = "SELECT * FROM iocs WHERE 1=1"
            params = []
            
            if session_id:
                query += " AND session_id = ?"
                params.append(session_id)
            
            if ioc_type:
                query += " AND ioc_type = ?"
                params.append(ioc_type)
            
            query += " ORDER BY extracted_at DESC"
            
            results = conn.execute(query, params).fetchall()
            return [dict(row) for row in results]
    
    # ==================== ATTACK TECHNIQUES ====================
    
    def add_attack_technique(self, session_id: str, technique_id: str, 
                            technique_name: str, tactic: str, 
                            confidence: float, evidence: str):
        """Record a detected MITRE ATT&CK technique."""
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO attack_techniques 
                (session_id, technique_id, technique_name, tactic, confidence, evidence)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (session_id, technique_id, technique_name, tactic, confidence, evidence))
            conn.commit()
    
    def get_attack_techniques(self, session_id: str = None) -> List[Dict]:
        """Retrieve detected attack techniques."""
        with self.get_connection() as conn:
            if session_id:
                results = conn.execute("""
                    SELECT * FROM attack_techniques 
                    WHERE session_id = ?
                    ORDER BY detected_at DESC
                """, (session_id,)).fetchall()
            else:
                results = conn.execute("""
                    SELECT * FROM attack_techniques 
                    ORDER BY detected_at DESC
                """).fetchall()
            
            return [dict(row) for row in results]
    
    # ==================== STATE SNAPSHOTS ====================
    
    def create_snapshot(self, session_id: str) -> str:
        """Create a complete state snapshot for rollback capability."""
        with self.get_connection() as conn:
            # Gather all state data
            snapshot_data = {
                'filesystem': [dict(row) for row in conn.execute(
                    "SELECT * FROM filesystem WHERE session_id = ?", 
                    (session_id,)).fetchall()],
                'processes': [dict(row) for row in conn.execute(
                    "SELECT * FROM processes WHERE session_id = ?", 
                    (session_id,)).fetchall()],
                'environment': [dict(row) for row in conn.execute(
                    "SELECT * FROM environment_vars WHERE session_id = ?", 
                    (session_id,)).fetchall()],
                'logs': [dict(row) for row in conn.execute(
                    "SELECT * FROM system_logs WHERE session_id = ?", 
                    (session_id,)).fetchall()],
            }
            
            snapshot_json = json.dumps(snapshot_data, default=str)
            checksum = hashlib.sha256(snapshot_json.encode()).hexdigest()
            
            conn.execute("""
                INSERT INTO state_snapshots 
                (session_id, snapshot_data, checksum)
                VALUES (?, ?, ?)
            """, (session_id, snapshot_json, checksum))
            conn.commit()
            
            return checksum
    
    def get_session_state(self, session_id: str) -> Dict:
        """Get complete current state for a session (for AI context)."""
        with self.get_connection() as conn:
            state = {
                'session_info': dict(conn.execute(
                    "SELECT * FROM sessions WHERE session_id = ?", 
                    (session_id,)).fetchone() or {}),
                'filesystem_count': conn.execute(
                    "SELECT COUNT(*) as count FROM filesystem WHERE session_id = ?", 
                    (session_id,)).fetchone()['count'],
                'process_count': conn.execute(
                    "SELECT COUNT(*) as count FROM processes WHERE session_id = ?", 
                    (session_id,)).fetchone()['count'],
                'recent_commands': self.get_command_history(session_id, limit=10),
                'environment': {row['key']: row['value'] for row in conn.execute(
                    "SELECT key, value FROM environment_vars WHERE session_id = ?", 
                    (session_id,)).fetchall()},
            }
            
            return state
