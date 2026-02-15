from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import logging
from database import SandboxDatabase

logger = logging.getLogger(__name__)

app = FastAPI(title="Sandbox State Store API", version="1.0.0")

# Initialize database
db = SandboxDatabase()

# ==================== PYDANTIC MODELS ====================

class SessionCreate(BaseModel):
    session_id: str
    source_ip: str
    protocol: str
    username: Optional[str] = None
    password: Optional[str] = None

class FileWrite(BaseModel):
    path: str
    content: str
    permissions: Optional[str] = '644'

class ProcessAdd(BaseModel):
    pid: int
    name: str
    cmdline: Optional[str] = ''
    ppid: Optional[int] = 1

class CommandRecord(BaseModel):
    command: str
    output: Optional[str] = ''
    exit_code: Optional[int] = 0
    duration_ms: Optional[int] = 0

class LogEntry(BaseModel):
    log_source: str
    log_level: str
    message: str

class IOCEntry(BaseModel):
    ioc_type: str
    value: str
    confidence: Optional[float] = 0.5
    context: Optional[str] = ''

class AttackTechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    evidence: str

# ==================== API ENDPOINTS ====================

@app.post("/sessions/")
async def create_session(session: SessionCreate):
    """Create a new honeypot session with initialized state."""
    success = db.create_session(
        session.session_id,
        session.source_ip,
        session.protocol,
        session.username,
        session.password
    )
    if success:
        return {"status": "created", "session_id": session.session_id}
    else:
        raise HTTPException(status_code=400, detail="Session already exists")

@app.delete("/sessions/{session_id}")
async def close_session(session_id: str):
    """Close a session and mark it as complete."""
    db.close_session(session_id)
    return {"status": "closed", "session_id": session_id}

@app.get("/sessions/{session_id}/state")
async def get_session_state(session_id: str):
    """Get complete current state for a session (used by AI Engine)."""
    state = db.get_session_state(session_id)
    if not state.get('session_info'):
        raise HTTPException(status_code=404, detail="Session not found")
    return state

@app.get("/files/{session_id}")
async def read_file(session_id: str, path: str):
    """Read a file from the sandbox filesystem."""
    content = db.read_file(session_id, path)
    if content is None:
        raise HTTPException(status_code=404, detail="File not found")
    return {"path": path, "content": content}

@app.post("/files/{session_id}")
async def write_file(session_id: str, file_data: FileWrite):
    """Write or update a file in the sandbox filesystem."""
    success = db.write_file(
        session_id,
        file_data.path,
        file_data.content,
        file_data.permissions
    )
    if success:
        return {"status": "written", "path": file_data.path}
    else:
        raise HTTPException(status_code=500, detail="Failed to write file")

@app.get("/files/{session_id}/list")
async def list_directory(session_id: str, path: str = '/'):
    """List directory contents."""
    entries = db.list_directory(session_id, path)
    return {"path": path, "entries": entries}

@app.post("/processes/{session_id}")
async def add_process(session_id: str, process: ProcessAdd):
    """Add a fake process to the process table."""
    success = db.add_process(
        session_id,
        process.pid,
        process.name,
        process.cmdline,
        process.ppid
    )
    if success:
        return {"status": "added", "pid": process.pid}
    else:
        raise HTTPException(status_code=400, detail="Process already exists")

@app.get("/processes/{session_id}")
async def list_processes(session_id: str):
    """Get list of all processes for a session."""
    processes = db.list_processes(session_id)
    return {"processes": processes}

@app.delete("/processes/{session_id}/{pid}")
async def kill_process(session_id: str, pid: int):
    """Kill a process (remove from table)."""
    db.kill_process(session_id, pid)
    return {"status": "killed", "pid": pid}

@app.post("/commands/{session_id}")
async def add_command(session_id: str, cmd: CommandRecord):
    """Record a command execution in history."""
    db.add_command(
        session_id,
        cmd.command,
        cmd.output,
        cmd.exit_code,
        cmd.duration_ms
    )
    return {"status": "recorded"}

@app.get("/commands/{session_id}")
async def get_command_history(session_id: str, limit: int = 100):
    """Get command history for a session."""
    history = db.get_command_history(session_id, limit)
    return {"history": history}

@app.post("/logs/{session_id}")
async def add_log(session_id: str, log: LogEntry):
    """Add a system log entry."""
    db.add_log(session_id, log.log_source, log.log_level, log.message)
    return {"status": "logged"}

@app.get("/logs/{session_id}")
async def get_logs(session_id: str, source: Optional[str] = None, limit: int = 100):
    """Get system logs."""
    logs = db.get_logs(session_id, source, limit)
    return {"logs": logs}

@app.post("/iocs/{session_id}")
async def add_ioc(session_id: str, ioc: IOCEntry):
    """Record an Indicator of Compromise."""
    db.add_ioc(
        session_id,
        ioc.ioc_type,
        ioc.value,
        ioc.confidence,
        ioc.context
    )
    return {"status": "recorded"}

@app.get("/iocs/")
async def get_iocs(session_id: Optional[str] = None, ioc_type: Optional[str] = None):
    """Get all IOCs with optional filtering."""
    iocs = db.get_iocs(session_id, ioc_type)
    return {"iocs": iocs}

@app.post("/attack-techniques/{session_id}")
async def add_attack_technique(session_id: str, technique: AttackTechnique):
    """Record a detected MITRE ATT&CK technique."""
    db.add_attack_technique(
        session_id,
        technique.technique_id,
        technique.technique_name,
        technique.tactic,
        technique.confidence,
        technique.evidence
    )
    return {"status": "recorded"}

@app.get("/attack-techniques/")
async def get_attack_techniques(session_id: Optional[str] = None):
    """Get detected attack techniques."""
    techniques = db.get_attack_techniques(session_id)
    return {"techniques": techniques}

@app.post("/snapshots/{session_id}")
async def create_snapshot(session_id: str):
    """Create a state snapshot for rollback."""
    checksum = db.create_snapshot(session_id)
    return {"status": "created", "checksum": checksum}

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "sandbox-store"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
