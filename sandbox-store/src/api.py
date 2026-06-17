from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import logging
import os
import requests
from database import SandboxDatabase

logger = logging.getLogger(__name__)

app = FastAPI(title="Sandbox State Store API", version="1.0.0")

# Initialize database
db_path = os.getenv("DB_PATH", "/data/app_state.db")
os.makedirs(os.path.dirname(db_path), exist_ok=True)
db = SandboxDatabase(db_path=db_path)

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

class StateValue(BaseModel):
    value: str

def _update_session_country(country: str, session_id: str):
    """Persist country to the sessions table."""
    try:
        with db.get_connection() as conn:
            conn.execute(
                "UPDATE sessions SET country = ? WHERE session_id = ?",
                (country, session_id)
            )
            conn.commit()
    except Exception as e:
        logger.error(f"[Geo] DB update failed for {session_id}: {e}")


def _geolocate_ip_api(ip: str) -> str | None:
    """Try ip-api.com (free, 45 req/min). Uses HTTPS. Returns country name or None."""
    import time
    for attempt in range(2):
        try:
            geo_resp = requests.get(
                f"https://ip-api.com/json/{ip}",
                timeout=5,
                headers={"User-Agent": "AdaptiveWardens/1.0"}
            )
            if geo_resp.status_code == 200:
                data = geo_resp.json()
                if data.get("status") == "success":
                    return data.get("country", "Unknown")
            elif geo_resp.status_code == 429:
                logger.warning(f"[Geo] ip-api rate limited on {ip}, retrying...")
                time.sleep(1)
                continue
        except Exception as e:
            logger.warning(f"[Geo] ip-api attempt {attempt + 1} failed for {ip}: {e}")
            time.sleep(0.5)
    return None


def _geolocate_ipapi_co(ip: str) -> str | None:
    """Fallback: ipapi.co (free tier, 1000 req/day). Returns country name or None."""
    try:
        resp = requests.get(
            f"https://ipapi.co/{ip}/country_name/",
            timeout=5,
            headers={"User-Agent": "AdaptiveWardens/1.0"}
        )
        if resp.status_code == 200 and resp.text:
            country = resp.text.strip()
            if country and country != "None":
                return country
    except Exception as e:
        logger.warning(f"[Geo] ipapi.co fallback failed for {ip}: {e}")
    return None


def geolocate_and_notify(ip: str, protocol: str, session_id: str):
    """Geolocate the IP, save country to DB, then fire the Slack alert."""
    country = "Unknown"

    # Primary: ip-api.com with retry
    country = _geolocate_ip_api(ip)

    # Fallback: ipapi.co
    if not country:
        logger.info(f"[Geo] Falling back to ipapi.co for {ip}")
        country = _geolocate_ipapi_co(ip)

    if not country:
        country = "Unknown"
        logger.warning(f"[Geo] All geolocation services failed for {ip}")

    logger.info(f"[Geo] {ip} -> {country}")
    _update_session_country(country, session_id)

    # Send Slack alert
    try:
        logger.info(f"[Slack] Firing alert for session={session_id} ip={ip} protocol={protocol}")
        message = f"\U0001f6a8 *New Honeypot Session Started* \U0001f6a8\n" \
                  f"\u2022 *Session ID:* `{session_id}`\n" \
                  f"\u2022 *Protocol:* `{protocol}`\n" \
                  f"\u2022 *Source IP:* `{ip}`\n" \
                  f"\u2022 *Country:* {country}\n"

        webhook_url = os.getenv("SLACK_WEBHOOK_URL")
        bot_token = os.getenv("SLACK_BOT_TOKEN")
        channel = os.getenv("SLACK_CHANNEL", "#alerts")

        if webhook_url:
            slack_resp = requests.post(webhook_url, json={"text": message}, timeout=5)
            logger.info(f"[Slack] Webhook response: {slack_resp.status_code} | {slack_resp.text}")
        elif bot_token and channel:
            slack_resp = requests.post(
                "https://slack.com/api/chat.postMessage",
                headers={"Authorization": f"Bearer {bot_token}"},
                json={"channel": channel, "text": message},
                timeout=5
            )
            logger.info(f"[Slack] Bot response: {slack_resp.status_code} | {slack_resp.text}")
        else:
            logger.warning("[Slack] No SLACK_WEBHOOK_URL or SLACK_BOT_TOKEN configured — alert skipped!")
    except Exception as e:
        logger.error(f"[Slack] Error sending alert: {e}")

    # Fire generic SOAR webhook (platform-agnostic JSON)
    soar_url = os.getenv("SOAR_WEBHOOK_URL")
    if soar_url:
        try:
            import time
            payload = {
                "event": "honeypot.session.new",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "session_id": session_id,
                "source_ip": ip,
                "country": country,
                "protocol": protocol,
                "severity": "medium",
                "source": "AdaptiveWardens",
            }
            soar_resp = requests.post(
                soar_url,
                json=payload,
                headers={"Content-Type": "application/json", "X-Source": "AdaptiveWardens"},
                timeout=5,
            )
            logger.info(f"[SOAR] Webhook response: {soar_resp.status_code}")
        except Exception as e:
            logger.error(f"[SOAR] Error sending webhook: {e}")

# ==================== API ENDPOINTS ====================

@app.post("/sessions/")
async def create_session(session: SessionCreate, background_tasks: BackgroundTasks):
    """Create a new session with initialized state."""
    success = db.create_session(
        session.session_id,
        session.source_ip,
        session.protocol,
        session.username,
        session.password
    )
    if success:
        background_tasks.add_task(geolocate_and_notify, session.source_ip, session.protocol, session.session_id)
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
        if db.is_directory(session_id, path):
            raise HTTPException(status_code=422, detail="Is a directory")
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


# ==================== B2: PERSISTENT ATTACKER STATE ====================

@app.get("/state/{source_ip}")
async def get_persistent_state(source_ip: str):
    """Return all saved env vars, aliases and cwd for this attacker IP."""
    return db.get_persistent_state(source_ip)

@app.put("/state/{source_ip}/env/{name}")
async def set_env_var(source_ip: str, name: str, body: StateValue):
    db.set_persistent_state(source_ip, 'env', name, body.value)
    return {"status": "ok"}

@app.delete("/state/{source_ip}/env/{name}")
async def delete_env_var(source_ip: str, name: str):
    db.delete_persistent_state(source_ip, 'env', name)
    return {"status": "ok"}

@app.put("/state/{source_ip}/alias/{name}")
async def set_alias(source_ip: str, name: str, body: StateValue):
    db.set_persistent_state(source_ip, 'alias', name, body.value)
    return {"status": "ok"}

@app.delete("/state/{source_ip}/alias/{name}")
async def delete_alias(source_ip: str, name: str):
    db.delete_persistent_state(source_ip, 'alias', name)
    return {"status": "ok"}

@app.put("/state/{source_ip}/cwd")
async def set_cwd(source_ip: str, body: StateValue):
    db.set_persistent_state(source_ip, 'cwd', 'cwd', body.value)
    return {"status": "ok"}


# ==================== MALWARE DOWNLOAD TRACKING ====================

class MalwareDownloadRecord(BaseModel):
    source_ip: Optional[str] = ''
    url: str
    filename: Optional[str] = ''
    file_size: Optional[int] = 0
    command: Optional[str] = ''


@app.post("/malware/downloads/{session_id}")
async def record_malware_download(session_id: str, body: MalwareDownloadRecord):
    """Record a wget/curl download detected in the honeypot session."""
    row_id = db.record_malware_download(
        session_id=session_id,
        source_ip=body.source_ip or '',
        url=body.url,
        filename=body.filename or '',
        file_size=body.file_size or 0,
        command=body.command or '',
    )
    return {"status": "recorded", "id": row_id}


@app.get("/malware/downloads")
async def list_malware_downloads(limit: int = 200):
    """Return all recorded malware download events."""
    return {"downloads": db.get_malware_downloads(limit)}


@app.get("/malware/downloads/{session_id}")
async def list_malware_downloads_for_session(session_id: str):
    """Return malware download events for a specific session."""
    return {"downloads": db.get_malware_downloads_by_session(session_id)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
