#!/usr/bin/env python3
"""Dashboard Backend API"""
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import asyncio
import hashlib
import hmac as hmac_mod
import httpx
import secrets
import sqlite3
import csv
import io
import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Any

from threat_intel import enrich_ip, _ensure_ti_table, _get_cache, vt_url_scan, sandbox_analyze


# ---------------------------------------------------------------------------
# User / Auth helpers
# ---------------------------------------------------------------------------

def _ensure_users_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    UNIQUE NOT NULL,
            email       TEXT,
            full_name   TEXT    NOT NULL,
            password_hash TEXT  NOT NULL,
            role        TEXT    NOT NULL
                            CHECK(role IN ('admin','soc_analyst','it_staff','read_only')),
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login  TIMESTAMP,
            is_active   INTEGER DEFAULT 1
        )
    """)
    conn.commit()


def _hash_password(password: str, salt: str | None = None) -> str:
    if salt is None:
        salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100_000)
    return f"{salt}:{key.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        salt, key_hex = stored.split(':', 1)
        expected = _hash_password(password, salt)
        return hmac_mod.compare_digest(expected, stored)
    except Exception:
        return False


def _seed_default_users(conn):
    defaults = [
        ('admin',      'admin@adaptivewardens.local',      'System Administrator', 'Admin@SOC2025!',   'admin'),
        ('j.smith',    'j.smith@adaptivewardens.local',    'John Smith',           'Analyst@SOC2025!', 'soc_analyst'),
        ('it.support', 'it.support@adaptivewardens.local', 'Support Engineer',     'Support@SOC2025!', 'it_staff'),
        ('auditor',    'auditor@adaptivewardens.local',    'Security Auditor',     'Viewer@SOC2025!',  'read_only'),
    ]
    for username, email, full_name, password, role in defaults:
        if not conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            conn.execute(
                "INSERT INTO users (username, email, full_name, password_hash, role) VALUES (?,?,?,?,?)",
                (username, email, full_name, _hash_password(password), role)
            )
    conn.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        with get_db_connection() as conn:
            _ensure_users_table(conn)
            _seed_default_users(conn)
    except Exception as e:
        print(f"[startup] users table init warning: {e}")
    yield


app = FastAPI(title="SOC Dashboard API", lifespan=lifespan)

# The backend is internal-only (no external ingress) with API-key auth on all
# non-health endpoints, so broad CORS is safe for the SOC dashboard use case.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # nosemgrep
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = os.getenv("DB_PATH", "/data/app_state.db")
DASHBOARD_API_KEY = os.getenv("DASHBOARD_API_KEY", "")
AI_ENGINE_URL = os.getenv("AI_ENGINE_URL", "http://ai-engine:8002")
SANDBOX_URL = os.getenv("SANDBOX_URL", "http://sandbox-store:8001")

AUTH_EXEMPT = {"/health", "/api/auth/login"}

@app.middleware("http")
async def require_api_key(request: Request, call_next):
    if DASHBOARD_API_KEY and request.url.path not in AUTH_EXEMPT:
        if request.headers.get("X-API-Key", "") != DASHBOARD_API_KEY:
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})
    return await call_next(request)

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Risk + lifecycle helpers (computed, not stored)
# ---------------------------------------------------------------------------

def _compute_risk(session_id: str, conn) -> tuple:
    """Returns (score: int, level: str) — Critical/High/Medium/Low."""
    techniques = conn.execute(
        "SELECT COUNT(*) FROM attack_techniques WHERE session_id=?",
        (session_id,)
    ).fetchone()[0]

    dangerous = conn.execute("""
        SELECT COUNT(*) FROM command_history WHERE session_id=? AND (
            command LIKE '%wget %' OR command LIKE '%curl %' OR
            command LIKE '%chmod +x%' OR command LIKE '%base64%' OR
            command LIKE '% nc %' OR command LIKE '%nmap%' OR
            command LIKE '%aws %' OR command LIKE '%kubectl%' OR
            command LIKE '%docker%' OR command LIKE '%.ssh%' OR
            command LIKE '%/etc/shadow%' OR command LIKE '%/etc/passwd%'
        )
    """, (session_id,)).fetchone()[0]

    cmd_count = conn.execute(
        "SELECT COUNT(*) FROM command_history WHERE session_id=?",
        (session_id,)
    ).fetchone()[0]

    score = min(techniques * 20, 60) + min(dangerous * 10, 30) + min(cmd_count * 2, 30)

    if score >= 80: return score, 'Critical'
    if score >= 50: return score, 'High'
    if score >= 20: return score, 'Medium'
    return score, 'Low'


def _compute_lifecycle_status(session_id: str, db_status: str, conn) -> str:
    """Returns Active / Idle / Closed based on DB status and last command time."""
    if db_status in ('closed', 'timeout'):
        return 'Closed'

    row = conn.execute("""
        SELECT CASE
            WHEN MAX(timestamp) IS NULL THEN
                CASE WHEN (SELECT start_time FROM sessions WHERE session_id = ?) < datetime('now', '-5 minutes')
                     THEN 'Idle' ELSE 'Active' END
            WHEN MAX(timestamp) < datetime('now', '-5 minutes') THEN 'Idle'
            ELSE 'Active'
        END
        FROM command_history WHERE session_id = ?
    """, (session_id, session_id)).fetchone()

    return row[0] if row and row[0] else 'Active'


def _enrich_session(session: sqlite3.Row, conn) -> dict:
    s = dict(session)
    score, level = _compute_risk(s['session_id'], conn)
    s['risk_score'] = min(score, 100)
    s['threat_score'] = min(score, 100)
    s['risk_level'] = level
    s['lifecycle_status'] = _compute_lifecycle_status(s['session_id'], s.get('status', 'active'), conn)
    return s


# ---------------------------------------------------------------------------
# Session endpoints
# ---------------------------------------------------------------------------

@app.get("/api/sessions")
def get_sessions(limit: int = 100):
    try:
        with get_db_connection() as conn:
            sessions = conn.execute(
                "SELECT * FROM sessions ORDER BY start_time DESC LIMIT ?", (limit,)
            ).fetchall()
            return {"sessions": [_enrich_session(s, conn) for s in sessions]}
    except sqlite3.OperationalError:
        return {"sessions": []}


@app.get("/api/sessions/{session_id}")
def get_session_details(session_id: str):
    try:
        with get_db_connection() as conn:
            session = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            if not session:
                raise HTTPException(status_code=404, detail="Session not found")

            commands = conn.execute(
                "SELECT * FROM command_history WHERE session_id = ? ORDER BY sequence_number ASC",
                (session_id,)
            ).fetchall()

            iocs = conn.execute(
                "SELECT * FROM iocs WHERE session_id = ? ORDER BY extracted_at DESC",
                (session_id,)
            ).fetchall()

            techniques = conn.execute(
                "SELECT * FROM attack_techniques WHERE session_id = ? ORDER BY detected_at DESC",
                (session_id,)
            ).fetchall()

            return {
                "session": _enrich_session(session, conn),
                "commands": [dict(c) for c in commands],
                "iocs": [dict(i) for i in iocs],
                "techniques": [dict(t) for t in techniques],
            }
    except sqlite3.OperationalError:
        raise HTTPException(status_code=500, detail="Database error")


@app.get("/api/sessions/{session_id}/commands")
def get_session_commands(session_id: str):
    try:
        with get_db_connection() as conn:
            commands = conn.execute(
                "SELECT * FROM command_history WHERE session_id = ? ORDER BY sequence_number ASC",
                (session_id,)
            ).fetchall()
            return {"commands": [dict(c) for c in commands]}
    except sqlite3.OperationalError:
        return {"commands": []}


# ---------------------------------------------------------------------------
# IOC endpoint
# ---------------------------------------------------------------------------

@app.get("/api/iocs")
def get_all_iocs(limit: int = 500):
    try:
        with get_db_connection() as conn:
            iocs = conn.execute(
                "SELECT * FROM iocs ORDER BY extracted_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return {"iocs": [dict(i) for i in iocs]}
    except sqlite3.OperationalError:
        return {"iocs": []}


# ---------------------------------------------------------------------------
# Analytics endpoint
# ---------------------------------------------------------------------------

@app.get("/api/analytics")
def get_analytics():
    try:
        with get_db_connection() as conn:
            total_sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            total_iocs = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
            unique_ips = conn.execute("SELECT COUNT(DISTINCT source_ip) FROM sessions").fetchone()[0]

            top_tactics = conn.execute("""
                SELECT tactic, COUNT(*) as count
                FROM attack_techniques
                GROUP BY tactic
                ORDER BY count DESC LIMIT 5
            """).fetchall()

            mitre_techniques_raw = conn.execute("""
                SELECT technique_id, MAX(technique_name) as technique_name, MAX(tactic) as tactic, COUNT(*) as count
                FROM attack_techniques
                GROUP BY technique_id
            """).fetchall()
            mitre_techniques = {
                row['technique_id']: {
                    "count": row['count'],
                    "name": row['technique_name'],
                    "tactic": row['tactic']
                } for row in mitre_techniques_raw
            }

            protocols = conn.execute("""
                SELECT protocol, COUNT(*) as count FROM sessions GROUP BY protocol
            """).fetchall()

            avg_duration = conn.execute("""
                SELECT AVG(strftime('%s', end_time) - strftime('%s', start_time))
                FROM sessions WHERE end_time IS NOT NULL
            """).fetchone()[0] or 0

            # Risk level breakdown across all sessions
            all_sessions = conn.execute("SELECT session_id, status FROM sessions").fetchall()
            risk_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            high_risk = 0
            for s in all_sessions:
                _, level = _compute_risk(s['session_id'], conn)
                risk_counts[level] += 1
                if level in ('Critical', 'High'):
                    high_risk += 1

            return {
                "total_sessions": total_sessions,
                "total_iocs": total_iocs,
                "unique_ips": unique_ips,
                "high_risk_sessions": high_risk,
                "avg_session_duration": round(avg_duration / 60.0, 1),
                "top_tactics": [dict(t) for t in top_tactics],
                "mitre_techniques": mitre_techniques,
                "protocols": [dict(p) for p in protocols],
                "risk_breakdown": risk_counts,
            }
    except sqlite3.OperationalError as e:
        print(f"DB Error in analytics: {e}")
        return {
            "total_sessions": 0, "total_iocs": 0, "unique_ips": 0,
            "high_risk_sessions": 0, "top_tactics": [], "mitre_techniques": {},
            "protocols": [], "risk_breakdown": {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        }


# ---------------------------------------------------------------------------
# Live session map pins
# ---------------------------------------------------------------------------

@app.get("/api/map/live-sessions")
def get_map_live_sessions():
    """Return sessions from the last 24 h with country + risk for live map pins."""
    try:
        with get_db_connection() as conn:
            rows = conn.execute("""
                SELECT session_id, source_ip, country, protocol, start_time
                FROM sessions
                WHERE start_time > datetime('now', '-24 hours')
                ORDER BY start_time DESC
                LIMIT 300
            """).fetchall()
            result = []
            for s in rows:
                score, level = _compute_risk(s['session_id'], conn)
                result.append({
                    "session_id": s['session_id'],
                    "source_ip": s['source_ip'],
                    "country": s['country'] or 'Unknown',
                    "protocol": s['protocol'],
                    "start_time": s['start_time'],
                    "risk_level": level,
                    "threat_score": min(score, 100),
                })
            return {"sessions": result}
    except sqlite3.OperationalError:
        return {"sessions": []}


# ---------------------------------------------------------------------------
# Deception effectiveness analytics
# ---------------------------------------------------------------------------

@app.get("/api/analytics/effectiveness")
def get_effectiveness():
    """Honeypot deception effectiveness metrics."""
    try:
        with get_db_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]

            # Engaged = attacker ran ≥ 5 commands (fooled long enough to keep going)
            engaged_rows = conn.execute("""
                SELECT COUNT(*) FROM (
                    SELECT session_id FROM command_history
                    GROUP BY session_id HAVING COUNT(*) >= 5
                )
            """).fetchone()[0]

            avg_cmds = conn.execute("""
                SELECT AVG(c) FROM (
                    SELECT COUNT(*) AS c FROM command_history GROUP BY session_id
                )
            """).fetchone()[0] or 0

            avg_dur = conn.execute("""
                SELECT AVG(strftime('%s', end_time) - strftime('%s', start_time))
                FROM sessions WHERE end_time IS NOT NULL
            """).fetchone()[0] or 0

            top_cmds = conn.execute("""
                SELECT command, COUNT(*) AS cnt
                FROM command_history
                GROUP BY command
                ORDER BY cnt DESC
                LIMIT 8
            """).fetchall()

            total_techniques = conn.execute("SELECT COUNT(DISTINCT technique_id) FROM attack_techniques").fetchone()[0]
            total_ioc_types = conn.execute("SELECT COUNT(DISTINCT ioc_type) FROM iocs").fetchone()[0]

            all_s = conn.execute("SELECT session_id FROM sessions").fetchall()
            risk_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for s in all_s:
                _, lvl = _compute_risk(s["session_id"], conn)
                risk_dist[lvl] = risk_dist.get(lvl, 0) + 1

            return {
                "total_sessions": total,
                "engaged_sessions": engaged_rows,
                "engagement_rate": round((engaged_rows / total * 100) if total > 0 else 0, 1),
                "avg_commands_per_session": round(avg_cmds, 1),
                "avg_session_duration_s": round(avg_dur),
                "top_commands": [{"command": r["command"], "count": r["cnt"]} for r in top_cmds],
                "unique_techniques_seen": total_techniques,
                "unique_ioc_types_seen": total_ioc_types,
                "risk_distribution": risk_dist,
            }
    except sqlite3.OperationalError as e:
        raise HTTPException(status_code=503, detail=str(e))


# ---------------------------------------------------------------------------
# Geo heatmap
# ---------------------------------------------------------------------------

@app.get("/api/geo-heatmap")
def get_geo_heatmap():
    try:
        with get_db_connection() as conn:
            rows = conn.execute("""
                SELECT country, COUNT(*) as count
                FROM sessions
                WHERE country IS NOT NULL AND country != ''
                GROUP BY country ORDER BY count DESC
            """).fetchall()
            return {"heatmap": [dict(r) for r in rows]}
    except sqlite3.OperationalError:
        return {"heatmap": []}


# ---------------------------------------------------------------------------
# Reports endpoints
# ---------------------------------------------------------------------------

@app.get("/api/reports")
def list_reports(limit: int = 200):
    """List all sessions with enriched data for the reports page."""
    try:
        with get_db_connection() as conn:
            sessions = conn.execute(
                "SELECT * FROM sessions ORDER BY start_time DESC LIMIT ?", (limit,)
            ).fetchall()
            enriched = []
            for s in sessions:
                e = _enrich_session(s, conn)
                # Duration in seconds
                if e.get('end_time') and e.get('start_time'):
                    try:
                        from datetime import datetime
                        start = datetime.fromisoformat(str(e['start_time']))
                        end = datetime.fromisoformat(str(e['end_time']))
                        e['duration_seconds'] = int((end - start).total_seconds())
                    except Exception:
                        e['duration_seconds'] = None
                else:
                    e['duration_seconds'] = None

                technique_count = conn.execute(
                    "SELECT COUNT(*) FROM attack_techniques WHERE session_id=?",
                    (e['session_id'],)
                ).fetchone()[0]
                e['technique_count'] = technique_count
                enriched.append(e)
            return {"sessions": enriched}
    except sqlite3.OperationalError:
        return {"sessions": []}


@app.get("/api/reports/{session_id}/json")
def export_session_json(session_id: str):
    """Full session export as JSON (for download)."""
    detail = get_session_details(session_id)
    content = json.dumps(detail, indent=2, default=str)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="session-{session_id[:8]}.json"'}
    )


@app.get("/api/reports/{session_id}/csv")
def export_session_csv(session_id: str):
    """Command history export as CSV."""
    try:
        with get_db_connection() as conn:
            commands = conn.execute(
                "SELECT sequence_number, timestamp, command, exit_code, duration_ms "
                "FROM command_history WHERE session_id=? ORDER BY sequence_number ASC",
                (session_id,)
            ).fetchall()
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(['#', 'timestamp', 'command', 'exit_code', 'duration_ms'])
        for c in commands:
            writer.writerow([c['sequence_number'], c['timestamp'], c['command'], c['exit_code'], c['duration_ms']])
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="commands-{session_id[:8]}.csv"'}
        )
    except sqlite3.OperationalError:
        raise HTTPException(status_code=500, detail="Database error")


# ---------------------------------------------------------------------------
# AI report endpoint
# ---------------------------------------------------------------------------

def _ensure_ai_reports_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ai_reports (
            session_id   TEXT PRIMARY KEY,
            content_hash TEXT NOT NULL,
            report_json  TEXT NOT NULL,
            generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()


def _content_hash(commands: list, techniques: list, iocs: list) -> str:
    payload = json.dumps({"c": commands, "t": techniques, "i": iocs}, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


@app.get("/api/reports/{session_id}/ai-summary")
async def get_ai_summary(session_id: str):
    """Return (or generate) an AI SOC incident report for a session.

    Hits are served from ai_reports table without calling the AI engine.
    A stale cache entry (content_hash mismatch) triggers regeneration.
    """
    try:
        detail = get_session_details(session_id)
    except HTTPException:
        raise

    commands = detail.get("commands", [])
    techniques = detail.get("techniques", [])
    iocs = detail.get("iocs", [])
    session = detail.get("session", {})
    chash = _content_hash(commands, techniques, iocs)

    try:
        with get_db_connection() as conn:
            _ensure_ai_reports_table(conn)
            row = conn.execute(
                "SELECT report_json, content_hash, generated_at FROM ai_reports WHERE session_id = ?",
                (session_id,)
            ).fetchone()

        if row and row["content_hash"] == chash:
            return {
                "report": json.loads(row["report_json"]),
                "cached": True,
                "generated_at": row["generated_at"],
            }
    except sqlite3.OperationalError as e:
        pass

    # Fetch threat intelligence for the attacker IP (cache-first, non-fatal)
    threat_intel: dict = {}
    src_ip = session.get("source_ip") if isinstance(session, dict) else None
    if src_ip:
        try:
            with get_db_connection() as ti_conn:
                threat_intel = await enrich_ip(src_ip, ti_conn)
        except Exception:
            pass  # TI is best-effort — never block report generation

    # Generate report via ai-engine
    try:
        async with httpx.AsyncClient(timeout=35.0) as client:
            resp = await client.post(
                f"{AI_ENGINE_URL}/summarize-session",
                json={
                    "session": session,
                    "commands": commands,
                    "techniques": techniques,
                    "iocs": iocs,
                    "threat_intel": threat_intel,
                },
            )
            resp.raise_for_status()
            report = resp.json().get("report", {})
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"AI engine unavailable: {e}")

    # Persist to cache
    try:
        with get_db_connection() as conn:
            _ensure_ai_reports_table(conn)
            conn.execute(
                "INSERT OR REPLACE INTO ai_reports (session_id, content_hash, report_json, generated_at) "
                "VALUES (?, ?, ?, datetime('now'))",
                (session_id, chash, json.dumps(report))
            )
            conn.commit()
    except sqlite3.OperationalError:
        pass

    return {
        "report": report,
        "cached": False,
        "generated_at": None,
    }


# ---------------------------------------------------------------------------
# Threat Intelligence endpoints
# ---------------------------------------------------------------------------

@app.get("/api/threat-intel/ips")
async def get_threat_intel_all():
    """Enrich all unique attacker IPs. Cache-first; cold start is slow."""
    try:
        with get_db_connection() as conn:
            _ensure_ti_table(conn)
            rows = conn.execute("""
                SELECT
                    source_ip,
                    COUNT(*)                       AS session_count,
                    MAX(start_time)                AS last_seen,
                    MIN(start_time)                AS first_seen,
                    MAX(country)                   AS country
                FROM sessions
                GROUP BY source_ip
                ORDER BY session_count DESC
            """).fetchall()
            unique_ips = [dict(r) for r in rows]
    except sqlite3.OperationalError as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Enrich all IPs concurrently (cache makes this fast on warm runs)
    async def _enrich_one(ip_row: dict) -> dict:
        with get_db_connection() as conn:
            _ensure_ti_table(conn)
            enriched = await enrich_ip(ip_row["source_ip"], conn)
        enriched["session_count"] = ip_row["session_count"]
        enriched["last_seen"]     = ip_row["last_seen"]
        enriched["first_seen"]    = ip_row["first_seen"]
        enriched["country"]       = ip_row["country"] or ""
        return enriched

    results = await asyncio.gather(*[_enrich_one(r) for r in unique_ips])

    # Sort: confirmed malicious first, then by abuse score, then by session count
    def _sort_key(r):
        vt_mal  = (r.get("virustotal") or {}).get("malicious", 0) or 0
        abuse   = (r.get("abuseipdb") or {}).get("abuse_confidence_score", 0) or 0
        return (-vt_mal, -abuse, -r.get("session_count", 0))

    results.sort(key=_sort_key)
    return {"ips": results}


@app.get("/api/threat-intel/ip/{ip}")
async def get_threat_intel_single(ip: str):
    """Full enrichment + session history for one attacker IP."""
    try:
        with get_db_connection() as conn:
            _ensure_ti_table(conn)
            enriched = await enrich_ip(ip, conn)

            sessions = conn.execute("""
                SELECT session_id, start_time, end_time, protocol,
                       username, status, command_count, country
                FROM sessions
                WHERE source_ip = ?
                ORDER BY start_time DESC
            """, (ip,)).fetchall()

            session_list = []
            for s in sessions:
                sd = dict(s)
                score, level = _compute_risk(sd["session_id"], conn)
                sd["risk_level"] = level
                sd["risk_score"] = score
                tech_count = conn.execute(
                    "SELECT COUNT(*) FROM attack_techniques WHERE session_id=?",
                    (sd["session_id"],)
                ).fetchone()[0]
                sd["technique_count"] = tech_count
                session_list.append(sd)

        enriched["sessions"] = session_list
        return enriched
    except sqlite3.OperationalError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/threat-intel/blocklist")
async def get_blocklist():
    """Export confirmed malicious / high-abuse IPs as a plain-text blocklist."""
    try:
        with get_db_connection() as conn:
            _ensure_ti_table(conn)
            unique_ips = conn.execute(
                "SELECT DISTINCT source_ip FROM sessions"
            ).fetchall()

        bad_ips: list[str] = []
        for row in unique_ips:
            ip = row[0]
            with get_db_connection() as conn:
                vt    = _get_cache(conn, ip, "virustotal") or {}
                abuse = _get_cache(conn, ip, "abuseipdb") or {}

            vt_bad    = (vt.get("malicious") or 0) > 0
            abuse_bad = (abuse.get("abuse_confidence_score") or 0) >= 50
            # Fallback: include Critical/High risk IPs even without TI data
            if not vt_bad and not abuse_bad:
                with get_db_connection() as conn:
                    _, level = _compute_risk(ip, conn) if False else (0, "Low")
                    sessions = conn.execute(
                        "SELECT session_id FROM sessions WHERE source_ip=?", (ip,)
                    ).fetchall()
                    for s in sessions:
                        _, level = _compute_risk(s[0], conn)
                        if level in ("Critical", "High"):
                            abuse_bad = True
                            break

            if vt_bad or abuse_bad:
                bad_ips.append(ip)

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        lines = [
            f"# AdaptiveWardens Blocklist — generated {now}",
            f"# {len(bad_ips)} IP(s) — criteria: VT malicious > 0 OR AbuseIPDB >= 50%",
            "# Compatible with: iptables, ufw, firewalld, plain IP lists",
            "",
        ] + bad_ips

        content = "\n".join(lines) + "\n"
        filename = f"blocklist-{datetime.now(timezone.utc).strftime('%Y%m%d')}.txt"
        return Response(
            content=content,
            media_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except sqlite3.OperationalError as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login")
def login(body: LoginRequest):
    username = body.username.strip().lower()
    try:
        with get_db_connection() as conn:
            _ensure_users_table(conn)
            user = conn.execute(
                "SELECT * FROM users WHERE username=? AND is_active=1", (username,)
            ).fetchone()
    except sqlite3.OperationalError as e:
        raise HTTPException(status_code=503, detail=f"Database error: {e}")

    if not user or not _verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    try:
        with get_db_connection() as conn:
            conn.execute(
                "UPDATE users SET last_login=datetime('now') WHERE username=?", (username,)
            )
            conn.commit()
    except sqlite3.OperationalError:
        pass

    return {
        "username": user["username"],
        "full_name": user["full_name"],
        "email": user["email"],
        "role": user["role"],
    }


@app.get("/api/auth/users")
def list_users():
    """Return all users (admin view). API-key protected by middleware."""
    try:
        with get_db_connection() as conn:
            _ensure_users_table(conn)
            rows = conn.execute(
                "SELECT username, email, full_name, role, created_at, last_login, is_active FROM users ORDER BY role, username"
            ).fetchall()
            return {"users": [dict(r) for r in rows]}
    except sqlite3.OperationalError as e:
        raise HTTPException(status_code=503, detail=str(e))


# ---------------------------------------------------------------------------
# SIEM / SOAR integrations
# ---------------------------------------------------------------------------

_CEF_SEVERITY = {"Critical": 10, "High": 7, "Medium": 5, "Low": 3}


def _session_to_cef(session: dict, commands: list, techniques: list) -> str:
    """Render one session as a CEF syslog line."""
    risk = session.get("risk_level", "Unknown")
    sev = _CEF_SEVERITY.get(risk, 5)
    src = session.get("source_ip", "0.0.0.0")
    country = session.get("country") or "Unknown"
    proto = session.get("protocol", "ssh").upper()
    username = (session.get("username") or "").replace("|", "/")
    start = session.get("start_time") or ""
    cmd_count = len(commands)
    tactic_set = sorted({t.get("tactic", "") for t in techniques if t.get("tactic")})
    tactics = ",".join(tactic_set)[:200] or "none"

    # Minimal CEF extensions — no pipe or = in values
    ext = (
        f"src={src} "
        f"proto={proto} "
        f"cs1={country} cs1Label=Country "
        f"cs2={username or 'unknown'} cs2Label=Username "
        f"cs3={tactics} cs3Label=MITRETactics "
        f"cn1={cmd_count} cn1Label=CommandCount "
        f"cn2={sev} cn2Label=RiskScore "
        f"start={start}"
    )
    session_id = session.get("session_id", "unknown")
    name = f"{proto} Honeypot Session — Risk {risk}"
    return f"CEF:0|AdaptiveWardens|Honeypot|1.0|{session_id}|{name}|{sev}|{ext}"


@app.get("/api/integrations/siem/cef/{session_id}", response_class=Response)
def export_cef_session(session_id: str):
    """Export a single session as a CEF-formatted syslog line (Content-Type: text/plain)."""
    try:
        detail = get_session_details(session_id)
    except HTTPException:
        raise

    line = _session_to_cef(
        detail.get("session", {}),
        detail.get("commands", []),
        detail.get("techniques", []),
    )
    return Response(content=line + "\n", media_type="text/plain")


@app.get("/api/integrations/siem/cef", response_class=Response)
def export_cef_bulk(limit: int = 200):
    """Export recent sessions as CEF-formatted syslog lines, one per line."""
    try:
        with get_db_connection() as conn:
            sessions = conn.execute(
                "SELECT * FROM sessions ORDER BY start_time DESC LIMIT ?", (min(limit, 1000),)
            ).fetchall()
    except sqlite3.OperationalError as e:
        raise HTTPException(status_code=503, detail=str(e))

    lines = []
    for s in sessions:
        sid = s["session_id"]
        try:
            with get_db_connection() as conn:
                cmds = conn.execute(
                    "SELECT * FROM command_history WHERE session_id=? ORDER BY sequence_number", (sid,)
                ).fetchall()
                techs = conn.execute(
                    "SELECT * FROM attack_techniques WHERE session_id=?", (sid,)
                ).fetchall()
        except sqlite3.OperationalError:
            cmds, techs = [], []
        lines.append(_session_to_cef(dict(s), [dict(c) for c in cmds], [dict(t) for t in techs]))

    return Response(content="\n".join(lines) + ("\n" if lines else ""), media_type="text/plain")


@app.post("/api/integrations/soar/test")
async def test_soar_webhook(session_id: str):
    """Fire the SOAR webhook for an existing session (for integration testing)."""
    soar_url = os.getenv("SOAR_WEBHOOK_URL")
    if not soar_url:
        raise HTTPException(status_code=424, detail="SOAR_WEBHOOK_URL not configured")

    try:
        detail = get_session_details(session_id)
    except HTTPException:
        raise

    session = detail.get("session", {})
    commands = detail.get("commands", [])
    techniques = detail.get("techniques", [])
    tactic_set = sorted({t.get("tactic", "") for t in techniques if t.get("tactic")})
    payload = {
        "event": "honeypot.session.alert",
        "session_id": session_id,
        "source_ip": session.get("source_ip"),
        "country": session.get("country"),
        "protocol": session.get("protocol"),
        "risk_level": session.get("risk_level"),
        "command_count": len(commands),
        "mitre_tactics": tactic_set,
        "start_time": session.get("start_time"),
        "end_time": session.get("end_time"),
        "source": "AdaptiveWardens",
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(
                soar_url,
                json=payload,
                headers={"Content-Type": "application/json", "X-Source": "AdaptiveWardens"},
            )
            return {"status": "sent", "http_status": resp.status_code, "response": resp.text[:500]}
        except Exception as e:
            raise HTTPException(status_code=502, detail=f"SOAR webhook failed: {e}")


# ---------------------------------------------------------------------------
# Malware download tracking + VirusTotal + Any.run analysis
# ---------------------------------------------------------------------------

@app.get("/api/malware")
async def get_malware_downloads(limit: int = 200):
    """Return detected downloads enriched with VT (static) + Any.run (dynamic) analysis."""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(f"{SANDBOX_URL}/malware/downloads", params={"limit": limit})
            resp.raise_for_status()
            downloads: list[dict] = resp.json().get("downloads", [])
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"sandbox-store unavailable: {e}")

    unique_urls = list({d["url"] for d in downloads if d.get("url")})

    async def _enrich_url(url: str, row: dict) -> tuple[str, dict, dict]:
        """Run VT (async, cached) + in-house sandbox (sync, instant) for one URL."""
        try:
            with get_db_connection() as conn:
                vt_res = await vt_url_scan(url, conn)
        except Exception as ex:
            vt_res = {"error": str(ex)}
        sb_res = sandbox_analyze(url, row.get("filename", ""), row.get("command", ""))
        return url, vt_res, sb_res

    # Build lookup: url → first row with that url (for filename/command context)
    url_to_row: dict[str, dict] = {}
    for d in downloads:
        u = d.get("url", "")
        if u and u not in url_to_row:
            url_to_row[u] = d

    vt_results: dict[str, dict] = {}
    sb_results: dict[str, dict] = {}
    if unique_urls:
        tuples = await asyncio.gather(*[_enrich_url(u, url_to_row[u]) for u in unique_urls])
        for url, vt_r, sb_r in tuples:
            vt_results[url] = vt_r
            sb_results[url] = sb_r

    for d in downloads:
        u = d.get("url", "")
        d["virustotal"] = vt_results.get(u, {})
        d["sandbox"]    = sb_results.get(u, {})

    # Sort: highest combined threat first, then newest
    def _sort_key(d: dict) -> tuple:
        vt  = d.get("virustotal") or {}
        sb  = d.get("sandbox")    or {}
        mal = vt.get("malicious", 0) or 0
        tl  = sb.get("threat_level", 0) or 0
        return (-(mal + tl * 10), d.get("detected_at", "") or "")

    downloads.sort(key=_sort_key)
    return {"downloads": downloads, "total": len(downloads)}


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/api/ai-status")
async def ai_status():
    """Surface the AI engine's real health to the SOC dashboard so analysts can
    see if the honeypot has silently degraded to static-only responses, plus
    LLM budget spend and cache hit-rate. Never raises — returns offline state."""
    result = {
        "status": "offline",
        "response_mode": "unknown",
        "llm_model": None,
        "budget_available": None,
        "cache": None,
        "budget": None,
    }
    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            h = await client.get(f"{AI_ENGINE_URL}/health")
            if h.status_code == 200:
                result.update(h.json())
            try:
                cs = await client.get(f"{AI_ENGINE_URL}/cache/stats")
                if cs.status_code == 200:
                    result["cache"] = cs.json()
            except Exception:
                pass
            try:
                bs = await client.get(f"{AI_ENGINE_URL}/budget/stats")
                if bs.status_code == 200:
                    result["budget"] = bs.json()
            except Exception:
                pass
    except Exception as e:
        result["error"] = str(e)
    return result


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
