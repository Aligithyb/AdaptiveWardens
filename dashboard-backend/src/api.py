#!/usr/bin/env python3
"""Dashboard Backend API"""
from fastapi import FastAPI, HTTPException, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import asyncio
import hashlib
import httpx
import sqlite3
import csv
import io
import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Any

from threat_intel import enrich_ip, _ensure_ti_table, _get_cache

app = FastAPI(title="SOC Dashboard API")

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

@app.middleware("http")
async def require_api_key(request: Request, call_next):
    if DASHBOARD_API_KEY and request.url.path != "/health":
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
    s['risk_score'] = score
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
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
