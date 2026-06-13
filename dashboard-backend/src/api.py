#!/usr/bin/env python3
"""Dashboard Backend API"""
from fastapi import FastAPI, HTTPException, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import sqlite3
import csv
import io
import json
import os
from typing import List, Dict, Any

app = FastAPI(title="SOC Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = os.getenv("DB_PATH", "/data/app_state.db")
DASHBOARD_API_KEY = os.getenv("DASHBOARD_API_KEY", "")

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
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
