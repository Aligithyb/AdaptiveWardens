#!/usr/bin/env python3
"""Dashboard Backend API"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
import os
from typing import List, Dict, Any

app = FastAPI(title="HoneyOps Dashboard API")

# Allow CORS for dashboard UI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Connect directly to the sandbox database volume
# In a real microservices arch we might use httpx to talk to Sandbox API,
# but direct DB read here is faster for large analytical dashboard queries.
DB_PATH = os.getenv("DB_PATH", "/data/honeypot.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

@app.get("/api/sessions")
def get_sessions(limit: int = 100):
    """Get all connected attacker sessions"""
    try:
        with get_db_connection() as conn:
            sessions = conn.execute(
                "SELECT * FROM sessions ORDER BY start_time DESC LIMIT ?", (limit,)
            ).fetchall()
            return {"sessions": [dict(s) for s in sessions]}
    except sqlite3.OperationalError:
        return {"sessions": []}

@app.get("/api/sessions/{session_id}")
def get_session_details(session_id: str):
    """Get details of a specific session including commands and logs"""
    try:
        with get_db_connection() as conn:
            session = conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
            if not session:
                raise HTTPException(status_code=404, detail="Session not found")
                
            commands = conn.execute(
                "SELECT * FROM command_history WHERE session_id = ? ORDER BY sequence_number ASC", (session_id,)
            ).fetchall()
            
            iocs = conn.execute(
                "SELECT * FROM iocs WHERE session_id = ? ORDER BY extracted_at DESC", (session_id,)
            ).fetchall()
            
            techniques = conn.execute(
                "SELECT * FROM attack_techniques WHERE session_id = ? ORDER BY detected_at DESC", (session_id,)
            ).fetchall()
            
            return {
                "session": dict(session),
                "commands": [dict(c) for c in commands],
                "iocs": [dict(i) for i in iocs],
                "techniques": [dict(t) for t in techniques]
            }
    except sqlite3.OperationalError:
        raise HTTPException(status_code=500, detail="Database error")

@app.get("/api/iocs")
def get_all_iocs(limit: int = 500):
    """Get all extracted IOCs across all sessions"""
    try:
        with get_db_connection() as conn:
            iocs = conn.execute(
                "SELECT * FROM iocs ORDER BY extracted_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return {"iocs": [dict(i) for i in iocs]}
    except sqlite3.OperationalError:
        return {"iocs": []}

@app.get("/api/sessions/{session_id}/commands")
def get_session_commands(session_id: str):
    """Get command history for a specific session"""
    try:
        with get_db_connection() as conn:
            commands = conn.execute(
                "SELECT * FROM command_history WHERE session_id = ? ORDER BY sequence_number ASC", (session_id,)
            ).fetchall()
            return {"commands": [dict(c) for c in commands]}
    except sqlite3.OperationalError:
        return {"commands": []}

@app.get("/api/analytics")
def get_analytics():
    """Get overall dashboard analytics"""
    try:
        with get_db_connection() as conn:
            total_sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            total_iocs = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
            unique_ips = conn.execute("SELECT COUNT(DISTINCT source_ip) FROM sessions").fetchone()[0]
            
            # Top Tactics
            top_tactics = conn.execute("""
                SELECT tactic, COUNT(*) as count 
                FROM attack_techniques 
                GROUP BY tactic 
                ORDER BY count DESC LIMIT 5
            """).fetchall()
            
            # Grouped MITRE Techniques for Map
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
            
            # Protocols
            protocols = conn.execute("""
                SELECT protocol, COUNT(*) as count 
                FROM sessions 
                GROUP BY protocol
            """).fetchall()

            # Avg Session Duration (in seconds)
            avg_duration = conn.execute("""
                SELECT AVG(strftime('%s', end_time) - strftime('%s', start_time)) 
                FROM sessions 
                WHERE end_time IS NOT NULL
            """).fetchone()[0] or 0

            # High Risk Sessions (Sessions with > 0 attack techniques or severity keywords in commands)
            high_risk = conn.execute("""
                SELECT COUNT(DISTINCT s.session_id) 
                FROM sessions s 
                LEFT JOIN attack_techniques t ON s.session_id = t.session_id
                WHERE t.id IS NOT NULL 
                OR s.session_id IN (
                    SELECT session_id FROM command_history 
                    WHERE command LIKE '%wget%' OR command LIKE '%curl%' OR command LIKE '%chmod +x%'
                )
            """).fetchone()[0]
            
            return {
                "total_sessions": total_sessions,
                "total_iocs": total_iocs,
                "unique_ips": unique_ips,
                "high_risk_sessions": high_risk,
                "avg_session_duration": round(avg_duration, 1),
                "top_tactics": [dict(t) for t in top_tactics],
                "mitre_techniques": mitre_techniques,
                "protocols": [dict(p) for p in protocols]
            }
    except sqlite3.OperationalError as e:
         print(f"DB Error in analytics: {e}")
         return {
            "total_sessions": 0, "total_iocs": 0, "unique_ips": 0, "high_risk_sessions": 0,
            "top_tactics": [], "mitre_techniques": {}, "protocols": []
        }

@app.get("/api/geo-heatmap")
def get_geo_heatmap():
    """Get attack counts grouped by country for the heatmap."""
    try:
        with get_db_connection() as conn:
            rows = conn.execute("""
                SELECT country, COUNT(*) as count
                FROM sessions
                WHERE country IS NOT NULL AND country != ''
                GROUP BY country
                ORDER BY count DESC
            """).fetchall()
            return {"heatmap": [dict(r) for r in rows]}
    except sqlite3.OperationalError:
        return {"heatmap": []}

@app.get("/health")
def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8003)
