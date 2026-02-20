from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Optional
import logging
import asyncio
from datetime import datetime, timedelta
import sqlite3
from contextlib import contextmanager

logger = logging.getLogger(__name__)

app = FastAPI(title="Dashboard Backend", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_PATH = "/data/honeypot.db"

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
    
    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass

manager = ConnectionManager()

@contextmanager
def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

# ==================== ENDPOINTS ====================

@app.get("/api/sessions")
async def get_sessions(status: Optional[str] = None, limit: int = 100):
    """Get all sessions with optional filtering."""
    with get_db() as conn:
        if status:
            query = """
                SELECT * FROM sessions 
                WHERE status = ?
                ORDER BY start_time DESC 
                LIMIT ?
            """
            results = conn.execute(query, (status, limit)).fetchall()
        else:
            query = """
                SELECT * FROM sessions 
                ORDER BY start_time DESC 
                LIMIT ?
            """
            results = conn.execute(query, (limit,)).fetchall()
        
        return [dict(row) for row in results]

@app.get("/api/sessions/{session_id}")
async def get_session(session_id: str):
    """Get detailed session information."""
    with get_db() as conn:
        session = conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?",
            (session_id,)
        ).fetchone()
        
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        # Get commands
        commands = conn.execute("""
            SELECT * FROM command_history 
            WHERE session_id = ?
            ORDER BY sequence_number
        """, (session_id,)).fetchall()
        
        # Get IOCs
        iocs = conn.execute("""
            SELECT * FROM iocs 
            WHERE session_id = ?
        """, (session_id,)).fetchall()
        
        # Get techniques
        techniques = conn.execute("""
            SELECT * FROM attack_techniques 
            WHERE session_id = ?
        """, (session_id,)).fetchall()
        
        return {
            'session': dict(session),
            'commands': [dict(cmd) for cmd in commands],
            'iocs': [dict(ioc) for ioc in iocs],
            'techniques': [dict(tech) for tech in techniques]
        }

@app.get("/api/iocs")
async def get_iocs(ioc_type: Optional[str] = None, limit: int = 1000):
    """Get all IOCs with optional filtering."""
    with get_db() as conn:
        if ioc_type:
            results = conn.execute("""
                SELECT * FROM iocs 
                WHERE ioc_type = ?
                ORDER BY extracted_at DESC
                LIMIT ?
            """, (ioc_type, limit)).fetchall()
        else:
            results = conn.execute("""
                SELECT * FROM iocs 
                ORDER BY extracted_at DESC
                LIMIT ?
            """, (limit,)).fetchall()
        
        return [dict(row) for row in results]

@app.get("/api/attack-techniques")
async def get_attack_techniques(limit: int = 1000):
    """Get all detected ATT&CK techniques."""
    with get_db() as conn:
        results = conn.execute("""
            SELECT * FROM attack_techniques 
            ORDER BY detected_at DESC
            LIMIT ?
        """, (limit,)).fetchall()
        
        return [dict(row) for row in results]

@app.get("/api/attack-heatmap")
async def get_attack_heatmap():
    """Generate ATT&CK heatmap data."""
    with get_db() as conn:
        results = conn.execute("""
            SELECT technique_id, technique_name, tactic, 
                   COUNT(*) as count,
                   AVG(confidence) as avg_confidence
            FROM attack_techniques
            GROUP BY technique_id, tactic
            ORDER BY count DESC
        """).fetchall()
        
        # Group by tactic
        heatmap = {}
        for row in results:
            tactic = row['tactic']
            if tactic not in heatmap:
                heatmap[tactic] = []
            
            heatmap[tactic].append({
                'technique_id': row['technique_id'],
                'technique_name': row['technique_name'],
                'count': row['count'],
                'confidence': row['avg_confidence']
            })
        
        return heatmap

@app.get("/api/statistics")
async def get_statistics():
    """Get dashboard statistics."""
    with get_db() as conn:
        # Total sessions
        total_sessions = conn.execute("SELECT COUNT(*) as count FROM sessions").fetchone()['count']
        
        # Active sessions
        active_sessions = conn.execute(
            "SELECT COUNT(*) as count FROM sessions WHERE status = 'active'"
        ).fetchone()['count']
        
        # Total commands
        total_commands = conn.execute("SELECT COUNT(*) as count FROM command_history").fetchone()['count']
        
        # Total IOCs
        total_iocs = conn.execute("SELECT COUNT(*) as count FROM iocs").fetchone()['count']
        
        # Unique source IPs
        unique_ips = conn.execute(
            "SELECT COUNT(DISTINCT source_ip) as count FROM sessions"
        ).fetchone()['count']
        
        # Today's sessions
        today = datetime.now().date()
        today_sessions = conn.execute("""
            SELECT COUNT(*) as count FROM sessions 
            WHERE DATE(start_time) = ?
        """, (today,)).fetchone()['count']
        
        return {
            'total_sessions': total_sessions,
            'active_sessions': active_sessions,
            'total_commands': total_commands,
            'total_iocs': total_iocs,
            'unique_ips': unique_ips,
            'today_sessions': today_sessions
        }

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket for real-time updates."""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and send heartbeat
            await asyncio.sleep(30)
            await websocket.send_json({"type": "heartbeat"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# Background task to broadcast updates
async def broadcast_updates():
    """Periodically check for new data and broadcast."""
    while True:
        try:
            with get_db() as conn:
                # Get recent activity
                recent = conn.execute("""
                    SELECT * FROM sessions 
                    WHERE status = 'active'
                    ORDER BY start_time DESC
                    LIMIT 10
                """).fetchall()
                
                if recent:
                    await manager.broadcast({
                        "type": "session_update",
                        "data": [dict(row) for row in recent]
                    })
        except Exception as e:
            logger.error(f"Error broadcasting updates: {e}")
        
        await asyncio.sleep(5)

@app.on_event("startup")
async def startup_event():
    """Start background tasks."""
    asyncio.create_task(broadcast_updates())

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "dashboard-backend"}

if __name__ == "__main__":
    import uvicorn
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    uvicorn.run(app, host="0.0.0.0", port=8000)
