#!/usr/bin/env python3
"""HTTP Web Honeypot"""
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
import httpx
import uuid
import os
import asyncio

app = FastAPI(title="Corporate Login Gateway")

SANDBOX_URL = os.getenv("SANDBOX_URL", "http://localhost:8001")
AI_ENGINE_URL = os.getenv("AI_ENGINE_URL", "http://localhost:8002")

http_client = httpx.AsyncClient(timeout=10.0)

# Simplistic scanner detection
SCANNERS = ["nikto", "nuclei", "nmap", "sqlmap", "zgrab"]

async def log_to_sandbox(method: str, path: str, ip: str, user_agent: str, body: str = ""):
    session_id = str(uuid.uuid4())
    source_ip = ip if ip else "127.0.0.1"
    
    # Check for scanners
    is_scanner = any(s in user_agent for s in SCANNERS)
    
    if is_scanner:
        # Create minimal session and log immediately
        try:
            await http_client.post(f"{SANDBOX_URL}/sessions/", json={
                "session_id": session_id,
                "source_ip": source_ip,
                "protocol": "http"
            })
            
            await http_client.post(f"{SANDBOX_URL}/attack-techniques/{session_id}", json={
                "technique_id": "T1595.002",
                "technique_name": "Active Scanning: Vulnerability Scanning",
                "tactic": "Reconnaissance",
                "confidence": 0.9,
                "evidence": f"Scanner User-Agent detected: {user_agent}"
            })
            
            await http_client.post(f"{SANDBOX_URL}/commands/{session_id}", json={
                "command": f"{method} {path} (Scanner: {user_agent})",
                "output": "",
                "exit_code": 0,
                "duration_ms": 5
            })
        except Exception as e:
            print(f"Error logging scanner: {e}")
    else:
        # Log normal malicious or generic request
        try:
            await http_client.post(f"{SANDBOX_URL}/sessions/", json={
                "session_id": session_id,
                "source_ip": source_ip,
                "protocol": "http"
            })
            
            await http_client.post(f"{SANDBOX_URL}/commands/{session_id}", json={
                "command": f"{method} {path} Body: {body}",
                "output": "",
                "exit_code": 0,
                "duration_ms": 5
            })
            
            # Simple heuristic for payload detection (e.g. bash injection, sql injection)
            if "select" in body.lower() or "union" in body.lower():
                await http_client.post(f"{SANDBOX_URL}/attack-techniques/{session_id}", json={
                    "technique_id": "T1190",
                    "technique_name": "Exploit Public-Facing Application",
                    "tactic": "Initial Access",
                    "confidence": 0.8,
                    "evidence": f"Potential SQLi in body: {body[:100]}"
                })
        except Exception as e:
            print(f"Error logging request: {e}")


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def catch_all(request: Request, path: str):
    body_bytes = await request.body()
    body = body_bytes.decode("utf-8", errors="ignore")
    ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "")
    
    # Asynchronously log the request details
    asyncio.create_task(log_to_sandbox(request.method, path, ip, user_agent, body))
    
    if path == "" or path == "login" or path == "index.html":
        html_content = """
        <html>
            <head>
                <title>Internal Corporate Portal</title>
                <style>
                    body { font-family: Arial, sans-serif; background: #f4f4f4; text-align: center; padding-top: 100px; }
                    .login-box { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); display: inline-block; }
                    input { margin: 10px 0; padding: 10px; width: 200px; border: 1px solid #ccc; border-radius: 4px; }
                    button { padding: 10px 20px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
                </style>
            </head>
            <body>
                <div class="login-box">
                    <h2>Restricted Area</h2>
                    <form method="POST" action="/login_submit">
                        <input type="text" name="username" placeholder="Username" required /><br />
                        <input type="password" name="password" placeholder="Password" required /><br />
                        <button type="submit">Login</button>
                    </form>
                </div>
            </body>
        </html>
        """
        return HTMLResponse(content=html_content, status_code=200)
    elif path == "login_submit":
        return HTMLResponse(content="<h3>Invalid Credentials. Access Denied.</h3>", status_code=401)
    elif path == "api/v1/status":
        return JSONResponse(content={"status": "online", "version": "1.0.4"}, status_code=200)
    else:
        return HTMLResponse(content="<h1>404 Not Found</h1>", status_code=404)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
