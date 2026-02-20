from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
import logging
import uuid
import aiohttp
from datetime import datetime
from typing import Dict, Optional
import re

logger = logging.getLogger(__name__)

app = FastAPI(title="HTTP Honeypot", docs_url=None, redoc_url=None)

# Configuration
AI_ENGINE_URL = "http://ai-engine:8002"
SANDBOX_URL = "http://sandbox-store:8001"
DASHBOARD_URL = "http://dashboard-backend:8000"

# Scanner detection patterns
SCANNER_SIGNATURES = {
    'nmap': re.compile(r'nmap', re.IGNORECASE),
    'nikto': re.compile(r'nikto', re.IGNORECASE),
    'sqlmap': re.compile(r'sqlmap', re.IGNORECASE),
    'burp': re.compile(r'burp', re.IGNORECASE),
    'metasploit': re.compile(r'metasploit', re.IGNORECASE),
    'masscan': re.compile(r'masscan', re.IGNORECASE),
    'zap': re.compile(r'owasp.*zap', re.IGNORECASE),
    'acunetix': re.compile(r'acunetix', re.IGNORECASE),
}

VULN_SCAN_PATTERNS = {
    'sqli': [
        r"'|\"|\-\-|;|\/\*|\*\/",  # SQL injection
        r"union.*select",
        r"or\s+1\s*=\s*1",
    ],
    'xss': [
        r"<script", 
        r"javascript:",
        r"onerror\s*=",
    ],
    'lfi': [
        r"\.\./",
        r"etc/passwd",
        r"windows/system32",
    ],
    'rce': [
        r";.*?(ls|cat|whoami|id)",
        r"\$\(.*?\)",
        r"`.*?`",
    ]
}

class HTTPSession:
    """Represents an HTTP attack session."""
    
    def __init__(self, source_ip: str):
        self.session_id = str(uuid.uuid4())
        self.source_ip = source_ip
        self.request_count = 0
        self.detected_scanners = set()
        self.detected_attacks = set()
        self.created_at = datetime.now()
    
    async def create_in_sandbox(self):
        """Create session in sandbox database."""
        try:
            async with aiohttp.ClientSession() as session:
                await session.post(
                    f"{SANDBOX_URL}/sessions/",
                    json={
                        'session_id': self.session_id,
                        'source_ip': self.source_ip,
                        'protocol': 'http'
                    }
                )
        except Exception as e:
            logger.error(f"Error creating sandbox session: {e}")

# Session tracking
active_sessions: Dict[str, HTTPSession] = {}

async def get_or_create_session(source_ip: str) -> HTTPSession:
    """Get existing session or create new one."""
    if source_ip not in active_sessions:
        session = HTTPSession(source_ip)
        await session.create_in_sandbox()
        active_sessions[source_ip] = session
    return active_sessions[source_ip]

def detect_scanner(user_agent: str, headers: dict) -> Optional[str]:
    """Detect security scanner from User-Agent and headers."""
    for scanner_name, pattern in SCANNER_SIGNATURES.items():
        if pattern.search(user_agent):
            return scanner_name
    return None

def detect_attack_type(request: Request, body: str) -> set:
    """Detect attack types from request."""
    detected = set()
    
    # Combine all searchable text
    search_text = f"{request.url.path} {request.url.query} {body}"
    
    for attack_type, patterns in VULN_SCAN_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, search_text, re.IGNORECASE):
                detected.add(attack_type)
                break
    
    return detected

async def log_request_to_sandbox(session: HTTPSession, request: Request, 
                                 body: str, scanner: Optional[str], attacks: set):
    """Log request details to sandbox."""
    try:
        # Build command-like representation
        command = f"{request.method} {request.url.path}"
        if request.url.query:
            command += f"?{request.url.query}"
        
        # Build detailed output
        output = f"""HTTP Request Details:
Method: {request.method}
Path: {request.url.path}
Query: {request.url.query or '(none)'}
Headers: {dict(request.headers)}
Body: {body[:500] if body else '(none)'}
Scanner: {scanner or 'Unknown'}
Detected Attacks: {', '.join(attacks) if attacks else 'None'}
"""
        
        async with aiohttp.ClientSession() as http_session:
            await http_session.post(
                f"{SANDBOX_URL}/commands/{session.session_id}",
                json={
                    'command': command,
                    'output': output,
                    'exit_code': 0,
                    'duration_ms': 0
                }
            )
            
            # Log attack techniques if detected
            if attacks:
                technique_map = {
                    'sqli': ('T1190', 'Exploit Public-Facing Application', 'Initial Access'),
                    'xss': ('T1059.007', 'JavaScript', 'Execution'),
                    'lfi': ('T1083', 'File and Directory Discovery', 'Discovery'),
                    'rce': ('T1059', 'Command and Scripting Interpreter', 'Execution')
                }
                
                for attack in attacks:
                    if attack in technique_map:
                        tech_id, tech_name, tactic = technique_map[attack]
                        await http_session.post(
                            f"{SANDBOX_URL}/attack-techniques/{session.session_id}",
                            json={
                                'technique_id': tech_id,
                                'technique_name': tech_name,
                                'tactic': tactic,
                                'confidence': 0.85,
                                'evidence': command
                            }
                        )
    
    except Exception as e:
        logger.error(f"Error logging to sandbox: {e}")

async def generate_ai_response(session: HTTPSession, request: Request, 
                               body: str) -> Dict:
    """Generate response using AI engine."""
    try:
        context = {
            'session_id': session.session_id,
            'method': request.method,
            'path': request.url.path,
            'query': str(request.url.query),
            'headers': dict(request.headers),
            'body': body,
            'request_count': session.request_count
        }
        
        async with aiohttp.ClientSession() as http_session:
            async with http_session.post(
                f"{AI_ENGINE_URL}/process-http",
                json=context,
                timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
                else:
                    return {
                        'status_code': 404,
                        'content': '<html><body><h1>404 Not Found</h1></body></html>',
                        'content_type': 'text/html'
                    }
    except Exception as e:
        logger.error(f"Error calling AI engine: {e}")
        return {
            'status_code': 500,
            'content': '<html><body><h1>500 Internal Server Error</h1></body></html>',
            'content_type': 'text/html'
        }

@app.middleware("http")
async def honeypot_middleware(request: Request, call_next):
    """Process all HTTP requests through honeypot logic."""
    
    # Get client IP
    source_ip = request.client.host
    
    # Get or create session
    session = await get_or_create_session(source_ip)
    session.request_count += 1
    
    # Read request body
    body = ""
    if request.method in ['POST', 'PUT', 'PATCH']:
        body_bytes = await request.body()
        body = body_bytes.decode('utf-8', errors='ignore')
    
    # Detect scanner
    user_agent = request.headers.get('user-agent', '')
    scanner = detect_scanner(user_agent, dict(request.headers))
    if scanner:
        session.detected_scanners.add(scanner)
    
    # Detect attack types
    attacks = detect_attack_type(request, body)
    session.detected_attacks.update(attacks)
    
    # Log request
    logger.info(f"HTTP Request - IP: {source_ip}, Method: {request.method}, "
                f"Path: {request.url.path}, Scanner: {scanner}, Attacks: {attacks}")
    
    # Log to sandbox
    await log_request_to_sandbox(session, request, body, scanner, attacks)
    
    # Generate AI response
    ai_response = await generate_ai_response(session, request, body)
    
    # Return response
    return Response(
        content=ai_response.get('content', ''),
        status_code=ai_response.get('status_code', 200),
        media_type=ai_response.get('content_type', 'text/html')
    )

# Catch-all route
@app.get("/{full_path:path}")
async def catch_all_get(full_path: str):
    """This will never be reached due to middleware, but required for FastAPI."""
    return {"message": "Not found"}

@app.post("/{full_path:path}")
async def catch_all_post(full_path: str):
    """This will never be reached due to middleware, but required for FastAPI."""
    return {"message": "Not found"}

@app.put("/{full_path:path}")
async def catch_all_put(full_path: str):
    return {"message": "Not found"}

@app.delete("/{full_path:path}")
async def catch_all_delete(full_path: str):
    return {"message": "Not found"}

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "http-frontend"}

if __name__ == "__main__":
    import uvicorn
    import os
    
    port = int(os.getenv('HTTP_PORT', 8080))
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    uvicorn.run(app, host="0.0.0.0", port=port)
