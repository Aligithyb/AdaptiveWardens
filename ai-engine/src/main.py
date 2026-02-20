from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Optional
import logging
from models.model_manager import AIModelManager
from ioc_extractor import IOCExtractor
from attack_mapper import MITREAttackMapper
import aiohttp
import os

logger = logging.getLogger(__name__)

app = FastAPI(title="AI Engine", version="1.0.0")

# Initialize components
model_manager = AIModelManager(
    model_name=os.getenv('AI_MODEL', 'distilgpt2'),
    device=os.getenv('AI_DEVICE', 'cpu')
)
ioc_extractor = IOCExtractor()
attack_mapper = MITREAttackMapper()

SANDBOX_URL = os.getenv('SANDBOX_URL', 'http://sandbox-store:8001')

# ==================== MODELS ====================

class CommandRequest(BaseModel):
    session_id: str
    command: str
    current_directory: str = '/root'
    username: str = 'root'
    hostname: str = 'ubuntu-server'
    environment: Dict[str, str] = {}
    recent_commands: List[Dict] = []

class HTTPRequest(BaseModel):
    session_id: str
    method: str
    path: str
    query: str = ''
    headers: Dict[str, str] = {}
    body: str = ''
    request_count: int = 0

# ==================== HELPER FUNCTIONS ====================

async def save_iocs_to_sandbox(session_id: str, iocs: Dict):
    """Save extracted IOCs to sandbox database."""
    try:
        async with aiohttp.ClientSession() as session:
            for ioc_type, ioc_list in iocs.items():
                for ioc in ioc_list:
                    await session.post(
                        f"{SANDBOX_URL}/iocs/{session_id}",
                        json={
                            'ioc_type': ioc['type'],
                            'value': ioc['value'],
                            'confidence': ioc['confidence'],
                            'context': ioc.get('context', '')
                        }
                    )
    except Exception as e:
        logger.error(f"Error saving IOCs: {e}")

async def save_techniques_to_sandbox(session_id: str, techniques: List[Dict]):
    """Save detected ATT&CK techniques to sandbox."""
    try:
        async with aiohttp.ClientSession() as session:
            for tech in techniques:
                await session.post(
                    f"{SANDBOX_URL}/attack-techniques/{session_id}",
                    json={
                        'technique_id': tech['technique_id'],
                        'technique_name': tech['technique_name'],
                        'tactic': tech['tactic'],
                        'confidence': tech['confidence'],
                        'evidence': tech['evidence']
                    }
                )
    except Exception as e:
        logger.error(f"Error saving techniques: {e}")

# ==================== ENDPOINTS ====================

@app.post("/process")
async def process_command(request: CommandRequest):
    """
    Process a command from SSH frontend.
    Returns AI-generated output and state mutations.
    """
    try:
        # Build context for AI
        context = {
            'current_directory': request.current_directory,
            'username': request.username,
            'hostname': request.hostname,
            'recent_commands': request.recent_commands,
            'environment': request.environment
        }
        
        # Generate response
        output = model_manager.generate_response(
            command=request.command,
            context=context
        )
        
        # Extract state mutations
        mutations = model_manager.extract_state_mutations(
            command=request.command,
            output=output,
            context=context
        )
        
        # Extract IOCs
        command_iocs = ioc_extractor.extract_all(request.command, 'command')
        output_iocs = ioc_extractor.extract_all(output, 'output')
        
        # Combine IOCs
        all_iocs = {}
        for key in command_iocs.keys():
            all_iocs[key] = command_iocs[key] + output_iocs.get(key, [])
        
        # Map to ATT&CK
        techniques = attack_mapper.analyze_command(request.command)
        
        # Save IOCs and techniques asynchronously
        import asyncio
        asyncio.create_task(save_iocs_to_sandbox(request.session_id, all_iocs))
        asyncio.create_task(save_techniques_to_sandbox(request.session_id, techniques))
        
        return {
            'output': output,
            'exit_code': 0,
            'state_mutations': mutations,
            'iocs_count': sum(len(v) for v in all_iocs.values()),
            'techniques_count': len(techniques)
        }
        
    except Exception as e:
        logger.error(f"Error processing command: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/process-http")
async def process_http_request(request: HTTPRequest):
    """
    Process HTTP request and generate appropriate response.
    """
    try:
        # Determine response based on path and scanner detection
        if request.path == '/':
            # Return fake homepage
            content = """<!DOCTYPE html>
<html>
<head>
    <title>Welcome to nginx!</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
    </style>
</head>
<body>
    <h1>Welcome to nginx!</h1>
    <p>If you see this page, the nginx web server is successfully installed and working.</p>
    <p>For online documentation and support please refer to
    <a href="http://nginx.org/">nginx.org</a>.</p>
    <p><em>Thank you for using nginx.</em></p>
</body>
</html>"""
            return {
                'status_code': 200,
                'content': content,
                'content_type': 'text/html'
            }
        
        elif '/admin' in request.path.lower():
            # Fake admin login
            content = """<!DOCTYPE html>
<html>
<head><title>Admin Login</title></head>
<body>
    <h2>Administrator Login</h2>
    <form method="POST" action="/admin/login">
        <input type="text" name="username" placeholder="Username"><br>
        <input type="password" name="password" placeholder="Password"><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>"""
            return {
                'status_code': 200,
                'content': content,
                'content_type': 'text/html'
            }
        
        elif '.php' in request.path:
            # Fake PHP response
            return {
                'status_code': 200,
                'content': '<?php\n// Placeholder\necho "Hello World";\n?>',
                'content_type': 'text/plain'
            }
        
        else:
            # Default 404
            return {
                'status_code': 404,
                'content': '<html><body><h1>404 Not Found</h1></body></html>',
                'content_type': 'text/html'
            }
        
    except Exception as e:
        logger.error(f"Error processing HTTP request: {e}")
        return {
            'status_code': 500,
            'content': '<html><body><h1>500 Internal Server Error</h1></body></html>',
            'content_type': 'text/html'
        }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "ai-engine"}

if __name__ == "__main__":
    import uvicorn
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    uvicorn.run(app, host="0.0.0.0", port=8002)
