from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict
import os
from llm_provider import LLMProvider
from response_cache import ResponseCache
from extractor import extract_iocs
from mitre import map_command_to_mitre

app = FastAPI(title="AI Engine")

# Initialize
llm = LLMProvider(provider="gemini")
cache = ResponseCache()

class CommandRequest(BaseModel):
    command: str
    context: Dict
    history: Optional[List[Dict]] = []

@app.post("/generate-response")
async def generate_response(req: CommandRequest):
    """Generate shell response using LLM"""
    
    # Extract IOCs from the command
    iocs = extract_iocs(req.command)
    
    # Map command to MITRE techniques
    mitre_techniques = map_command_to_mitre(req.command)
    
    # Check cache first
    cached = cache.get(req.command, req.context)
    if cached:
        return {"response": cached, "cached": True, "iocs": iocs, "mitre_techniques": mitre_techniques}
    
    # Generate new response
    response = llm.generate_shell_response(
        req.command,
        req.context,
        req.history
    )
    
    # Cache it
    cache.set(req.command, req.context, response)
    
    # Extract IOCs from response as well, optionally
    response_iocs = extract_iocs(response)
    
    # Merge command IOCs and response IOCs
    all_iocs = iocs + [ioc for ioc in response_iocs if ioc not in iocs]
    
    return {
        "response": response, 
        "cached": False, 
        "iocs": all_iocs,
        "mitre_techniques": mitre_techniques
    }

@app.get("/health")
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
