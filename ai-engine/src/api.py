from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict
import os
from llm_provider import LLMProvider
from response_cache import ResponseCache

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
    
    # Check cache first
    cached = cache.get(req.command, req.context)
    if cached:
        return {"response": cached, "cached": True}
    
    # Generate new response
    response = llm.generate_shell_response(
        req.command,
        req.context,
        req.history
    )
    
    # Cache it
    cache.set(req.command, req.context, response)
    
    return {"response": response, "cached": False}

@app.get("/health")
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
