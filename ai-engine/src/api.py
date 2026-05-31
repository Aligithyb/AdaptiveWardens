from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional, List, Dict
from llm_provider import LLMProvider
from response_cache import ResponseCache
from extractor import extract_iocs
from mitre import map_command_to_mitre
from deterministic import lookup as deterministic_lookup

app = FastAPI(title="AI Engine")

llm = LLMProvider()
cache = ResponseCache()


class CommandRequest(BaseModel):
    command: str
    context: Dict
    history: Optional[List[Dict]] = []


@app.post("/generate-response")
async def generate_response(req: CommandRequest):
    mitre_techniques = map_command_to_mitre(req.command)

    # Tier-1 / C3: short-circuit deterministic commands. Free, instant, no tokens.
    det = deterministic_lookup(req.command, req.context)
    if det is not None:
        response, _scope = det
        iocs = extract_iocs(req.command)
        return {
            "response": response,
            "cached": True,
            "source": "deterministic",
            "iocs": iocs,
            "mitre_techniques": mitre_techniques,
        }

    # Tier-1 / C7: cache hit returns cached IOCs too, skipping a fresh extractor run.
    cached = cache.get(req.command, req.context)
    if cached is not None:
        return {
            "response": cached["response"],
            "cached": True,
            "source": "cache",
            "iocs": cached["iocs"],
            "mitre_techniques": cached["mitre"] or mitre_techniques,
        }

    response = llm.generate_shell_response(req.command, req.context, req.history)

    cmd_iocs = extract_iocs(req.command)
    resp_iocs = extract_iocs(response)
    seen = {(i["ioc_type"], i["value"]) for i in cmd_iocs}
    all_iocs = cmd_iocs + [i for i in resp_iocs if (i["ioc_type"], i["value"]) not in seen]

    cache.set(req.command, req.context, response, iocs=all_iocs, mitre=mitre_techniques)

    return {
        "response": response,
        "cached": False,
        "source": "llm",
        "iocs": all_iocs,
        "mitre_techniques": mitre_techniques,
    }


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.get("/cache/stats")
async def cache_stats():
    return cache.get_stats()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
