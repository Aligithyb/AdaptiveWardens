from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional, List, Dict
from llm_provider import LLMProvider
from response_cache import ResponseCache
from extractor import extract_iocs
from mitre import map_command_to_mitre
from mitre_ai import classify_with_llm
from report import generate_session_report
from deterministic import lookup as deterministic_lookup

app = FastAPI(title="AI Engine")

llm = LLMProvider()
cache = ResponseCache()


class CommandRequest(BaseModel):
    command: str
    context: Dict
    history: Optional[List[Dict]] = []


class SessionSummaryRequest(BaseModel):
    session: Dict
    commands: List[Dict] = []
    techniques: List[Dict] = []
    iocs: List[Dict] = []


def _resolve_mitre(command: str) -> list:
    """Hybrid MITRE resolver: regex → cached AI verdict → fresh AI call."""
    hits = map_command_to_mitre(command)
    if hits:
        return hits

    cached = cache.get_mitre(command)
    if cached is not None:
        return cached

    ai = classify_with_llm(command, llm)
    # Cache even an empty list so we don't re-ask for the same unknown command.
    cache.set_mitre(command, ai)
    return ai


@app.post("/generate-response")
async def generate_response(req: CommandRequest):
    mitre_techniques = _resolve_mitre(req.command)

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

    source_ip = req.context.get("source_ip") if isinstance(req.context, dict) else None
    response = llm.generate_shell_response(req.command, req.context, req.history, source_ip=source_ip)

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


@app.post("/summarize-session")
async def summarize_session(req: SessionSummaryRequest):
    """Generate a structured SOC incident report for a session."""
    payload = {
        "session": req.session,
        "commands": req.commands,
        "techniques": req.techniques,
        "iocs": req.iocs,
    }
    report = generate_session_report(payload, llm)
    return {"report": report}


@app.get("/health")
async def health():
    return {"status": "healthy"}


@app.get("/cache/stats")
async def cache_stats():
    return cache.get_stats()


@app.get("/budget/stats")
async def budget_stats():
    """Daily LLM token spend + per-IP rate limiter counters."""
    return {
        "budget": llm.budget.stats(),
        "rate_limit": llm.rate_limiter.stats(),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
