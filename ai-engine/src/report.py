"""SOC incident report generator.

generate_session_report() takes the full session payload (meta + commands +
techniques + IOCs) and returns a structured analyst narrative. When the LLM
budget is exhausted or the call fails, a deterministic fallback is assembled
from the structured data so the dashboard button never returns empty.
"""

import json
import logging
import re
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from llm_provider import LLMProvider

logger = logging.getLogger("ai-engine.report")

_REPORT_SYSTEM_PROMPT = """You are a senior SOC analyst writing an incident report for a honeypot session.
Given structured JSON data about an attacker session (metadata, commands executed, MITRE techniques, IOCs),
produce a concise but complete incident report as a JSON object.

The JSON object MUST have exactly these keys:
- executive_summary: 2-3 sentence plain-English summary for management. What happened, how bad, is it contained.
- attacker_objective: 1-2 sentences on what the attacker was trying to achieve (reconnaissance, data theft, persistence, etc.).
- kill_chain: array of objects {tactic, techniques: [string], summary: string} — one entry per observed tactic, in kill-chain order.
- notable_iocs: array of objects {type, value, significance} — the most meaningful indicators to block/monitor.
- severity_justification: 2-3 sentences explaining why this session has the given risk level, citing specific evidence.
- recommended_actions: array of strings — concrete defensive actions (block IP, rotate credentials, patch CVE, etc.).

Return ONLY the JSON object. No markdown, no code fences, no prose outside the JSON."""

_FENCE_RE = re.compile(r'^```[a-zA-Z0-9_-]*\s*$')
_REQUIRED_KEYS = {
    "executive_summary", "attacker_objective", "kill_chain",
    "notable_iocs", "severity_justification", "recommended_actions",
}


def _strip_fences(text: str) -> str:
    lines = text.strip().splitlines()
    lines = [l for l in lines if not _FENCE_RE.match(l.strip())]
    return "\n".join(lines).strip()


def _deterministic_report(payload: dict) -> dict:
    """Fallback report built from structured data — no LLM, always works."""
    session = payload.get("session", {})
    commands = payload.get("commands", [])
    techniques = payload.get("techniques", [])
    iocs = payload.get("iocs", [])

    risk = session.get("risk_level", "Unknown")
    src_ip = session.get("source_ip", "unknown")
    country = session.get("country") or "unknown"
    tactic_counts: dict[str, int] = {}
    for t in techniques:
        tac = t.get("tactic", "Unknown")
        tactic_counts[tac] = tactic_counts.get(tac, 0) + 1
    top_tactics = sorted(tactic_counts.items(), key=lambda x: -x[1])
    tactic_str = ", ".join(t for t, _ in top_tactics[:3]) if top_tactics else "no specific tactics"

    kill_chain = []
    for tac, count in top_tactics:
        tech_names = list({t.get("technique_name", "") for t in techniques if t.get("tactic") == tac})[:3]
        kill_chain.append({
            "tactic": tac,
            "techniques": tech_names,
            "summary": f"{count} technique(s) observed in this phase.",
        })

    notable = []
    for ioc in iocs[:5]:
        notable.append({
            "type": ioc.get("ioc_type", ""),
            "value": ioc.get("value", ""),
            "significance": f"Confidence {round((ioc.get('confidence', 0)) * 100)}%",
        })

    actions = [f"Block source IP {src_ip} at perimeter firewall."]
    if any("shadow" in (c.get("command", "")) for c in commands):
        actions.append("Rotate all system credentials — attacker attempted to read /etc/shadow.")
    if any("wget" in (c.get("command", "")) or "curl" in (c.get("command", "")) for c in commands):
        actions.append("Review outbound HTTP/S connections for exfiltration from this host.")
    if any("crontab" in (c.get("command", "")) or "bashrc" in (c.get("command", "")) for c in commands):
        actions.append("Audit cron jobs and shell startup files for persistence mechanisms.")
    actions.append("Review this session in full via SessionPlayback and export for forensic records.")

    return {
        "executive_summary": (
            f"A {risk.lower()}-risk SSH session was recorded from {src_ip} ({country}). "
            f"The attacker executed {len(commands)} command(s) and triggered {len(techniques)} MITRE technique(s) "
            f"across {len(tactic_counts)} tactic(s) ({tactic_str}). "
            f"This report was generated from structured data (AI narrative unavailable)."
        ),
        "attacker_objective": (
            f"Based on observed tactics ({tactic_str}), the attacker appears to have been performing "
            "reconnaissance and exploring the environment for valuable data or persistence opportunities."
        ),
        "kill_chain": kill_chain,
        "notable_iocs": notable,
        "severity_justification": (
            f"Risk assessed as {risk}. "
            f"{len(techniques)} MITRE technique(s) detected; "
            f"{len(iocs)} IOC(s) extracted. "
            "See full session commands for detailed evidence."
        ),
        "recommended_actions": actions,
        "source": "deterministic",
    }


def _build_user_message(payload: dict) -> str:
    session = payload.get("session", {})
    commands = payload.get("commands", [])
    techniques = payload.get("techniques", [])
    iocs = payload.get("iocs", [])

    # Trim to keep tokens manageable — last 40 commands is plenty for a report
    cmd_summary = [
        {"seq": c.get("sequence_number"), "cmd": c.get("command", "")[:200], "exit": c.get("exit_code")}
        for c in commands[-40:]
    ]
    tech_summary = [
        {"id": t.get("technique_id"), "name": t.get("technique_name"), "tactic": t.get("tactic"),
         "confidence": round((t.get("confidence") or 0) * 100)}
        for t in techniques
    ]
    ioc_summary = [
        {"type": i.get("ioc_type"), "value": i.get("value", "")[:100], "confidence": round((i.get("confidence") or 0) * 100)}
        for i in iocs[:20]
    ]

    data = {
        "session": {
            "source_ip": session.get("source_ip"),
            "country": session.get("country"),
            "protocol": session.get("protocol"),
            "risk_level": session.get("risk_level"),
            "start_time": session.get("start_time"),
            "end_time": session.get("end_time"),
            "command_count": len(commands),
        },
        "commands": cmd_summary,
        "mitre_techniques": tech_summary,
        "iocs": ioc_summary,
    }
    return json.dumps(data, default=str)


def generate_session_report(payload: dict, llm: "LLMProvider") -> dict:
    """Generate a structured SOC incident report for a session.

    Always returns a dict with the six report keys. Falls back to a
    deterministic report if the LLM is unavailable or fails.
    """
    if llm.client is None or not llm.budget.can_call():
        logger.debug("report: LLM unavailable, returning deterministic report")
        return _deterministic_report(payload)

    user_msg = _build_user_message(payload)
    backoff = [0.0, 2.0]
    timeouts = [25.0, 30.0]
    last_exc = None

    for attempt, (sleep_s, t_out) in enumerate(zip(backoff, timeouts)):
        if sleep_s:
            time.sleep(sleep_s)
        try:
            resp = llm.client.with_options(timeout=t_out).chat.completions.create(
                model=llm.model_name,
                messages=[
                    {"role": "system", "content": _REPORT_SYSTEM_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.2,
                max_tokens=700,
                extra_body={"thinking": {"type": "disabled"}},
            )
            # Charge budget
            try:
                usage = getattr(resp, "usage", None)
                if usage:
                    details = getattr(usage, "prompt_tokens_details", None)
                    cached = getattr(details, "cached_tokens", 0) if details else 0
                    total_in = getattr(usage, "prompt_tokens", 0) or 0
                    total_out = getattr(usage, "completion_tokens", 0) or 0
                    llm.budget.record(max(0, total_in - (cached or 0)), total_out)
            except Exception:
                pass

            raw = (resp.choices[0].message.content or "").strip()
            raw = _strip_fences(raw)
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                raise ValueError("LLM returned non-dict")
            missing = _REQUIRED_KEYS - set(parsed.keys())
            if missing:
                logger.warning(f"report: LLM response missing keys {missing}, using deterministic")
                return _deterministic_report(payload)
            parsed["source"] = "ai"
            return parsed
        except json.JSONDecodeError:
            logger.debug(f"report: JSON parse error on attempt {attempt+1}, falling back")
            return _deterministic_report(payload)
        except Exception as e:
            last_exc = e
            logger.warning(f"report: attempt {attempt+1} failed: {e}")

    logger.error(f"report: all attempts failed: {last_exc}")
    return _deterministic_report(payload)
