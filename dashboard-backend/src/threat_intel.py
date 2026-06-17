"""Threat Intelligence enrichment module.

Three async clients (VirusTotal, AbuseIPDB, ip-api.com) with a shared
SQLite cache. Each source is cached independently so a VT miss/key absence
never blocks a cached ip-api result. Callers always get a dict back — never
raises so it is safe on the hot path.

TTLs:
  VirusTotal  : 24h  (free: 500/day)
  AbuseIPDB   : 24h  (free: 1000/day)
  ip-api.com  : 7d   (free, no key, 45 req/min)
"""

import asyncio
import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Optional

import httpx

logger = logging.getLogger("dashboard.threat_intel")

VT_API_KEY    = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSE_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

ABUSE_CATEGORY_MAP = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
    4: "DDoS Attack", 5: "FTP Brute Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
    10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking",
    16: "SQL Injection", 17: "Spoofing", 18: "Brute Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH", 23: "IoT Targeted",
}

_VT_TTL_S    = 86400      # 24 h
_ABUSE_TTL_S = 86400      # 24 h
_IPAPI_TTL_S = 86400 * 7  # 7 d

# Very simple token-bucket for VT free tier (4 req / 60 s)
_vt_lock    = asyncio.Lock()
_vt_calls:  list[float] = []   # epoch timestamps of recent calls
_VT_MAX     = 4
_VT_WINDOW  = 61.0             # slightly over 60 s to be safe


# ---------------------------------------------------------------------------
# Cache helpers (operate on an already-open sqlite3.Connection)
# ---------------------------------------------------------------------------

def _ensure_ti_table(conn: sqlite3.Connection):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS threat_intel_cache (
            ioc_value   TEXT NOT NULL,
            source_api  TEXT NOT NULL,
            result_json TEXT NOT NULL,
            cached_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at  TIMESTAMP NOT NULL,
            PRIMARY KEY (ioc_value, source_api)
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ti_cache_ioc "
        "ON threat_intel_cache(ioc_value)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ti_cache_expires "
        "ON threat_intel_cache(expires_at)"
    )
    conn.commit()


def _get_cache(conn: sqlite3.Connection, ioc_value: str, source_api: str) -> Optional[dict]:
    try:
        row = conn.execute(
            "SELECT result_json FROM threat_intel_cache "
            "WHERE ioc_value=? AND source_api=? AND expires_at > datetime('now')",
            (ioc_value, source_api),
        ).fetchone()
        return json.loads(row[0]) if row else None
    except Exception:
        return None


def _set_cache(conn: sqlite3.Connection, ioc_value: str, source_api: str,
               data: dict, ttl_seconds: int):
    try:
        expires = (datetime.utcnow() + timedelta(seconds=ttl_seconds)).isoformat()
        conn.execute(
            "INSERT OR REPLACE INTO threat_intel_cache "
            "(ioc_value, source_api, result_json, cached_at, expires_at) "
            "VALUES (?, ?, ?, datetime('now'), ?)",
            (ioc_value, source_api, json.dumps(data), expires),
        )
        conn.commit()
    except Exception as e:
        logger.debug(f"cache write failed: {e}")


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

async def _vt_rate_gate():
    """Block until we are within the 4-req/min free-tier limit."""
    async with _vt_lock:
        now = time.monotonic()
        # drop timestamps outside the window
        cutoff = now - _VT_WINDOW
        while _vt_calls and _vt_calls[0] < cutoff:
            _vt_calls.pop(0)
        if len(_vt_calls) >= _VT_MAX:
            wait = _VT_WINDOW - (now - _vt_calls[0]) + 0.5
            if wait > 0:
                await asyncio.sleep(wait)
        _vt_calls.append(time.monotonic())


async def vt_lookup(ip: str, conn: sqlite3.Connection) -> dict:
    if not VT_API_KEY:
        return {"error": "no_key"}

    cached = _get_cache(conn, ip, "virustotal")
    if cached is not None:
        return cached

    await _vt_rate_gate()
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": VT_API_KEY},
            )
            if resp.status_code == 404:
                result = {"error": "not_found"}
            elif resp.status_code == 401:
                return {"error": "invalid_key"}
            elif resp.status_code != 200:
                return {"error": f"http_{resp.status_code}"}
            else:
                raw = resp.json()
                attrs = raw.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                analysis_results = attrs.get("last_analysis_results", {})
                flagged_vendors = sorted(
                    [
                        {"name": vendor, "verdict": details.get("category", "")}
                        for vendor, details in analysis_results.items()
                        if details.get("category") in ("malicious", "suspicious")
                    ],
                    key=lambda x: (0 if x["verdict"] == "malicious" else 1, x["name"].lower()),
                )
                result = {
                    "malicious":         stats.get("malicious", 0),
                    "suspicious":        stats.get("suspicious", 0),
                    "harmless":          stats.get("harmless", 0),
                    "undetected":        stats.get("undetected", 0),
                    "total_engines":     sum(stats.values()),
                    "last_analysis_date": attrs.get("last_analysis_date"),
                    "tags":              attrs.get("tags", []),
                    "country":           attrs.get("country", ""),
                    "asn":               attrs.get("asn", ""),
                    "as_owner":          attrs.get("as_owner", ""),
                    "reputation":        attrs.get("reputation", 0),
                    "flagged_vendors":   flagged_vendors,
                }
    except Exception as e:
        logger.warning(f"VT lookup failed for {ip}: {e}")
        return {"error": str(e)}

    _set_cache(conn, ip, "virustotal", result, _VT_TTL_S)
    return result


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------

async def abuse_lookup(ip: str, conn: sqlite3.Connection) -> dict:
    if not ABUSE_API_KEY:
        return {"error": "no_key"}

    cached = _get_cache(conn, ip, "abuseipdb")
    if cached is not None:
        return cached

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                headers={"Key": ABUSE_API_KEY, "Accept": "application/json"},
            )
            if resp.status_code == 401:
                return {"error": "invalid_key"}
            elif resp.status_code == 429:
                return {"error": "rate_limited"}
            elif resp.status_code != 200:
                return {"error": f"http_{resp.status_code}"}
            raw = resp.json().get("data", {})
            seen_cats: set[int] = set()
            for report in raw.get("reports", []):
                seen_cats.update(report.get("categories", []))
            categories = [
                ABUSE_CATEGORY_MAP.get(c, f"Category {c}")
                for c in sorted(seen_cats)
            ]
            result = {
                "abuse_confidence_score": raw.get("abuseConfidenceScore", 0),
                "total_reports":          raw.get("totalReports", 0),
                "last_reported_at":       raw.get("lastReportedAt"),
                "is_tor":                 raw.get("isTor", False),
                "isp":                    raw.get("isp", ""),
                "usage_type":             raw.get("usageType", ""),
                "domain":                 raw.get("domain", ""),
                "country_code":           raw.get("countryCode", ""),
                "num_distinct_users":     raw.get("numDistinctUsers", 0),
                "categories":             categories,
            }
    except Exception as e:
        logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")
        return {"error": str(e)}

    _set_cache(conn, ip, "abuseipdb", result, _ABUSE_TTL_S)
    return result


# ---------------------------------------------------------------------------
# ip-api.com (free, no key required)
# ---------------------------------------------------------------------------

async def ipapi_lookup(ip: str, conn: sqlite3.Connection) -> dict:
    cached = _get_cache(conn, ip, "ipapi")
    if cached is not None:
        return cached

    fields = "status,country,countryCode,regionName,city,isp,org,as,hosting,proxy,mobile"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": fields},
            )
            if resp.status_code != 200:
                return {"error": f"http_{resp.status_code}"}
            raw = resp.json()
            if raw.get("status") != "success":
                return {"error": raw.get("message", "failed")}
            result = {
                "country":     raw.get("country", ""),
                "country_code": raw.get("countryCode", ""),
                "region":      raw.get("regionName", ""),
                "city":        raw.get("city", ""),
                "isp":         raw.get("isp", ""),
                "org":         raw.get("org", ""),
                "as_info":     raw.get("as", ""),
                "hosting":     raw.get("hosting", False),   # True = datacenter/VPS
                "proxy":       raw.get("proxy", False),     # True = VPN/proxy/Tor
                "mobile":      raw.get("mobile", False),
            }
    except Exception as e:
        logger.warning(f"ip-api lookup failed for {ip}: {e}")
        return {"error": str(e)}

    _set_cache(conn, ip, "ipapi", result, _IPAPI_TTL_S)
    return result


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------

def _hosting_label(ipapi: dict, abuse: dict) -> str:
    """Derive a human-readable infrastructure label."""
    if abuse.get("is_tor"):
        return "Tor Exit"
    if ipapi.get("proxy"):
        return "VPN/Proxy"
    if ipapi.get("hosting"):
        return "Datacenter"
    if ipapi.get("mobile"):
        return "Mobile ISP"
    usage = (abuse.get("usage_type") or "").lower()
    if "data center" in usage or "hosting" in usage:
        return "Datacenter"
    if "vpn" in usage or "proxy" in usage:
        return "VPN/Proxy"
    if ipapi.get("isp") or ipapi.get("org"):
        return "ISP"
    return "Unknown"


async def enrich_ip(ip: str, conn: sqlite3.Connection) -> dict:
    """Enrich a single IP with all three sources. Always returns a dict."""
    _ensure_ti_table(conn)
    vt, abuse, ipapi = await asyncio.gather(
        vt_lookup(ip, conn),
        abuse_lookup(ip, conn),
        ipapi_lookup(ip, conn),
        return_exceptions=True,
    )
    # gather with return_exceptions means exceptions become the value
    if isinstance(vt, Exception):    vt    = {"error": str(vt)}
    if isinstance(abuse, Exception): abuse = {"error": str(abuse)}
    if isinstance(ipapi, Exception): ipapi = {"error": str(ipapi)}

    return {
        "ip":             ip,
        "virustotal":     vt,
        "abuseipdb":      abuse,
        "ipapi":          ipapi,
        "hosting_label":  _hosting_label(ipapi or {}, abuse or {}),
    }
