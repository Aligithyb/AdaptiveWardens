#!/usr/bin/env python3
"""HTTP honeypot — NexoPay corporate portal.

Key design decisions vs. the naive one-session-per-request approach:

SESSION GROUPING
  All requests from the same source IP within SESSION_WINDOW_SECONDS are
  merged into one session. Bots typically spray hundreds of requests in a
  few seconds — without grouping those become hundreds of useless sessions
  that bury real signal in the dashboard.

NOISE FILTER
  Favicon, robots.txt, well-known paths, and recognised legitimate crawlers
  are silently swallowed (respond normally, don't log). They tell us nothing.

RATE CAP PER SESSION
  After MAX_CMDS_PER_SESSION commands we stop logging new commands from that
  IP (still respond) to prevent one noisy scanner from flooding a session
  with thousands of entries.

MITRE DETECTION
  Expanded from two patterns to ~15 covering the most common HTTP attack
  classes: scanning, SQLi, path traversal, LFI, RCE/command injection,
  credential stuffing, secret file hunting, Log4Shell, SSRF, and more.

DECEPTION RESPONSES
  Common attack targets (/.env, /wp-admin, /phpmyadmin, /actuator,
  /api/v1/users, admin panels) return realistic-looking responses so
  attackers stay engaged and reveal more of their toolchain.
"""

import asyncio
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SANDBOX_URL     = os.getenv("SANDBOX_URL",    "http://localhost:8001")
AI_ENGINE_URL   = os.getenv("AI_ENGINE_URL",  "http://localhost:8002")
SESSION_WINDOW  = int(os.getenv("HTTP_SESSION_WINDOW", "300"))   # 5 min
MAX_CMDS        = int(os.getenv("HTTP_MAX_CMDS_PER_SESSION", "60"))
FRONTDOOR_FDID  = os.getenv("FRONTDOOR_FDID", "")               # verify FD origin

app = FastAPI(title="NexoPay Corporate Portal")
http_client = httpx.AsyncClient(timeout=8.0)

# ---------------------------------------------------------------------------
# In-memory session store  {source_ip: {session_id, last_seen, cmd_count}}
# Lightweight — only unique attacker IPs, not per-request.
# ---------------------------------------------------------------------------

_sessions: dict[str, dict] = {}
_lock = asyncio.Lock()


async def _get_or_create_session(ip: str) -> Optional[str]:
    """Return an active session_id for ip, creating one if needed.

    Returns None when the session has hit MAX_CMDS (still respond, don't log).
    """
    async with _lock:
        now = datetime.now(timezone.utc).timestamp()
        entry = _sessions.get(ip)

        if entry and (now - entry["last_seen"]) < SESSION_WINDOW:
            if entry["cmd_count"] >= MAX_CMDS:
                return None                          # rate cap hit — stop logging
            entry["last_seen"] = now
            entry["cmd_count"] += 1
            return entry["session_id"]

        # New session (either first visit or previous window expired)
        session_id = str(uuid.uuid4())
        _sessions[ip] = {"session_id": session_id, "last_seen": now, "cmd_count": 1}
        return session_id


# ---------------------------------------------------------------------------
# Noise filter
# ---------------------------------------------------------------------------

_BORING_PATHS = re.compile(
    r"^(favicon\.ico|robots\.txt|sitemap\.xml|"
    r"\.well-known/|apple-touch-icon|browserconfig\.xml|"
    r"ads\.txt|humans\.txt|security\.txt)$",
    re.IGNORECASE,
)

_LEGIT_UA = re.compile(
    r"(Googlebot|Bingbot|Slurp|DuckDuckBot|Baiduspider|YandexBot|"
    r"facebookexternalhit|Twitterbot|LinkedInBot|Applebot|"
    r"AhrefsBot|SemrushBot|MJ12bot|DataForSeoBot|PetalBot)",
    re.IGNORECASE,
)

def _is_noise(path: str, ua: str) -> bool:
    return bool(_BORING_PATHS.match(path.lstrip("/"))) or bool(_LEGIT_UA.search(ua))


# ---------------------------------------------------------------------------
# MITRE ATT&CK detection from HTTP requests
# ---------------------------------------------------------------------------

_MITRE_RULES = [
    # Scanning
    (re.compile(r"nikto|nuclei|nmap|zgrab|masscan|dirbuster|gobuster|ffuf|wfuzz|"
                r"sqlmap|nessus|openvas|burpsuite|acunetix|ZAP|"
                r"python-requests/|Go-http-client|curl/|libwww|"
                r"zgrab|masscan|shodan", re.I),
     "ua", "T1595.002", "Active Scanning: Vulnerability Scanning", "Reconnaissance", 0.90),

    # Credential stuffing / brute force
    (re.compile(r"login|signin|auth|wp-login|admin|administrator|user|account", re.I),
     "path", "T1110.004", "Brute Force: Credential Stuffing", "Initial Access", 0.65),

    # SQLi
    (re.compile(r"(\bselect\b.*\bfrom\b|\bunion\b.*\bselect\b|'--|\bor\b\s+1=1|"
                r"sleep\(\d+\)|benchmark\(|waitfor\s+delay|xp_cmdshell|"
                r"0x[0-9a-f]+|char\(\d+\)|information_schema)", re.I),
     "body", "T1190", "Exploit Public-Facing Application: SQLi", "Initial Access", 0.90),

    # Path traversal / LFI
    (re.compile(r"\.\./|\.\.\\|%2e%2e|%252e%252e|/etc/passwd|/etc/shadow|"
                r"/proc/self|/var/log|/windows/win\.ini|boot\.ini", re.I),
     "url", "T1055", "Path Traversal / LFI", "Initial Access", 0.92),

    # RCE / command injection
    (re.compile(r"(;|\||\`|\$\()\s*(id|whoami|uname|cat\s|ls\s|wget|curl|bash|sh|"
                r"python|perl|nc\s|ncat|/bin/sh|/bin/bash|cmd\.exe|powershell)", re.I),
     "body", "T1059", "Command and Scripting Interpreter", "Execution", 0.95),

    # Secret / config file hunting
    (re.compile(r"\.(env|git|svn|htaccess|htpasswd|bak|sql|log|conf|cfg|ini|"
                r"config|backup|old|orig|swp|yml|yaml|json|xml|pem|key|crt|"
                r"p12|pfx)(\b|$)", re.I),
     "path", "T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access", 0.85),

    # SSRF
    (re.compile(r"169\.254\.169\.254|metadata\.google\.internal|"
                r"169\.254\.170\.2|localhost|127\.0\.0\.1|0\.0\.0\.0|"
                r"file://|dict://|gopher://|ftp://", re.I),
     "body", "T1649", "Steal Application Access Token (SSRF)", "Credential Access", 0.88),

    # Log4Shell
    (re.compile(r"\$\{jndi:", re.I),
     "body", "T1190", "Exploit Public-Facing Application: Log4Shell", "Initial Access", 0.99),
    (re.compile(r"\$\{jndi:", re.I),
     "ua",   "T1190", "Exploit Public-Facing Application: Log4Shell", "Initial Access", 0.99),

    # WordPress / CMS probing
    (re.compile(r"wp-(admin|login|content|includes|json|cron|config)|"
                r"xmlrpc\.php|wp\.php", re.I),
     "path", "T1190", "Exploit Public-Facing Application: CMS Probe", "Reconnaissance", 0.80),

    # Spring Boot actuator
    (re.compile(r"actuator(/|$)|/env|/heapdump|/jolokia|/mappings|/beans|/trace", re.I),
     "path", "T1083", "File and Directory Discovery: Spring Actuator", "Discovery", 0.85),

    # PHP / eval injection
    (re.compile(r"eval\(|base64_decode\(|system\(|passthru\(|shell_exec\(|"
                r"phpinfo\(\)|assert\(|preg_replace.*\/e", re.I),
     "body", "T1059.004", "Command and Scripting Interpreter: PHP", "Execution", 0.92),

    # XSS
    (re.compile(r"<script|javascript:|onerror=|onload=|alert\(|document\.cookie", re.I),
     "body", "T1059.007", "Command and Scripting Interpreter: XSS", "Execution", 0.80),

    # Directory brute-force (many 404s from same path structure)
    (re.compile(r"\.(php|asp|aspx|jsp|cgi|pl|py|rb|sh|cfm)(\?|$)", re.I),
     "path", "T1595.003", "Active Scanning: Wordlist Scanning", "Reconnaissance", 0.75),
]


def _detect_mitre(method: str, path: str, ua: str, body: str) -> list[dict]:
    full_url = f"{method} /{path}"
    hits: list[dict] = []
    seen: set[str] = set()

    for pattern, target, tid, name, tactic, conf in _MITRE_RULES:
        subject = {"ua": ua, "path": path, "body": body, "url": full_url}.get(target, "")
        if pattern.search(subject) and tid not in seen:
            seen.add(tid)
            evidence_src = subject[:200] if subject else full_url[:200]
            hits.append({
                "technique_id":   tid,
                "technique_name": name,
                "tactic":         tactic,
                "confidence":     conf,
                "evidence":       evidence_src,
            })
    return hits


# ---------------------------------------------------------------------------
# IOC extraction from HTTP requests
# ---------------------------------------------------------------------------

_IP_RE     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_URL_RE    = re.compile(r'https?://[^\s\'"<>]+', re.I)
_DOMAIN_RE = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.I)
_HASH_RE   = re.compile(r'\b([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\b', re.I)


def _extract_iocs(text: str) -> list[dict]:
    iocs: list[dict] = []
    seen: set = set()

    for m in _URL_RE.finditer(text):
        v = m.group()
        if v not in seen:
            seen.add(v)
            iocs.append({"ioc_type": "url", "value": v, "confidence": 0.85})

    for m in _IP_RE.finditer(text):
        v = m.group()
        parts = v.split(".")
        if all(0 <= int(p) <= 255 for p in parts) and v not in seen:
            seen.add(v)
            iocs.append({"ioc_type": "ip", "value": v, "confidence": 0.75})

    for m in _HASH_RE.finditer(text):
        v = m.group().lower()
        if v not in seen:
            seen.add(v)
            t = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(v), "hash")
            iocs.append({"ioc_type": t, "value": v, "confidence": 0.80})

    return iocs[:20]  # cap


# ---------------------------------------------------------------------------
# Logging pipeline
# ---------------------------------------------------------------------------

async def _log_request(session_id: str, is_new: bool, method: str, path: str,
                        ip: str, ua: str, body: str, headers: dict):
    try:
        if is_new:
            await http_client.post(f"{SANDBOX_URL}/sessions/", json={
                "session_id": session_id,
                "source_ip":  ip,
                "protocol":   "http",
                "username":   ua[:80] if ua else "",  # store UA as username for display
            })

        cmd_text = f'{method} /{path}'
        if body:
            cmd_text += f' | body: {body[:300]}'

        await http_client.post(f"{SANDBOX_URL}/commands/{session_id}", json={
            "command":     cmd_text,
            "output":      "",
            "exit_code":   0,
            "duration_ms": 0,
        })

        # MITRE techniques
        techniques = _detect_mitre(method, path, ua, body)
        for t in techniques:
            try:
                await http_client.post(f"{SANDBOX_URL}/attack-techniques/{session_id}", json=t)
            except Exception:
                pass

        # IOCs from body + UA
        iocs = _extract_iocs(body + " " + ua)
        for ioc in iocs:
            try:
                await http_client.post(f"{SANDBOX_URL}/iocs/{session_id}", json=ioc)
            except Exception:
                pass

    except Exception as e:
        print(f"[http-honeypot] log error: {e}")


# ---------------------------------------------------------------------------
# Deception response library
# ---------------------------------------------------------------------------

_LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NexoPay — Employee Portal</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Segoe UI',Arial,sans-serif;background:#0f172a;min-height:100vh;
         display:flex;align-items:center;justify-content:center}
    .card{background:#1e293b;border-radius:12px;padding:40px;width:380px;
          box-shadow:0 20px 60px rgba(0,0,0,.5)}
    .logo{color:#38bdf8;font-size:22px;font-weight:700;margin-bottom:4px}
    .sub{color:#64748b;font-size:13px;margin-bottom:32px}
    label{display:block;color:#94a3b8;font-size:12px;margin-bottom:6px;margin-top:18px}
    input{width:100%;padding:10px 14px;background:#0f172a;border:1px solid #334155;
          border-radius:6px;color:#e2e8f0;font-size:14px;outline:none}
    input:focus{border-color:#38bdf8}
    button{width:100%;margin-top:24px;padding:12px;background:#0284c7;border:none;
           border-radius:6px;color:#fff;font-size:15px;font-weight:600;cursor:pointer}
    button:hover{background:#0369a1}
    .footer{color:#334155;font-size:11px;text-align:center;margin-top:24px}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">NexoPay</div>
    <div class="sub">Internal Employee Portal · IT-managed access only</div>
    <form method="POST" action="/login">
      <label>Email address</label>
      <input type="email" name="email" placeholder="you@nexopay.com" autocomplete="email" />
      <label>Password</label>
      <input type="password" name="password" placeholder="••••••••" autocomplete="current-password" />
      <button type="submit">Sign in</button>
    </form>
    <div class="footer">v2.14.3 · &copy; 2024 NexoPay Inc. · IT Support: it-help@nexopay.internal</div>
  </div>
</body>
</html>"""

_FAKE_ENV = """\
APP_ENV=production
APP_KEY=base64:kX3mN8vQpR2sT7uW1yZ4aB6cD9eF0gH5iJ2lK8mN3oP6qR1sT4uVwX7yZ0aB3cD
APP_DEBUG=false
APP_URL=https://api.nexopay.com

DB_CONNECTION=pgsql
DB_HOST=db-primary.nexopay.internal
DB_PORT=5432
DB_DATABASE=nexopay_prod
DB_USERNAME=nexopay_app
DB_PASSWORD=Nx$Pr0d!2024#SecureDB

REDIS_HOST=cache-01.nexopay.internal
REDIS_PASSWORD=rX9!kP3mQ7nR2sT5
REDIS_PORT=6379

STRIPE_KEY=sk_live_REDACTED_nexopay_prod_2024_xK9mP3nQ7
STRIPE_WEBHOOK_SECRET=whsec_nexopay_internal_wh_2024_rT5uV8wX

AWS_ACCESS_KEY_ID=AKIA_NEXOPAY_PROD_KEY_2024
AWS_SECRET_ACCESS_KEY=NxP/K7MDENGbPxRfiCY_nexopay_aws_prod_secret
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=nexopay-prod-backups

JWT_SECRET=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.nexopay.prod.2024  # nosemgrep
JWT_TTL=3600

MAIL_DRIVER=smtp
MAIL_HOST=email-smtp.us-east-1.amazonaws.com
MAIL_USERNAME=AKIAIOSFODNN7SMTPKEY  # nosemgrep
MAIL_PASSWORD=BG+kP3mQ7nR2sT5wJalrXUtnSMTP
MAIL_FROM_ADDRESS=noreply@nexopay.com
"""

_PHPINFO = """<!DOCTYPE html>
<html><head><title>phpinfo()</title>
<style>body{font-family:sans-serif}table{border-collapse:collapse;width:100%}
td,th{border:1px solid #ccc;padding:4px 8px}h1{background:#9999cc;color:#fff;padding:8px}
tr:nth-child(even){background:#f0f0f0}</style></head>
<body>
<h1>PHP Version 8.1.12</h1>
<table>
<tr><td>System</td><td>Linux api-prod-01 5.15.0-91-generic #101-Ubuntu SMP x86_64</td></tr>
<tr><td>Build Date</td><td>Oct 28 2022 18:24:32</td></tr>
<tr><td>Server API</td><td>FPM/FastCGI</td></tr>
<tr><td>Virtual Directory Support</td><td>disabled</td></tr>
<tr><td>Configuration File (php.ini) Path</td><td>/etc/php/8.1/fpm</td></tr>
<tr><td>Loaded Configuration File</td><td>/etc/php/8.1/fpm/php.ini</td></tr>
<tr><td>PHP API</td><td>20210902</td></tr>
<tr><td>PHP Extension</td><td>20210902</td></tr>
</table>
</body></html>"""

_ACTUATOR = {
    "status": "UP",
    "components": {
        "db":         {"status": "UP", "details": {"database": "PostgreSQL", "validationQuery": "isValid()"}},
        "redis":      {"status": "UP", "details": {"version": "7.0.15"}},
        "diskSpace":  {"status": "UP", "details": {"total": 107374182400, "free": 91268046848, "threshold": 10485760}},
        "ping":       {"status": "UP"},
    },
    "info": {
        "app":     {"name": "nexopay-api", "version": "2.14.3", "encoding": "UTF-8"},
        "java":    {"version": "17.0.9", "vendor": {"name": "Eclipse Adoptium"}},
        "git":     {"commit": {"id": "a3f9c12", "time": "2024-11-14T09:22:14Z"}},
    },
}

_WP_LOGIN = """<!DOCTYPE html>
<html><head><title>Log In &lsaquo; NexoPay &#8212; WordPress</title>
<style>body{background:#f0f0f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}
#login{width:320px;margin:100px auto}h1 a{display:block;background:#21759b;height:80px;
line-height:80px;text-align:center;color:#fff;text-decoration:none;font-size:20px;border-radius:4px}
.login-box{background:#fff;padding:26px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.13)}
input[type=text],input[type=password]{width:100%;padding:8px;border:1px solid #dcdcde;
border-radius:4px;box-sizing:border-box;margin:6px 0 16px}
input[type=submit]{background:#2271b1;color:#fff;border:none;padding:10px;width:100%;
border-radius:4px;cursor:pointer;font-size:14px}</style></head>
<body><div id="login"><h1><a>NexoPay</a></h1>
<div class="login-box">
<form method="post" action="/wp-login.php">
<label>Username or Email Address<br>
<input type="text" name="log" size="20" autocomplete="username"/></label>
<label>Password<br>
<input type="password" name="pwd" size="20" autocomplete="current-password"/></label>
<input type="submit" name="wp-submit" value="Log In"/>
</form></div></div></body></html>"""


def _make_response(path: str, method: str, body: str) -> Response:
    """Return the most deceptive-yet-realistic response for a given path."""
    p = path.lower().lstrip("/")

    # Root / login
    if p in ("", "login", "index.html", "index.php"):
        return HTMLResponse(_LOGIN_PAGE, 200)

    if p in ("login", "login/") and method == "POST":
        return HTMLResponse(
            "<script>window.location='/dashboard'</script>", 302,
            headers={"Location": "/dashboard", "Set-Cookie": "session=deleted; expires=Thu, 01 Jan 1970 00:00:00 GMT"}
        )

    # .env — return a fake-but-juicy env file
    if p in (".env", ".env.local", ".env.production", ".env.backup", "config/.env"):
        return PlainTextResponse(_FAKE_ENV, 200)

    # phpinfo
    if p in ("phpinfo.php", "info.php", "test.php", "php.php"):
        return HTMLResponse(_PHPINFO, 200)

    # WordPress
    if "wp-login" in p or "wp-admin" in p:
        return HTMLResponse(_WP_LOGIN, 200)

    # Spring Boot actuator
    if "actuator" in p:
        if "health" in p:
            return JSONResponse({"status": "UP"}, 200)
        return JSONResponse(_ACTUATOR, 200)

    # /api routes — generic JSON
    if p.startswith("api/"):
        if "user" in p or "account" in p or "profile" in p:
            return JSONResponse({
                "error": "Unauthorized",
                "message": "Authentication required",
                "code": 401,
                "path": f"/{path}",
            }, 401)
        if "health" in p or "status" in p or "ping" in p:
            return JSONResponse({"status": "online", "version": "2.14.3", "env": "production"}, 200)
        return JSONResponse({"error": "Not Found", "path": f"/{path}"}, 404)

    # phpMyAdmin
    if "phpmyadmin" in p or "pma" in p or "myadmin" in p:
        return HTMLResponse(
            "<html><head><title>phpMyAdmin</title></head>"
            "<body><h2>phpMyAdmin 5.2.1</h2>"
            "<p><a href='/phpmyadmin/index.php'>Access phpMyAdmin</a></p></body></html>",
            200,
        )

    # Admin panel
    if p in ("admin", "admin/", "admin/login", "administrator", "manage"):
        return HTMLResponse(
            "<html><head><title>Admin Panel</title></head>"
            "<body style='font-family:sans-serif;padding:40px'>"
            "<h2>Admin Panel — Restricted</h2>"
            "<p>This area requires multi-factor authentication.</p>"
            "<p><a href='/login'>Return to portal</a></p></body></html>",
            403,
        )

    # Git / SVN exposure
    if p.startswith(".git") or p.startswith(".svn"):
        return PlainTextResponse("ref: refs/heads/main\n", 200)

    # Backup / config files
    if any(p.endswith(ext) for ext in (".sql", ".bak", ".backup", ".dump", ".tar.gz", ".zip")):
        return Response(status_code=403)

    # robots.txt (already noise-filtered before this, but just in case)
    if p == "robots.txt":
        return PlainTextResponse("User-agent: *\nDisallow: /admin/\nDisallow: /api/internal/\n", 200)

    # Default 404 — mimics nginx
    return HTMLResponse(
        "<html><head><title>404 Not Found</title></head>"
        "<body><center><h1>404 Not Found</h1></center>"
        "<hr><center>nginx/1.18.0 (Ubuntu)</center></body></html>",
        404,
    )


# ---------------------------------------------------------------------------
# Background task: close stale HTTP sessions
# ---------------------------------------------------------------------------

async def _cleanup_loop():
    """Every SESSION_WINDOW seconds, close sessions that have gone quiet."""
    while True:
        await asyncio.sleep(SESSION_WINDOW)
        now = datetime.now(timezone.utc).timestamp()
        to_close: list[tuple[str, str]] = []

        async with _lock:
            for ip, entry in list(_sessions.items()):
                if (now - entry["last_seen"]) >= SESSION_WINDOW:
                    to_close.append((ip, entry["session_id"]))
                    del _sessions[ip]

        for ip, sid in to_close:
            try:
                await http_client.delete(f"{SANDBOX_URL}/sessions/{sid}")
            except Exception:
                pass


@app.on_event("startup")
async def _startup():
    asyncio.create_task(_cleanup_loop())


# ---------------------------------------------------------------------------
# Catch-all route
# ---------------------------------------------------------------------------

def _get_client_ip(request: Request) -> str:
    """Extract the real client IP, respecting Azure Front Door headers.

    When the app is behind Azure Front Door Standard, the connection to ACA
    comes from Front Door's edge, so request.client.host would be a Microsoft
    IP. The real attacker IP is in the first value of X-Forwarded-For.

    Front Door also sets X-Azure-ClientIP as a convenience header.
    """
    # 1) X-Forwarded-For: Front Door appends its own IP as the rightmost value
    forwarded = request.headers.get("x-forwarded-for", "").strip()
    if forwarded:
        return forwarded.split(",")[0].strip()

    # 2) Fallback: X-Azure-ClientIP (set by Front Door)
    azure_ip = request.headers.get("x-azure-clientip", "").strip()
    if azure_ip:
        return azure_ip

    # 3) Direct connection (local dev or direct ACA access)
    return request.client.host if request.client else "127.0.0.1"


def _get_frontdoor_ref(request: Request) -> dict:
    """Extract Azure Front Door tracing headers for audit logging."""
    ref = request.headers.get("x-azure-ref", "")
    fdid = request.headers.get("x-azure-fdid", "")
    proto = request.headers.get("x-forwarded-proto", "")
    host = request.headers.get("x-forwarded-host", "")
    return {
        "azure_ref": ref,
        "azure_fdid": fdid,
        "forwarded_proto": proto,
        "forwarded_host": host,
    }


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def catch_all(request: Request, path: str):
    body_bytes = await request.body()
    body = body_bytes.decode("utf-8", errors="ignore")[:2000]
    ip   = _get_client_ip(request)
    ua   = request.headers.get("user-agent", "")
    fd   = _get_frontdoor_ref(request)

    # Optionally verify the request came through our Front Door instance
    if FRONTDOOR_FDID and fd["azure_fdid"] and fd["azure_fdid"] != FRONTDOOR_FDID:
        return Response(status_code=403)

    # Always respond — then decide whether to log
    response = _make_response(path, request.method, body)

    # Add Front Door tracing to response headers (visible to attacker)
    if fd["azure_ref"]:
        response.headers["X-Azure-Ref"] = fd["azure_ref"]

    # Skip logging noise
    if _is_noise(path, ua):
        return response

    session_id = await _get_or_create_session(ip)
    if session_id is None:
        return response   # rate cap hit for this IP/session — stop logging

    is_new = _sessions.get(ip, {}).get("cmd_count", 0) <= 1
    asyncio.create_task(
        _log_request(session_id, is_new, request.method, path, ip, ua, body, dict(request.headers))
    )

    return response


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
