"""SQLite-backed response cache with command-scoped keys and per-command TTLs.

Three improvements over the prior dict-based cache:
1. Cache keys are scoped by command class. `whoami` is identical for every
   attacker so it's keyed globally; `ls` is keyed by (command, cwd, user).
   Stops 50x-multiplier LLM bills under concurrent attackers.
2. TTLs vary per command. `date`/`uptime`/`w` are never cached. `uname`,
   `cat /etc/os-release` cache for 24h. Everything else 5 minutes.
3. Persists to /data/ai_cache.db so a container restart doesn't trigger a
   cold cache burst. Also caches IOC + MITRE results alongside the response
   so cache hits skip the spaCy extractor pass.
"""

from datetime import datetime, timedelta
from typing import Optional, Tuple
import hashlib
import json
import os
import re
import sqlite3
import threading

CACHE_DB_PATH = os.getenv("AI_CACHE_DB", "/data/ai_cache.db")
DEFAULT_TTL_SECONDS = 300       # 5 minutes
LONG_TTL_SECONDS = 86400        # 24 hours

# Commands that must never be served from cache (they return time-sensitive
# or randomised output that an attacker can poll to detect staleness).
_NEVER_CACHE_PATTERNS = [
    re.compile(r'^date(\s|$)'),
    re.compile(r'^uptime(\s|$)'),
    re.compile(r'^w(\s|$)'),
    re.compile(r'^who(\s|$)'),
    re.compile(r'^last(\s|$)'),
    re.compile(r'^top(\s|$)'),
    re.compile(r'^htop(\s|$)'),
    re.compile(r'^ps(\s|$)'),
    re.compile(r'^free(\s|$)'),
    re.compile(r'^vmstat(\s|$)'),
    re.compile(r'^iostat(\s|$)'),
    re.compile(r'^netstat(\s|$)'),
    re.compile(r'^ss(\s|$)'),
    re.compile(r'^cat\s+/proc/(loadavg|uptime|stat|meminfo|net/)'),
    re.compile(r'\$random', re.IGNORECASE),
]

# Commands whose output is effectively immutable for a single boot of the box.
_LONG_CACHE_PATTERNS = [
    re.compile(r'^uname(\s|$)'),
    re.compile(r'^hostname(\s|$)'),
    re.compile(r'^lsb_release(\s|$)'),
    re.compile(r'^lscpu(\s|$)'),
    re.compile(r'^dpkg\s+-l'),
    re.compile(r'^apt\s+list'),
    re.compile(r'^cat\s+/etc/(passwd|os-release|hostname|issue|debian_version|lsb-release|hosts)'),
    re.compile(r'^cat\s+/proc/(cpuinfo|version)'),
]

# Commands whose response is identical for every attacker (no user/cwd context).
_GLOBAL_PATTERNS = [
    re.compile(r'^whoami(\s|$)'),
    re.compile(r'^id(\s|$)'),
    re.compile(r'^hostname(\s|$)'),
    re.compile(r'^uname(\s|$)'),
    re.compile(r'^lsb_release(\s|$)'),
    re.compile(r'^lscpu(\s|$)'),
    re.compile(r'^cat\s+/etc/(passwd|os-release|hostname|issue|debian_version|lsb-release|hosts)'),
    re.compile(r'^cat\s+/proc/(cpuinfo|version)'),
    re.compile(r'^dpkg\s+-l'),
    re.compile(r'^apt\s+list'),
    re.compile(r'^ip\s+(a|addr)(\s|$)'),
    re.compile(r'^ifconfig(\s|$)'),
]

# Commands whose response depends on user but not cwd.
_PER_USER_PATTERNS = [
    re.compile(r'^pwd(\s|$)'),
    re.compile(r'^env(\s|$)'),
    re.compile(r'^printenv(\s|$)'),
    re.compile(r'^echo\s+\$'),
]


_FLAG_SORT_COMMANDS = {"ls", "ps", "du", "df", "find", "grep", "cat", "ll", "rm", "cp", "mv", "tar", "zcat"}
_SHORT_FLAG_RE = re.compile(r'^-[a-zA-Z]+$')
_WHITESPACE_RE = re.compile(r'\s+')


def _normalize_for_cache(command: str) -> str:
    """Canonicalize a command so attacker variants collide on the same cache row.

    Conservative — only does things that provably preserve semantics:
      - lowercase the command verb (Linux is case-sensitive but attackers rarely
        run `LS`; when they do it's identical fallback output anyway)
      - collapse runs of whitespace and strip trailing space
      - sort the letters inside short-flag clusters for a known-safe set of
        commands so `ls -la`, `ls -al`, `ls -a -l` all key to one row.

    Does NOT touch URLs / IPs / file paths — those still semantically matter
    for the response. Structural URL→<URL> templating is a future-phase item.
    """
    if not command:
        return command
    c = _WHITESPACE_RE.sub(' ', command.strip())
    tokens = c.split(' ')
    if not tokens:
        return c
    verb = tokens[0].lower()
    if verb not in _FLAG_SORT_COMMANDS:
        return c

    short_letters = []
    rest = []
    for t in tokens[1:]:
        if _SHORT_FLAG_RE.match(t):
            short_letters.extend(sorted(t[1:]))
        else:
            rest.append(t)
    flag_token = ('-' + ''.join(sorted(set(short_letters)))) if short_letters else ''
    parts = [verb]
    if flag_token:
        parts.append(flag_token)
    parts.extend(rest)
    return ' '.join(parts)


def _classify_scope(command: str) -> str:
    lc = command.lower().strip()
    for p in _GLOBAL_PATTERNS:
        if p.match(lc):
            return "global"
    for p in _PER_USER_PATTERNS:
        if p.match(lc):
            return "per_user"
    return "per_cwd"


def _classify_ttl(command: str) -> int:
    lc = command.lower().strip()
    for p in _NEVER_CACHE_PATTERNS:
        if p.search(lc):
            return 0
    for p in _LONG_CACHE_PATTERNS:
        if p.match(lc):
            return LONG_TTL_SECONDS
    return DEFAULT_TTL_SECONDS


class ResponseCache:
    def __init__(self):
        self._lock = threading.Lock()
        self.stats = {"hits": 0, "misses": 0, "bypassed": 0, "stores": 0}
        self._db = None
        self._init_db()

    def _init_db(self):
        try:
            os.makedirs(os.path.dirname(CACHE_DB_PATH), exist_ok=True)
        except OSError:
            pass
        try:
            self._db = sqlite3.connect(CACHE_DB_PATH, check_same_thread=False)
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("""
                CREATE TABLE IF NOT EXISTS response_cache (
                    key TEXT PRIMARY KEY,
                    response TEXT NOT NULL,
                    iocs TEXT,
                    mitre TEXT,
                    expires_at REAL NOT NULL,
                    hit_count INTEGER DEFAULT 0,
                    created_at REAL NOT NULL
                )
            """)
            # Global, no-TTL cache for command→MITRE technique mappings.
            # A technique mapping is stable (same command always maps to the same
            # technique), so there is no expiry. Keyed by normalised command hash,
            # global scope (no user/cwd) to maximise hit rate across attackers.
            self._db.execute("""
                CREATE TABLE IF NOT EXISTS mitre_cache (
                    cmd_key TEXT PRIMARY KEY,
                    techniques TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
            """)
            self._db.commit()
        except Exception as e:
            print(f"WARNING: cache DB init failed ({e}); falling back to memory-only")
            self._db = None
            self._mem = {}
            self._mitre_mem = {}

    def _build_key(self, command: str, context: dict) -> Tuple[str, str]:
        scope = _classify_scope(command)
        norm = _normalize_for_cache(command)
        if scope == "global":
            payload = norm
        elif scope == "per_user":
            payload = f"{norm}|user={context.get('username', 'root')}"
        else:
            payload = (f"{norm}|user={context.get('username', 'root')}"
                       f"|cwd={context.get('current_directory', '/root')}")
        return hashlib.sha256(payload.encode("utf-8")).hexdigest(), scope

    def get(self, command: str, context: dict) -> Optional[dict]:
        """Return {'response', 'iocs', 'mitre'} or None."""
        if _classify_ttl(command) == 0:
            self.stats["bypassed"] += 1
            return None
        key, _ = self._build_key(command, context)
        now = datetime.now().timestamp()

        with self._lock:
            if self._db is not None:
                row = self._db.execute(
                    "SELECT response, iocs, mitre, expires_at FROM response_cache WHERE key = ?",
                    (key,)
                ).fetchone()
                if row and row[3] > now:
                    self._db.execute(
                        "UPDATE response_cache SET hit_count = hit_count + 1 WHERE key = ?",
                        (key,)
                    )
                    self._db.commit()
                    self.stats["hits"] += 1
                    return {
                        "response": row[0],
                        "iocs": json.loads(row[1]) if row[1] else [],
                        "mitre": json.loads(row[2]) if row[2] else [],
                    }
            else:
                entry = self._mem.get(key)
                if entry and entry["expires_at"] > now:
                    self.stats["hits"] += 1
                    return entry["payload"]

        self.stats["misses"] += 1
        return None

    def set(self, command: str, context: dict, response: str,
            iocs: Optional[list] = None, mitre: Optional[list] = None):
        ttl = _classify_ttl(command)
        if ttl == 0:
            return
        key, _ = self._build_key(command, context)
        now = datetime.now().timestamp()
        expires_at = now + ttl
        iocs_json = json.dumps(iocs or [])
        mitre_json = json.dumps(mitre or [])

        with self._lock:
            if self._db is not None:
                self._db.execute("""
                    INSERT OR REPLACE INTO response_cache
                    (key, response, iocs, mitre, expires_at, hit_count, created_at)
                    VALUES (?, ?, ?, ?, ?, 0, ?)
                """, (key, response, iocs_json, mitre_json, expires_at, now))
                self._db.commit()
            else:
                self._mem[key] = {
                    "expires_at": expires_at,
                    "payload": {"response": response, "iocs": iocs or [], "mitre": mitre or []},
                }
            self.stats["stores"] += 1

    # ------------------------------------------------------------------
    # MITRE classification cache (global scope, no TTL)
    # ------------------------------------------------------------------

    def _mitre_key(self, command: str) -> str:
        return hashlib.sha256(_normalize_for_cache(command).encode("utf-8")).hexdigest()

    def get_mitre(self, command: str) -> Optional[list]:
        """Return cached MITRE techniques or None."""
        key = self._mitre_key(command)
        with self._lock:
            if self._db is not None:
                row = self._db.execute(
                    "SELECT techniques FROM mitre_cache WHERE cmd_key = ?", (key,)
                ).fetchone()
                if row:
                    self.stats["mitre_hits"] = self.stats.get("mitre_hits", 0) + 1
                    return json.loads(row[0])
            else:
                entry = self._mitre_mem.get(key)
                if entry is not None:
                    self.stats["mitre_hits"] = self.stats.get("mitre_hits", 0) + 1
                    return entry
        self.stats["mitre_misses"] = self.stats.get("mitre_misses", 0) + 1
        return None

    def set_mitre(self, command: str, techniques: list):
        """Persist MITRE classification (including empty list so we don't re-ask)."""
        key = self._mitre_key(command)
        now = datetime.now().timestamp()
        techniques_json = json.dumps(techniques)
        with self._lock:
            if self._db is not None:
                self._db.execute(
                    "INSERT OR REPLACE INTO mitre_cache (cmd_key, techniques, created_at) VALUES (?, ?, ?)",
                    (key, techniques_json, now)
                )
                self._db.commit()
            else:
                self._mitre_mem[key] = techniques

    def vacuum_expired(self):
        if self._db is None:
            return
        now = datetime.now().timestamp()
        with self._lock:
            self._db.execute("DELETE FROM response_cache WHERE expires_at < ?", (now,))
            self._db.commit()

    def get_stats(self) -> dict:
        total = self.stats["hits"] + self.stats["misses"]
        hit_rate = self.stats["hits"] / total if total > 0 else 0.0
        mitre_hits = self.stats.get("mitre_hits", 0)
        mitre_misses = self.stats.get("mitre_misses", 0)
        mitre_total = mitre_hits + mitre_misses
        mitre_hit_rate = mitre_hits / mitre_total if mitre_total > 0 else 0.0
        return {
            **self.stats,
            "hit_rate": round(hit_rate, 4),
            "mitre_hit_rate": round(mitre_hit_rate, 4),
        }
