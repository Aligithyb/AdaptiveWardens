"""Per-IP sliding-window rate limiter for LLM calls.

In-memory only — the goal is to cap one spammy attacker from chewing through
the daily token budget in 30 seconds. Stateless across restarts is fine: at
worst they get a tiny grace window after a redeploy.
"""

import logging
import os
import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict

logger = logging.getLogger("ai-engine.ratelimit")

PER_IP_RATE_LIMIT_CALLS = int(os.getenv("LLM_PER_IP_RATE_LIMIT_CALLS", "30"))
PER_IP_RATE_LIMIT_WINDOW = float(os.getenv("LLM_PER_IP_RATE_LIMIT_WINDOW", "60"))
RATE_LIMIT_MAX_TRACKED_IPS = int(os.getenv("LLM_RATE_LIMIT_MAX_IPS", "10000"))


class PerIPRateLimiter:
    def __init__(self):
        self._lock = threading.Lock()
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._blocked_count = 0
        self._allowed_count = 0

    def allow(self, ip: str) -> bool:
        if not ip:
            return True
        now = time.monotonic()
        cutoff = now - PER_IP_RATE_LIMIT_WINDOW
        with self._lock:
            if len(self._hits) > RATE_LIMIT_MAX_TRACKED_IPS:
                self._evict_stale(cutoff)

            dq = self._hits[ip]
            while dq and dq[0] < cutoff:
                dq.popleft()
            if len(dq) >= PER_IP_RATE_LIMIT_CALLS:
                self._blocked_count += 1
                return False
            dq.append(now)
            self._allowed_count += 1
            return True

    def _evict_stale(self, cutoff: float):
        stale = [ip for ip, dq in self._hits.items() if not dq or dq[-1] < cutoff]
        for ip in stale:
            del self._hits[ip]

    def stats(self) -> dict:
        with self._lock:
            return {
                "tracked_ips": len(self._hits),
                "allowed": self._allowed_count,
                "blocked": self._blocked_count,
                "calls_per_window": PER_IP_RATE_LIMIT_CALLS,
                "window_seconds": PER_IP_RATE_LIMIT_WINDOW,
            }
