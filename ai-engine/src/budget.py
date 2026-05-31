"""Daily LLM token budget circuit breaker.

Persists per-UTC-day input/output token counts in SQLite so a container restart
doesn't reset the day's spend. When either ceiling is hit, can_call() returns
False and the caller is expected to fall back to deterministic / static output
for the remainder of the UTC day. Counters roll over automatically at 00:00 UTC.

Why persist: the whole point is to survive bursts that would otherwise blow
through a tiny prepaid balance ($2 of DeepSeek credit). An in-memory counter
loses state on every redeploy.
"""

import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone

logger = logging.getLogger("ai-engine.budget")

BUDGET_DB_PATH = os.getenv("LLM_BUDGET_DB", "/data/llm_budget.db")
DAILY_INPUT_TOKEN_BUDGET = int(os.getenv("LLM_DAILY_INPUT_TOKEN_BUDGET", "50000"))
DAILY_OUTPUT_TOKEN_BUDGET = int(os.getenv("LLM_DAILY_OUTPUT_TOKEN_BUDGET", "20000"))


def _today_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class BudgetTracker:
    def __init__(self):
        self._lock = threading.Lock()
        self._db = None
        self._mem_day = None
        self._mem_input = 0
        self._mem_output = 0
        self._mem_calls = 0
        self._mem_blocked = 0
        self._init_db()

    def _init_db(self):
        try:
            os.makedirs(os.path.dirname(BUDGET_DB_PATH), exist_ok=True)
        except OSError:
            pass
        try:
            self._db = sqlite3.connect(BUDGET_DB_PATH, check_same_thread=False)
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("""
                CREATE TABLE IF NOT EXISTS llm_daily_usage (
                    day TEXT PRIMARY KEY,
                    input_tokens INTEGER NOT NULL DEFAULT 0,
                    output_tokens INTEGER NOT NULL DEFAULT 0,
                    calls INTEGER NOT NULL DEFAULT 0,
                    blocked INTEGER NOT NULL DEFAULT 0
                )
            """)
            self._db.commit()
        except Exception as e:
            logger.warning(f"budget DB init failed ({e}); using memory-only counters")
            self._db = None

    def _row_for_today(self):
        day = _today_utc()
        if self._db is None:
            if self._mem_day != day:
                self._mem_day = day
                self._mem_input = self._mem_output = self._mem_calls = self._mem_blocked = 0
            return day, self._mem_input, self._mem_output, self._mem_calls, self._mem_blocked
        row = self._db.execute(
            "SELECT input_tokens, output_tokens, calls, blocked FROM llm_daily_usage WHERE day = ?",
            (day,),
        ).fetchone()
        if row is None:
            self._db.execute(
                "INSERT INTO llm_daily_usage (day, input_tokens, output_tokens, calls, blocked) VALUES (?, 0, 0, 0, 0)",
                (day,),
            )
            self._db.commit()
            return day, 0, 0, 0, 0
        return day, row[0], row[1], row[2], row[3]

    def can_call(self) -> bool:
        with self._lock:
            _, inp, outp, _, _ = self._row_for_today()
            if inp >= DAILY_INPUT_TOKEN_BUDGET:
                return False
            if outp >= DAILY_OUTPUT_TOKEN_BUDGET:
                return False
            return True

    def record(self, input_tokens: int, output_tokens: int):
        if input_tokens <= 0 and output_tokens <= 0:
            return
        with self._lock:
            day, _, _, _, _ = self._row_for_today()
            if self._db is None:
                self._mem_input += input_tokens
                self._mem_output += output_tokens
                self._mem_calls += 1
                return
            self._db.execute(
                "UPDATE llm_daily_usage SET input_tokens = input_tokens + ?, "
                "output_tokens = output_tokens + ?, calls = calls + 1 WHERE day = ?",
                (input_tokens, output_tokens, day),
            )
            self._db.commit()

    def record_blocked(self):
        with self._lock:
            day, _, _, _, _ = self._row_for_today()
            if self._db is None:
                self._mem_blocked += 1
                return
            self._db.execute(
                "UPDATE llm_daily_usage SET blocked = blocked + 1 WHERE day = ?",
                (day,),
            )
            self._db.commit()

    def stats(self) -> dict:
        with self._lock:
            day, inp, outp, calls, blocked = self._row_for_today()
            return {
                "day_utc": day,
                "input_tokens": inp,
                "output_tokens": outp,
                "calls": calls,
                "blocked": blocked,
                "input_budget": DAILY_INPUT_TOKEN_BUDGET,
                "output_budget": DAILY_OUTPUT_TOKEN_BUDGET,
                "input_remaining": max(0, DAILY_INPUT_TOKEN_BUDGET - inp),
                "output_remaining": max(0, DAILY_OUTPUT_TOKEN_BUDGET - outp),
                "exhausted": inp >= DAILY_INPUT_TOKEN_BUDGET or outp >= DAILY_OUTPUT_TOKEN_BUDGET,
            }
