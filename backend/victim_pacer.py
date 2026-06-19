"""
victim_pacer.py — global rate limiter for calls to the victim agent.

On a free-tier Groq key the victim can only serve ~1-2 messages/minute before
hitting the tokens-per-minute cap. Bursting past that triggers 429s. This pacer
enforces a minimum interval between victim requests ACROSS all threads, so
discovery probes and PAIR attempts don't pile up and trip the limit.

Set VICTIM_MIN_INTERVAL_SEC in the backend .env:
  * free tier  → 15-30 (higher = fewer 429s, slower)
  * paid/Dev   → 0 (disabled)
"""
from __future__ import annotations

import os
import time
import threading

_lock = threading.Lock()
_last_ts = [0.0]


def _interval() -> float:
    # Read at call time so it's correct regardless of dotenv import order.
    try:
        return float(os.getenv("VICTIM_MIN_INTERVAL_SEC", "0"))
    except (TypeError, ValueError):
        return 0.0


def pace() -> None:
    """Block until at least VICTIM_MIN_INTERVAL_SEC seconds have passed since the
    previous victim call. No-op when the interval is 0 (paid tier)."""
    interval = _interval()
    if interval <= 0:
        return
    with _lock:
        now = time.monotonic()
        wait = _last_ts[0] + interval - now
        if wait > 0:
            time.sleep(wait)
            now = time.monotonic()
        _last_ts[0] = now
