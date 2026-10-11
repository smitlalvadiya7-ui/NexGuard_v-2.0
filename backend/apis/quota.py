"""
Client-side quota limiter — spend a source's allowance instead of burning it.

The problem, measured 2026-07-30. VirusTotal's free tier allows 4 requests per
minute. A 200-URL batch runs 8 concurrent scans, so it fired roughly 240 VT
requests in the first minute. VirusTotal answered 4 and returned HTTP 429 to the
rest; after 5 of those the circuit breaker opened and **every remaining scan got
no VirusTotal at all**. 169 of 200 known-malicious domains came back unchecked.

The requests were not too many — they were too fast. The same 200 URLs fit
inside the free tier comfortably if they WAIT for their turn.

So a token bucket sits in front of each rate-limited source. A caller that
arrives with no token waits briefly for one; if none comes inside the wait
budget, the adapter does NOT send the request (it would only earn a 429 and
trip the breaker) and reports the source "rate-limited" instead.

    return paced("virustotal", _call, fallback=...)

`paced` also asks the circuit breaker first, so an OPEN breaker answers
instantly instead of waiting for a token it would then throw away.

Honest about the cost: at 4 requests/minute a free VirusTotal key checks about
4 URLs a minute; in a 200-URL batch most rows say "rate-limited" for VirusTotal.
That is the free tier's arithmetic. Google Safe Browsing / Web Risk allow far
higher volumes and are what actually covers bulk scanning — this limiter
protects that allowance too.

Configured per source, overridable by env var so a paid tier can raise it:

    NEXGUARD_QUOTA_VIRUSTOTAL_PER_MIN=1000     # premium key
    NEXGUARD_QUOTA_VIRUSTOTAL_WAIT=0           # disable waiting entirely
"""

from __future__ import annotations

import contextlib
import logging
import os
import threading
import time

log = logging.getLogger("nexguard.quota")

# requests per minute, and how long a caller may wait for a token.
#
# Every wait must be SHORTER than the time full_scan gives the source
# (aggregator.CRIT_BUDGET_S, 2.2 s; enrichment sources get 6 s). The wait
# happens inside a worker thread, and a thread still waiting after full_scan
# has moved on is waiting for nobody — it only blocks the pool. Measured
# 2026-09-29: with VirusTotal at 45 s, eight concurrent batch scans filled the
# 20-thread default pool with sleepers, Safe Browsing and the local ML queued
# behind them, and 89 of 200 URLs came back UNKNOWN 0%. With the wait inside
# the budget: 0.
#
# So a free-tier VirusTotal answers about 4 URLs a minute in a batch and is
# honestly reported "rate-limited" for the rest; Google's corpus (Safe
# Browsing / Web Risk, far higher limits) carries the batch. A paid VT tier
# raises per_min via the env vars above.
_DEFAULTS = {
    "virustotal": {"per_min": 4, "max_wait_s": 0.5},
    # Web Risk is far more generous (100k/month); this only smooths bursts.
    "web_risk": {"per_min": 240, "max_wait_s": 1.0},
    # Safe Browsing's quota is per-day rather than per-minute, but bursts from a
    # batch still earn 429s.
    "safe_browsing": {"per_min": 120, "max_wait_s": 1.0},
    # urlscan is enrichment (6 s budget), so it may wait a little longer.
    "urlscan": {"per_min": 30, "max_wait_s": 2.0},
    "urlhaus": {"per_min": 60, "max_wait_s": 1.0},
}


def _envf(name: str, default: float) -> float:
    try:
        raw = os.getenv(name, "").strip()
        return float(raw) if raw else default
    except ValueError:
        return default


class _Bucket:
    """A token bucket. Full at start, so the first burst is not penalised."""

    def __init__(self, per_min: float, max_wait_s: float):
        self.capacity = max(1.0, per_min)
        self.per_sec = per_min / 60.0
        self.max_wait_s = max_wait_s
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self.lock = threading.Lock()
        self.waited_total = 0.0
        self.gave_up = 0

    def _refill(self) -> None:
        now = time.monotonic()
        self.tokens = min(self.capacity,
                          self.tokens + (now - self.updated) * self.per_sec)
        self.updated = now

    def acquire(self) -> bool:
        """
        Take a token, waiting if needed. False when the wait budget ran out —
        the caller should then skip the request (see `paced`) rather than
        spend it on a near-certain 429.
        """
        deadline = time.monotonic() + self.max_wait_s
        slept = 0.0
        while True:
            with self.lock:
                self._refill()
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    self.waited_total += slept
                    return True
                needed = (1.0 - self.tokens) / self.per_sec if self.per_sec else 1e9
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                with self.lock:
                    self.gave_up += 1
                return False
            nap = min(needed, remaining, 1.0)
            time.sleep(max(nap, 0.01))
            slept += nap


_BUCKETS: dict[str, _Bucket] = {}
_REG_LOCK = threading.Lock()


def _bucket(source: str) -> _Bucket | None:
    cfg = _DEFAULTS.get(source)
    if cfg is None:
        return None
    key = source.upper()
    per_min = _envf(f"NEXGUARD_QUOTA_{key}_PER_MIN", cfg["per_min"])
    max_wait = _envf(f"NEXGUARD_QUOTA_{key}_WAIT", cfg["max_wait_s"])
    if per_min <= 0 or max_wait <= 0:
        return None                      # explicitly disabled
    with _REG_LOCK:
        b = _BUCKETS.get(source)
        if b is None or b.capacity != max(1.0, per_min) or b.max_wait_s != max_wait:
            b = _Bucket(per_min, max_wait)
            _BUCKETS[source] = b
        return b


@contextlib.contextmanager
def quota(source: str):
    """
    Hold a token for `source` while the request runs.

    Never raises and never blocks forever. An unknown source is unlimited, so
    adding a new adapter cannot accidentally deadlock it.
    """
    b = _bucket(source)
    if b is None:
        yield True
        return
    got = b.acquire()
    if not got:
        log.debug("quota wait expired for %s — no token", source)
    try:
        yield got
    finally:
        pass


def paced(source: str, fn, fallback: dict):
    """
    Breaker first, then a token, then the request — the order matters.

      * breaker OPEN       -> fallback at once (no token spent, no wait);
      * no token in time   -> fallback marked rate-limited, request NOT sent;
      * otherwise          -> guarded(source, fn, fallback).

    The previous order (token, then breaker) made every call wait for a token
    even while the breaker was open, holding a worker thread for nothing.
    """
    from apis.circuit_breaker import guarded, is_open

    if is_open(source):
        return dict(fallback)
    with quota(source) as got:
        if not got:
            out = dict(fallback)
            out["detail"] = "rate-limited — free-tier quota used up, not checked"
            return out
        return guarded(source, fn, fallback=dict(fallback))


def snapshot() -> dict:
    """Per-source limiter state, for /health and for diagnosing a slow batch."""
    with _REG_LOCK:
        return {
            name: {
                "per_min": b.capacity,
                "tokens_available": round(b.tokens, 2),
                "total_wait_s": round(b.waited_total, 1),
                "wait_expired": b.gave_up,
            }
            for name, b in _BUCKETS.items()
        }


def reset() -> None:
    """Drop all buckets. For tests."""
    with _REG_LOCK:
        _BUCKETS.clear()
