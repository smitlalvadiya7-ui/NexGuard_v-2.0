"""
Per-source circuit breaker + retry/backoff for the external-intel sources
(VirusTotal, Safe Browsing, URLHaus, urlscan.io, RDAP/WHOIS, IP geo, TLS).

Why
---
At scale a single flaky or rate-limited source must NEVER fail the whole scan.
Each source gets its own breaker:

  CLOSED     — healthy; calls go through.
  OPEN       — too many recent failures; calls short-circuit INSTANTLY to a
               neutral fallback and the source is reported "unavailable" so the
               aggregator drops it from the blend (renormalising weights).
  HALF_OPEN  — after a cooldown, a single probe is allowed; success closes the
               breaker, failure re-opens it.

This keeps p95 latency bounded when a dependency is down (no waiting on a dead
endpoint) and is fully self-healing.

Usage
-----
    from apis.circuit_breaker import guarded

    def _vt_sync(url):
        return guarded(
            "virustotal",
            lambda: _do_network_call(url),   # the real work
            fallback={"status": "unavailable", "detail": "unavailable"},
            retries=1,
        )

`guarded` runs `fn` with retry/backoff while CLOSED/HALF_OPEN, records the
outcome, and returns `fallback` (without calling `fn`) while OPEN. A call that
returns normally counts as success; a raised exception counts as failure. To
treat a *returned* value as a failure (e.g. an HTTP 503 body), raise
`SourceUnavailable` from inside `fn`.

Everything is thread-safe — sources run in asyncio.to_thread() worker threads.
"""

from __future__ import annotations

import logging
import os
import random
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

log = logging.getLogger("nexguard.breaker")


class SourceUnavailable(Exception):
    """Raise inside a guarded fn to mark the attempt a failure (trips the breaker)."""


class SourceAuthRejected(SourceUnavailable):
    """
    Raise inside a guarded fn when the source REJECTED THE CREDENTIAL itself
    (HTTP 401/403, `unknown_auth_key`, "invalid API key", and friends).

    This is not an outage. Retrying cannot change the answer and neither can
    waiting out a cooldown, so the breaker opens permanently instead of
    re-probing every COOLDOWN_S until someone notices. Cleared only by fixing
    the key and restarting (or `reset_all()` in tests).

    Found the hard way on 2026-08-19: URLHaus answered `403
    {"query_status": "unknown_auth_key"}` on every scan for a key that abuse.ch
    had stopped recognising, and every scan dutifully paid two HTTP calls plus a
    backoff sleep for it.
    """


# Tunables (env-overridable so ops can tighten/loosen without a code change).
def _envf(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, "").strip() or default)
    except Exception:
        return default


def _envi(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "").strip() or default)
    except Exception:
        return default


FAIL_THRESHOLD = _envi("NEXGUARD_BREAKER_FAILS", 5)        # consecutive fails -> OPEN
COOLDOWN_S = _envf("NEXGUARD_BREAKER_COOLDOWN", 30.0)       # OPEN duration before a probe
DEFAULT_RETRIES = _envi("NEXGUARD_SOURCE_RETRIES", 1)       # extra attempts on transient error
BACKOFF_BASE_S = _envf("NEXGUARD_BACKOFF_BASE", 0.25)       # first backoff sleep
BACKOFF_CAP_S = _envf("NEXGUARD_BACKOFF_CAP", 2.0)          # max backoff sleep

CLOSED, OPEN, HALF_OPEN = "closed", "open", "half_open"


@dataclass
class _Breaker:
    name: str
    state: str = CLOSED
    consecutive_failures: int = 0
    opened_at: float = 0.0
    total_calls: int = 0
    total_failures: int = 0
    total_short_circuits: int = 0
    auth_rejected: bool = False
    last_error: str = ""
    last_change: float = field(default_factory=time.time)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # --- state transitions (caller holds no lock; we take it) ---------------
    def _allow(self) -> bool:
        """Return True if a real call should be attempted right now."""
        with self._lock:
            if self.auth_rejected:
                # No cooldown probe: the key is wrong, not the network.
                self.total_short_circuits += 1
                return False
            if self.state == OPEN:
                if time.monotonic() - self.opened_at >= COOLDOWN_S:
                    self.state = HALF_OPEN
                    self.last_change = time.time()
                    log.info("breaker '%s' -> HALF_OPEN (probing)", self.name)
                    return True
                self.total_short_circuits += 1
                return False
            return True  # CLOSED or HALF_OPEN

    def _on_success(self) -> None:
        with self._lock:
            self.total_calls += 1
            self.consecutive_failures = 0
            if self.state != CLOSED:
                log.info("breaker '%s' -> CLOSED (recovered)", self.name)
                self.state = CLOSED
                self.last_change = time.time()

    def _on_failure(self, err: str) -> None:
        with self._lock:
            self.total_calls += 1
            self.total_failures += 1
            self.consecutive_failures += 1
            self.last_error = (err or "")[:200]
            if self.state == HALF_OPEN or self.consecutive_failures >= FAIL_THRESHOLD:
                if self.state != OPEN:
                    log.warning(
                        "breaker '%s' -> OPEN after %d failures (%s)",
                        self.name, self.consecutive_failures, self.last_error,
                    )
                self.state = OPEN
                self.opened_at = time.monotonic()
                self.last_change = time.time()

    def _on_auth_rejected(self, err: str) -> None:
        """Permanent open — the source told us the credential is not valid."""
        with self._lock:
            self.total_calls += 1
            self.total_failures += 1
            self.consecutive_failures += 1
            self.last_error = (err or "")[:200]
            if not self.auth_rejected:
                log.error(
                    "breaker '%s' -> OPEN PERMANENTLY: the source rejected the "
                    "configured API key (%s). No further calls will be made. "
                    "Fix the key and restart.",
                    self.name, self.last_error,
                )
            self.auth_rejected = True
            self.state = OPEN
            self.opened_at = time.monotonic()
            self.last_change = time.time()

    def snapshot(self) -> dict:
        with self._lock:
            healthy = self.state == CLOSED
            return {
                "name": self.name,
                "state": self.state,
                "healthy": healthy,
                "consecutive_failures": self.consecutive_failures,
                "total_calls": self.total_calls,
                "total_failures": self.total_failures,
                "short_circuits": self.total_short_circuits,
                "auth_rejected": self.auth_rejected,
                "last_error": self.last_error or None,
            }


_REGISTRY: dict[str, _Breaker] = {}
_REG_LOCK = threading.Lock()


def get_breaker(name: str) -> _Breaker:
    with _REG_LOCK:
        b = _REGISTRY.get(name)
        if b is None:
            b = _Breaker(name=name)
            _REGISTRY[name] = b
        return b


def is_open(name: str) -> bool:
    """
    True while `name` would short-circuit — OPEN inside its cooldown, or
    permanently open after a rejected key. A read only: unlike `_allow` it
    never moves the breaker to HALF_OPEN, so callers can ask before spending
    anything (a rate-limit token, a thread's time) on a call that would be
    discarded anyway.
    """
    with _REG_LOCK:
        b = _REGISTRY.get(name)
    if b is None:
        return False
    with b._lock:
        if b.auth_rejected:
            return True
        return b.state == OPEN and time.monotonic() - b.opened_at < COOLDOWN_S


def guarded(
    name: str,
    fn: Callable[[], Any],
    fallback: Any,
    retries: int = DEFAULT_RETRIES,
) -> Any:
    """
    Execute `fn` under the named circuit breaker with retry/backoff.

    Returns fn()'s value on success; returns `fallback` if the breaker is OPEN
    (short-circuit, no call made) or if every attempt fails. Never raises.
    """
    b = get_breaker(name)
    if not b._allow():
        log.debug("breaker '%s' OPEN — short-circuit to neutral fallback", name)
        return _copy(fallback)

    attempts = max(1, retries + 1)
    last_exc: Exception | None = None
    for i in range(attempts):
        try:
            result = fn()
            b._on_success()
            return result
        except SourceAuthRejected as exc:
            # Not an outage. A retry sends the same rejected key, and the
            # cooldown probe would send it again every COOLDOWN_S forever.
            b._on_auth_rejected(repr(exc))
            return _copy(fallback)
        except Exception as exc:  # noqa: BLE001 — fail-neutral by contract
            last_exc = exc
            # Backoff before a retry, but only while we still have attempts left
            # and the breaker hasn't tripped to HALF_OPEN (probe = single shot).
            if i < attempts - 1 and b.state != HALF_OPEN:
                sleep = min(BACKOFF_CAP_S, BACKOFF_BASE_S * (2 ** i))
                sleep += random.uniform(0, sleep * 0.25)  # jitter
                time.sleep(sleep)
            else:
                break
    b._on_failure(repr(last_exc) if last_exc else "unknown error")
    return _copy(fallback)


def _copy(value: Any) -> Any:
    """Shallow-copy dict/list fallbacks so callers can mutate freely."""
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, list):
        return list(value)
    return value


def snapshot_all() -> list[dict]:
    """All breaker states, for /health. Sorted by name for stable output."""
    with _REG_LOCK:
        breakers = list(_REGISTRY.values())
    return sorted((b.snapshot() for b in breakers), key=lambda d: d["name"])


def auth_rejected_sources() -> set[str]:
    """Names of sources whose API key was rejected by the source itself.

    Read by intel_health so startup/health reporting can say "key rejected"
    instead of counting a dead credential as a working source.
    """
    with _REG_LOCK:
        return {b.name for b in _REGISTRY.values() if b.auth_rejected}


def reset_all() -> None:
    """Test helper — clear the registry."""
    with _REG_LOCK:
        _REGISTRY.clear()
