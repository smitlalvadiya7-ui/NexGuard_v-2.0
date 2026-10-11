"""
Shared TTL cache for external URL lookups (VirusTotal, Safe Browsing, URLHaus,
RDAP/WHOIS, geo, TLS) and full scan results.

Backends
--------
  * In-memory (default)  — a process-local dict. Zero-config; perfect for local
    runs and single-process deployments.
  * Redis (for scale)    — set REDIS_URL=redis://host:6379/0 and, if the redis
    package is installed, the cache transparently uses Redis so a multi-worker
    / multi-instance deployment shares one cache. Values are JSON-encoded.

The public surface (cache_get / cache_put / cache_size) is identical for both,
so callers never change. Anything that can't be JSON-encoded for Redis falls
back to skipping the cache write (fail-safe, never raises).

Usage in any API module
-----------------------
    from apis.url_cache import cache_get, cache_put
    cached = cache_get("vt:" + url)
    if cached is not None:
        return cached
    result = ...expensive network call...
    cache_put("vt:" + url, result)

Only store definitive results (status != "unavailable") so a missing API key or
transient network error never poisons the cache.
"""

import json
import logging
import os
import threading
import time
from typing import Any

log = logging.getLogger("nexguard.cache")

TTL = int(os.getenv("NEXGUARD_CACHE_TTL", "3600"))  # 1 hour default
_NS = "nexguard:cache:"

# ---------------------------------------------------------------------------
# In-memory backend (default)
# ---------------------------------------------------------------------------
_STORE: dict[str, dict] = {}
_LOCK = threading.Lock()


def _mem_get(key: str) -> Any | None:
    with _LOCK:
        entry = _STORE.get(key)
    if entry is None:
        return None
    if time.monotonic() - entry["ts"] >= TTL:
        with _LOCK:
            _STORE.pop(key, None)
        return None
    return entry["val"]


def _mem_put(key: str, value: Any) -> None:
    with _LOCK:
        _STORE[key] = {"val": value, "ts": time.monotonic()}


# ---------------------------------------------------------------------------
# Redis backend (optional, for scale)
# ---------------------------------------------------------------------------
_redis = None
_REDIS_URL = os.getenv("REDIS_URL", "").strip()
if _REDIS_URL:
    try:
        import redis  # type: ignore
        _redis = redis.from_url(_REDIS_URL, socket_timeout=2, socket_connect_timeout=2)
        _redis.ping()
        log.info("Cache backend: Redis (%s)", _REDIS_URL.split("@")[-1])
    except Exception as exc:  # noqa: BLE001
        log.warning("REDIS_URL set but Redis unavailable (%s) — using in-memory cache", exc)
        _redis = None


def _redis_get(key: str) -> Any | None:
    try:
        raw = _redis.get(_NS + key)
        return json.loads(raw) if raw is not None else None
    except Exception:
        return None


def _redis_put(key: str, value: Any) -> None:
    try:
        _redis.setex(_NS + key, TTL, json.dumps(value, default=str))
    except Exception:
        pass  # fail-safe: never let a cache write break a scan


# ---------------------------------------------------------------------------
# Public surface
# ---------------------------------------------------------------------------

def cache_get(key: str) -> Any | None:
    """Return the cached value if still fresh, otherwise None."""
    if _redis is not None:
        return _redis_get(key)
    return _mem_get(key)


def cache_put(key: str, value: Any) -> None:
    """Store a value; overwrites any existing entry."""
    if _redis is not None:
        _redis_put(key, value)
    else:
        _mem_put(key, value)


def cache_size() -> int:
    if _redis is not None:
        try:
            return sum(1 for _ in _redis.scan_iter(_NS + "*", count=500))
        except Exception:
            return -1
    with _LOCK:
        return len(_STORE)


def cache_backend() -> str:
    return "redis" if _redis is not None else "memory"


def cache_healthy() -> bool:
    if _redis is None:
        return True
    try:
        _redis.ping()
        return True
    except Exception:
        return False
