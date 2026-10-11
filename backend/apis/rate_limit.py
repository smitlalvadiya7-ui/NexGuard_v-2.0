"""
Distributed-friendly rate limiting.

Uses Redis (REDIS_URL) for a shared fixed-window counter so the limit holds
across multiple workers / instances. Falls back to a process-local in-memory
counter when Redis is unavailable — identical behaviour for a single process,
which keeps the local flow working with zero config.

    from apis.rate_limit import allow
    if not allow(f"anon:{ip}", limit=5, window_s=86400):
        return too_many_requests()

`allow` returns True if the call is within the limit (and counts it), False if
the limit is exceeded. Never raises — on any backend error it fails OPEN
(allows the call) so rate limiting can never take the whole service down.
"""

import logging
import threading
import time

log = logging.getLogger("nexguard.ratelimit")

# Reuse the same Redis connection the cache established, if any.
try:
    from apis.url_cache import _redis as _shared_redis  # type: ignore
except Exception:  # pragma: no cover
    _shared_redis = None

_NS = "nexguard:rl:"

# In-memory fallback: key -> (window_start_epoch, count, window_s)
# The window length is stored alongside the tally so count() can tell a live
# window from an expired one without being told the window again.
_MEM: dict[str, tuple[float, int, int]] = {}
_LOCK = threading.Lock()


def _mem_allow(key: str, limit: int, window_s: int) -> bool:
    now = time.time()
    with _LOCK:
        start, hits, _ = _MEM.get(key, (now, 0, window_s))
        if now - start >= window_s:
            start, hits = now, 0
        if hits >= limit:
            _MEM[key] = (start, hits, window_s)
            return False
        _MEM[key] = (start, hits + 1, window_s)
        return True


def _redis_allow(key: str, limit: int, window_s: int) -> bool:
    try:
        rkey = _NS + key
        # INCR then set the TTL on first hit (fixed window).
        count = _shared_redis.incr(rkey)
        if count == 1:
            _shared_redis.expire(rkey, window_s)
        return count <= limit
    except Exception:
        return True  # fail OPEN — never block scans on a rate-limiter error


def allow(key: str, limit: int, window_s: int) -> bool:
    """True if this call is within `limit` per `window_s` for `key` (and counts it)."""
    if _shared_redis is not None:
        return _redis_allow(key, limit, window_s)
    return _mem_allow(key, limit, window_s)


def count(key: str) -> int:
    """
    Hits recorded for `key` in the current window, WITHOUT consuming one.

    The login lockout needs to read the failure tally on every attempt while
    only charging genuine failures — `allow` can't do that, since it counts
    every call. Fails OPEN (returns 0) like the rest of this module.
    """
    if _shared_redis is not None:
        try:
            raw = _shared_redis.get(_NS + key)
            return int(raw) if raw is not None else 0
        except Exception:
            return 0

    with _LOCK:
        entry = _MEM.get(key)
    if entry is None:
        return 0
    start, hits, window_s = entry
    return 0 if time.time() - start >= window_s else hits


def reset(key: str) -> None:
    """Drop `key`'s counter (a successful login clears its failure tally)."""
    if _shared_redis is not None:
        try:
            _shared_redis.delete(_NS + key)
        except Exception:
            pass
        return

    with _LOCK:
        _MEM.pop(key, None)


def backend() -> str:
    return "redis" if _shared_redis is not None else "memory"
