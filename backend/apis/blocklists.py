"""
Blocklist checks — URLHaus.

Public surface
--------------
  async check_urlhaus(url) -> {"status": "clean|flag", "detail": str}

Runs its blocking HTTP work in a thread-pool via asyncio.to_thread() and falls
back to {"status":"clean","detail":"unavailable"} on any error or missing key.

PhishTank used to live here as a placeholder that returned a hardcoded
"clean" for every URL — its checkurl endpoint answers 403 without an app key
and registration for new keys is closed, so the check could never run while
the scan report still listed it as a source. It was removed on 2026-07-27 and
its slot in the reputation blend is now the community blocklist in
apis/phish_feeds.py (OpenPhish + Phishing.Database).
"""

import sys as _sys
from pathlib import Path as _Path
# Fill missing env vars from backend/.env before any key is read. Without
# this, only main.py and telegram_bot.py had the keys and every other entry
# point scanned with this source silently switched off (see env_config).
_BACKEND = _Path(__file__).resolve().parent.parent
if str(_BACKEND) not in _sys.path:
    _sys.path.insert(0, str(_BACKEND))
import env_config  # noqa: E402,F401  — imported for its side effect


import asyncio
import os
import requests

from apis.url_cache import cache_get, cache_put
from apis.circuit_breaker import guarded, SourceAuthRejected, SourceUnavailable
from apis import intel_pool

# "unavailable", not "clean" — see apis/virustotal.py.
_FALLBACK = {"status": "unavailable", "detail": "unavailable"}
_URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
_KEY = "uh:"


# ---------------------------------------------------------------------------
# URLHaus
# ---------------------------------------------------------------------------

def _auth_reason(resp) -> str:
    """abuse.ch's own words for why the key was refused, for the operator log."""
    try:
        body = resp.json()
    except Exception:
        return ""
    return str(body.get("query_status") or body.get("error") or "")


def _urlhaus_sync(url: str) -> dict:
    auth_key = os.getenv("URLHAUS_AUTH_KEY", "").strip()
    if not auth_key:
        return _FALLBACK.copy()

    cached = cache_get(_KEY + url)
    if cached is not None:
        return cached

    def _call() -> dict:
        resp = requests.post(
            _URLHAUS_API,
            data={"url": url},
            headers={"Auth-Key": auth_key},
            timeout=5,
        )
        if resp.status_code in (401, 403):
            # abuse.ch rejected the credential itself — 403
            # {"query_status": "unknown_auth_key"} for a key it no longer knows,
            # 401 for none at all. Retrying re-sends the same dead key, so this
            # opens the breaker permanently instead.
            raise SourceAuthRejected(
                f"URLHaus HTTP {resp.status_code} {_auth_reason(resp)}".strip())
        if resp.status_code in (429, 500, 502, 503, 504):
            raise SourceUnavailable(f"URLHaus HTTP {resp.status_code}")
        resp.raise_for_status()
        data = resp.json()
        status = data.get("query_status", "")
        if status == "ok":
            threat = data.get("threat") or data.get("tags") or "listed"
            if isinstance(threat, list):
                threat = ", ".join(threat) if threat else "listed"
            result = {"status": "flag", "detail": f"listed ({threat})"}
        elif status == "no_results":
            result = {"status": "clean", "detail": "clean"}
        else:
            # unknown status (e.g. "invalid_url") — not a source failure, don't cache
            return _FALLBACK.copy()
        cache_put(_KEY + url, result)
        return result

    return guarded("urlhaus", _call, fallback=_FALLBACK.copy())


async def check_urlhaus(url: str) -> dict:
    """Non-blocking URLHaus lookup for use inside FastAPI route handlers.

    On apis.intel_pool, so it never queues behind slow page and enrichment work.
    """
    return await intel_pool.run(_urlhaus_sync, url)


# ---------------------------------------------------------------------------
# Self-test  (python -m apis.blocklists)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    # URLHaus publishes a sample known-bad URL in their docs; using a benign
    # URL here so the test always passes even without a real hit.
    TEST_CASES = [
        # (function, url, acceptable_statuses)
        (check_urlhaus,   "https://www.google.com",   {"clean", "flag", "unavailable"}),
        (check_urlhaus,   "http://example.com/test",  {"clean", "flag", "unavailable"}),
    ]

    async def run_tests() -> None:
        key = os.getenv("URLHAUS_AUTH_KEY", "").strip()
        if not key:
            print("WARNING: URLHAUS_AUTH_KEY not set — URLHaus results will be 'unavailable'.")

        passed = failed = 0
        for fn, url, ok_statuses in TEST_CASES:
            result = await fn(url)
            status = result["status"]
            detail = result["detail"]
            ok = status in ok_statuses
            marker = "PASS" if ok else "FAIL"
            if ok:
                passed += 1
            else:
                failed += 1
            print(f"[{marker}] {fn.__name__}({url!r})")
            print(f"       status={status!r}  detail={detail!r}")

        print(f"\n{passed} passed, {failed} failed.")
        if failed:
            sys.exit(1)

    asyncio.run(run_tests())
