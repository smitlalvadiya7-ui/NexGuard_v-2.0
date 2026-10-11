"""
Google Safe Browsing v4 — async wrapper for FastAPI.

Public surface
--------------
  async check_safe_browsing(url) -> {"status": "clean|flag", "detail": str}

Runs the blocking HTTP call in a thread-pool via asyncio.to_thread() so it
never blocks the event loop.  Falls back to {"status":"clean","detail":"unavailable"}
on any error.
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
from apis.quota import paced  # noqa: E402
from apis.circuit_breaker import SourceUnavailable
from apis import intel_pool

# "unavailable", not "clean" — see apis/virustotal.py for why the distinction
# matters. Neutral in scoring either way.
_FALLBACK = {"status": "unavailable", "detail": "unavailable"}
_KEY = "gsb:"

_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# One Session for every lookup, so connections are kept alive and reused.
# requests.post() opens a fresh Session each time, which means a new SSL
# context and a fresh load of the certifi CA bundle: 0.24 s of CPU per lookup
# on OpenSSL 3.0, about 6 s with 20 in parallel. On 2026-10-09 that pushed a
# batch past full_scan's 2.2 s budget and 136 of 200 rows read UNKNOWN
# (tests/test_safe_browsing_session.py). pool_maxsize covers several batch
# jobs running at once; beyond it urllib3 opens extra connections, not errors.
_HTTP = requests.Session()
_HTTP.mount("https://", requests.adapters.HTTPAdapter(pool_maxsize=32))


_LICENCE_BLOCKED = {
    "status": "unavailable",
    "detail": "not licensed in this build (Safe Browsing v4 is non-commercial "
              "only) — this build uses Google Web Risk instead",
}


def _check_sync(url: str) -> dict:
    """Blocking implementation — call via check_safe_browsing() in async context."""
    # Licence gate before the request, not after it.
    from deployment_profile import is_allowed
    if not is_allowed("safe_browsing_v4"):
        return _LICENCE_BLOCKED.copy()

    api_key = os.getenv("GOOGLE_SAFEBROWSING_API_KEY", "").strip()
    if not api_key or api_key == "your_key_here":
        return _FALLBACK.copy()

    cached = cache_get(_KEY + url)
    if cached is not None:
        return cached

    payload = {
        "client": {"clientId": "nexguard-ai", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": _THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    def _call() -> dict:
        resp = _HTTP.post(
            f"{_API_URL}?key={api_key}",
            json=payload,
            timeout=5,
        )
        if resp.status_code in (429, 500, 502, 503, 504):
            raise SourceUnavailable(f"GSB HTTP {resp.status_code}")
        resp.raise_for_status()
        matches = resp.json().get("matches")
        result = (
            {"status": "flag",  "detail": matches[0]["threatType"]}
            if matches
            else {"status": "clean", "detail": "not listed"}
        )
        cache_put(_KEY + url, result)
        return result

    # Breaker first, then a token, then the request (apis.quota.paced). A
    # batch that fires everything at once earns 429s and opens the breaker;
    # a token wait longer than full_scan's budget pins a worker thread.
    return paced("safe_browsing", _call, fallback=_FALLBACK.copy())


async def check_safe_browsing(url: str) -> dict:
    """Non-blocking entry point for use inside FastAPI route handlers.

    Runs on apis.intel_pool, not the loop's default pool, so slow page and
    enrichment work cannot keep it waiting past full_scan's budget.
    """
    return await intel_pool.run(_check_sync, url)


# ---------------------------------------------------------------------------
# Self-test  (python -m apis.safe_browsing  or  python safe_browsing.py)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import asyncio
    import sys

    # Google publishes these URLs specifically for API testing:
    # https://developers.google.com/safe-browsing/v4/urls-hashes#checking-urls
    TEST_CASES = [
        # (url, expected_status)
        ("http://testsafebrowsing.appspot.com/s/malware.html", "flag"),
        ("http://testsafebrowsing.appspot.com/s/phishing.html", "flag"),
        ("https://www.google.com", "clean"),
    ]

    async def run_tests() -> None:
        key = os.getenv("GOOGLE_SAFEBROWSING_API_KEY", "").strip()
        if not key or key == "your_key_here":
            print("WARNING: GOOGLE_SAFEBROWSING_API_KEY not set — all results will be 'unavailable'.")

        passed = failed = 0
        for url, expected in TEST_CASES:
            result = await check_safe_browsing(url)
            status = result["status"]
            detail = result["detail"]
            ok = (status == expected) or (status == "clean" and detail == "unavailable")
            marker = "PASS" if ok else "FAIL"
            if ok:
                passed += 1
            else:
                failed += 1
            print(f"[{marker}] {url}")
            print(f"       expected={expected!r}  got={status!r}  detail={detail!r}")

        print(f"\n{passed} passed, {failed} failed.")
        if failed:
            sys.exit(1)

    asyncio.run(run_tests())
