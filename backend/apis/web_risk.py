"""
Google Web Risk — the reputation source a COMMERCIAL build may use.

Safe Browsing v4 is "for non-commercial use only" and Google directs commercial
users here. Web Risk queries the same threat corpus, and its Lookup API is free
for the first 100,000 calls per month — about 3,300 scans a day, which covers a
launch comfortably.

Deliberately interface-compatible with apis/safe_browsing.py, so the aggregator
swaps one import and nothing else changes:

    async check_web_risk(url) -> {"status": "flag|clean|unavailable", "detail": str}

Setup
-----
    1. Google Cloud console -> enable the Web Risk API
    2. Create an API key
    3. GOOGLE_WEB_RISK_API_KEY=... in backend/.env

Failure is never "clean"
------------------------
No key, a quota exhaustion, a network error or a malformed body all return
`status: "unavailable"`. That distinction is the reason this codebase exists in
its current shape: on 2026-07-28 a 190,542-domain known-malicious corpus scanned
73% SAFE because sources that had never run were reporting "clean".

Quota care
----------
Answers are cached (apis/url_cache, 1h default) and failures are NOT — caching a
failure would keep the source dark long after it recovered.
"""

import sys as _sys
from pathlib import Path as _Path

# Fill missing env vars from backend/.env before the key is read; only main.py
# and telegram_bot.py used to do this (see env_config).
_BACKEND = _Path(__file__).resolve().parent.parent
if str(_BACKEND) not in _sys.path:
    _sys.path.insert(0, str(_BACKEND))
import env_config  # noqa: E402,F401  — imported for its side effect

import asyncio  # noqa: E402
import os  # noqa: E402

import requests  # noqa: E402

from apis.quota import paced  # noqa: E402
from apis.circuit_breaker import SourceUnavailable  # noqa: E402
from apis.url_cache import cache_get, cache_put  # noqa: E402
from apis import intel_pool  # noqa: E402

_FALLBACK = {"status": "unavailable", "detail": "unavailable"}
_KEY = "webrisk:"

# SOCIAL_ENGINEERING is the phishing class and the one that matters most here;
# dropping any of these silently narrows what the scanner can ever detect.
_THREAT_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]

_API_URL = "https://webrisk.googleapis.com/v1/uris:search"

_TIMEOUT = 5


def _check_sync(url: str) -> dict:
    """Blocking implementation — call via check_web_risk() in async code."""
    api_key = os.getenv("GOOGLE_WEB_RISK_API_KEY", "").strip()
    if not api_key or api_key == "your_key_here":
        return _FALLBACK.copy()

    cached = cache_get(_KEY + url)
    if cached is not None:
        return cached

    def _call() -> dict:
        resp = requests.get(
            _API_URL,
            params={"key": api_key, "uri": url, "threatTypes": _THREAT_TYPES},
            timeout=_TIMEOUT,
        )
        # Quota exhaustion is the expected failure at 100k/month, and it must
        # read as "could not check", never as a clean bill of health.
        if resp.status_code in (429, 500, 502, 503, 504):
            raise SourceUnavailable(f"Web Risk HTTP {resp.status_code}")
        resp.raise_for_status()

        # Web Risk answers {} for a URL it has nothing on — not a 404.
        threat = (resp.json() or {}).get("threat") or {}
        types = threat.get("threatTypes") or []
        result = (
            {"status": "flag", "detail": ", ".join(types)}
            if types
            else {"status": "clean", "detail": "not listed"}
        )
        cache_put(_KEY + url, result)
        return result

    # Breaker first, then a token, then the request (apis.quota.paced). A
    # batch that fires everything at once earns 429s and opens the breaker;
    # a token wait longer than full_scan's budget pins a worker thread.
    return paced("web_risk", _call, fallback=_FALLBACK.copy())


async def check_web_risk(url: str) -> dict:
    """Non-blocking entry point — Google Web Risk reputation for a URL.

    On apis.intel_pool, like Safe Browsing, so it never queues behind slow
    page and enrichment work.
    """
    return await intel_pool.run(_check_sync, url)


# ---------------------------------------------------------------------------
# Self-test  (python -m apis.web_risk <url>)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json

    target = _sys.argv[1] if len(_sys.argv) > 1 else "http://testsafebrowsing.appspot.com/s/phishing.html"
    print(json.dumps(asyncio.run(check_web_risk(target)), indent=2))
