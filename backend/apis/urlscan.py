"""
urlscan.io — live page-preview + sandbox intel for the URL scanner.

Public surface
--------------
  async check_urlscan(url) -> {
      "screenshot_url": str | None,   # https://urlscan.io/screenshots/<uuid>.png
      "page_title":     str | None,
      "final_url":      str | None,   # URL after redirects, as rendered
      "malicious":      bool,
      "score":          int,
  }

Flow
----
  1. POST /api/v1/scan/  with header "API-Key" and JSON {url, visibility:"unlisted"}
     -> returns a scan UUID.
  2. Poll /api/v1/result/<uuid>/ with short backoff (max ~20s).  The result
     endpoint returns 404 until the sandbox finishes rendering the page.

The blocking work runs in a thread-pool via asyncio.to_thread() so it never
blocks the FastAPI event loop.  Any error, missing key, or timeout degrades
gracefully to a null-preview fallback.  Definitive results are cached by URL.
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


import os
import time

import requests

from apis.url_cache import cache_get, cache_put
from apis.quota import paced  # noqa: E402
from apis.circuit_breaker import SourceUnavailable

_KEY = "urlscan:"
_FALLBACK = {
    "screenshot_url": None,
    "page_title": None,
    "final_url": None,
    "malicious": False,
    "score": 0,
}

_SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
_RESULT_URL = "https://urlscan.io/api/v1/result/{uuid}/"
_SCREENSHOT_URL = "https://urlscan.io/screenshots/{uuid}.png"

# Max total time spent polling for the result. Must stay under
# aggregator.ENRICH_BUDGET_S (6 s): full_scan stops waiting for urlscan there,
# and a 20 s poll kept a worker thread busy for nobody on every
# non-allowlisted URL of a batch. A result not ready in time is skipped — the
# screenshot is enrichment and never part of the verdict.
_POLL_DEADLINE_S = 5.0


def _check_sync(url: str) -> dict:
    """Blocking implementation — call via check_urlscan() in async context."""
    api_key = os.getenv("URLSCAN_API_KEY", "").strip()
    if not api_key or api_key == "your_key_here":
        return _FALLBACK.copy()

    cached = cache_get(_KEY + url)
    if cached is not None:
        return cached

    headers = {"API-Key": api_key, "Content-Type": "application/json"}

    def _call() -> dict:
        submit = requests.post(
            _SUBMIT_URL,
            headers=headers,
            json={"url": url, "visibility": "unlisted"},
            timeout=10,
        )
        if submit.status_code in (429, 500, 502, 503, 504):
            raise SourceUnavailable(f"urlscan HTTP {submit.status_code}")
        if submit.status_code != 200:
            return _FALLBACK.copy()

        uuid = submit.json().get("uuid")
        if not uuid:
            return _FALLBACK.copy()

        result_json = _poll_result(uuid, headers)
        if result_json is None:
            return _FALLBACK.copy()

        page = result_json.get("page", {}) or {}
        verdict = (result_json.get("verdicts", {}) or {}).get("overall", {}) or {}

        result = {
            "screenshot_url": _SCREENSHOT_URL.format(uuid=uuid),
            "page_title": page.get("title"),
            "final_url": page.get("url"),
            "malicious": bool(verdict.get("malicious", False)),
            "score": int(verdict.get("score", 0) or 0),
        }
        cache_put(_KEY + url, result)
        return result

    # Breaker first, then a token, then the request (apis.quota.paced).
    return paced("urlscan", _call, fallback=_FALLBACK.copy())


def _poll_result(uuid: str, headers: dict) -> dict | None:
    """Poll the result endpoint until ready (HTTP 200) or the deadline passes."""
    result_url = _RESULT_URL.format(uuid=uuid)
    deadline = time.time() + _POLL_DEADLINE_S
    delay = 2.0
    while time.time() < deadline:
        try:
            resp = requests.get(result_url, headers=headers, timeout=10)
            if resp.status_code == 200:
                return resp.json()
            # 404 == not finished rendering yet; anything else, keep trying briefly
        except Exception:
            pass
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        time.sleep(min(delay, remaining))
        delay = min(delay * 1.5, 5.0)
    return None


async def check_urlscan(url: str) -> dict:
    """Non-blocking entry point for use inside FastAPI route handlers."""
    import asyncio
    return await asyncio.to_thread(_check_sync, url)


# ---------------------------------------------------------------------------
# Self-test  (python -m apis.urlscan <url>)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import asyncio
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    key = os.getenv("URLSCAN_API_KEY", "").strip()
    if not key or key == "your_key_here":
        print("WARNING: URLSCAN_API_KEY not set — result will be the null fallback.")

    out = asyncio.run(check_urlscan(target))
    for k, v in out.items():
        print(f"  {k:14} = {v!r}")
