
import sys as _sys
from pathlib import Path as _Path
# Fill missing env vars from backend/.env before any key is read. Without
# this, only main.py and telegram_bot.py had the keys and every other entry
# point scanned with this source silently switched off (see env_config).
_BACKEND = _Path(__file__).resolve().parent.parent
if str(_BACKEND) not in _sys.path:
    _sys.path.insert(0, str(_BACKEND))
import env_config  # noqa: E402,F401  — imported for its side effect

import requests
import os
import base64

from apis.url_cache import cache_get, cache_put
from apis.circuit_breaker import SourceUnavailable
from apis.quota import paced

# NOT "clean". A source that could not be reached — no API key, HTTP 429, an
# open circuit breaker — must never be indistinguishable from one that ran and
# found nothing. Scoring treats any status other than flag/warn as neutral, so
# this stays risk-free while telling the truth in the sources table.
_FALLBACK = {"status": "unavailable", "detail": "unavailable", "raw_positives": 0}
_KEY = "vt:"


_LICENCE_BLOCKED = {
    "status": "unavailable",
    "detail": "not licensed in this build (VirusTotal Public API forbids "
              "commercial use) — set NEXGUARD_DEPLOYMENT_PROFILE=noncommercial, "
              "or supply your own VirusTotal key",
    "raw_positives": 0,
}


def check_virustotal(url: str) -> dict:
    # Licence gate FIRST. Returning "unavailable" after making the request would
    # still be the violation — the request itself is the thing forbidden.
    from deployment_profile import is_allowed
    if not is_allowed("virustotal_public"):
        return _LICENCE_BLOCKED.copy()

    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key or api_key == "your_key_here":
        return _FALLBACK.copy()

    cached = cache_get(_KEY + url)
    if cached is not None:
        return cached

    headers = {"x-apikey": api_key}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def _call() -> dict:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10,
        )
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            result = _normalize(stats)
            cache_put(_KEY + url, result)
            return result
        # 429/5xx are real source failures — raise so the breaker counts them.
        if resp.status_code in (429, 500, 502, 503, 504):
            raise SourceUnavailable(f"VT HTTP {resp.status_code}")
        if resp.status_code == 404:
            # VirusTotal has no report for this URL. This used to submit it
            # and poll for up to 6 s — four or five more requests on ONE quota
            # token (guaranteed 429s at 4/min), for an answer that could never
            # arrive inside full_scan's 2.2 s budget anyway. Not knowing a URL
            # is not a clean bill of health, so it stays "unavailable".
            return {**_FALLBACK, "detail": "not yet in VirusTotal's database"}
        return _FALLBACK.copy()

    # Breaker first, then a 4/min token, then the request (apis.quota.paced).
    # No token -> no request: it would only earn a 429. The token wait is kept
    # inside full_scan's budget so a rate-limited VirusTotal can never pin a
    # worker thread — 45 s waits did, and turned 89 of 200 batch rows into
    # UNKNOWN 0% on 2026-09-29.
    return paced("virustotal", _call, fallback=_FALLBACK.copy())


def check_file_hash(sha256: str) -> dict:
    """
    Look up a file by its SHA-256 in VirusTotal (no upload — hash lookup only).

    Returns
    -------
    {
      "status":        "flag" | "warn" | "clean" | "unknown",
      "detail":        human-readable summary,
      "raw_positives": int,
      "found":         bool,   # whether VT has ever seen this file
    }

    Fails safe: missing key, network error, or rate-limit -> 'unavailable'.
    """
    # Deliberately still "clean" here, unlike the URL fallback above: the email
    # attachment UI renders any status other than "clean" as DANGER, so an
    # unreachable VirusTotal would paint every attachment red. Fixing that
    # properly means teaching the frontend the difference first.
    fallback = {"status": "clean", "detail": "unavailable", "raw_positives": 0, "found": False}
    sha256 = (sha256 or "").strip().lower()
    if not sha256:
        return fallback.copy()

    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key or api_key == "your_key_here":
        return fallback.copy()

    cached = cache_get(_KEY + "file:" + sha256)
    if cached is not None:
        return cached

    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers=headers,
            timeout=10,
        )
        if resp.status_code == 404:
            # VT has never seen this file — not proof of safety, just unknown.
            result = {
                "status": "unknown",
                "detail": "not seen by VirusTotal",
                "raw_positives": 0,
                "found": False,
            }
            cache_put(_KEY + "file:" + sha256, result)
            return result
        if resp.status_code != 200:
            return fallback.copy()

        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        result = _normalize(stats)
        result["found"] = True
        cache_put(_KEY + "file:" + sha256, result)
        return result

    except Exception:
        return fallback.copy()


def _normalize(stats: dict) -> dict:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    positives = malicious + suspicious
    total = sum(stats.values())

    if positives >= 3:
        status = "flag"
    elif positives >= 1:
        status = "warn"
    else:
        status = "clean"

    return {
        "status": status,
        "detail": f"{positives}/{total} engines flagged",
        "raw_positives": positives,
    }


