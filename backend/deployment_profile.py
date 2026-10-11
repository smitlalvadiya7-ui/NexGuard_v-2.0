"""
Which threat-intelligence sources this build is licensed to use.

NexGuard sells a Premium tier through Stripe (`billing.py`), which makes it a
COMMERCIAL product. Three of the sources the scanner leans on forbid exactly
that:

    VirusTotal Public API   "must not be used in commercial products or
                             services" · 500/day · 4 req/min
    Safe Browsing v4        "for non-commercial use only" — Google directs
                             commercial users to Web Risk
    OpenPhish feed          non-commercial

Measured 2026-07-28 against a 190,542-domain known-malicious corpus, the full
stack caught 96.7% and the local engine alone caught ~72%. **The difference was
borrowed from those three APIs.** Shipping it inside a paid product would be a
licence violation, not a technical problem — which is why this is a hard gate in
code rather than a note in a README.

Two builds, one code path
-------------------------
    NEXGUARD_DEPLOYMENT_PROFILE=commercial     (default)
        Web Risk, Phishing.Database, URLhaus, and a user's OWN VirusTotal key.

    NEXGUARD_DEPLOYMENT_PROFILE=noncommercial
        Everything, including VT public, Safe Browsing v4 and OpenPhish.

One switch rather than two branches, because two branches drift and the one that
drifts is always the one nobody is measuring.

Fails closed
------------
The default is COMMERCIAL, an unrecognised value falls back to COMMERCIAL, and a
source nobody has reviewed is refused. An unconfigured deployment declines to
use a source rather than silently violating its licence — the cost of getting
that wrong is legal, and legal mistakes are not caught by tests.

The blocked sources are reported as `unavailable`, never `clean`: "we are not
licensed to check this" is not the same claim as "we checked and it was fine".
"""

from __future__ import annotations

import os
from functools import lru_cache

COMMERCIAL = "commercial"
NONCOMMERCIAL = "noncommercial"

_ENV_VAR = "NEXGUARD_DEPLOYMENT_PROFILE"

# Sources whose free tier forbids commercial use, with the reason recorded so a
# future reader can check the claim without re-reading four vendors' terms.
_NON_COMMERCIAL_ONLY = {
    "virustotal_public": (
        "VirusTotal Public API: 'must not be used in commercial products or "
        "services'; 500 requests/day, 4 per minute. A paid product needs a "
        "Premium licence, or the user's own key (see virustotal_user_key)."
    ),
    "safe_browsing_v4": (
        "Google Safe Browsing v4 is 'for non-commercial use only'. Google "
        "directs commercial users to Web Risk, whose Lookup API is free for "
        "the first 100,000 calls per month and IS licensed for commercial use."
    ),
    "openphish": (
        "OpenPhish's community feed is licensed for non-commercial use only. "
        "Phishing.Database and URLhaus cover the same ground for a paid build."
    ),
}

# Reviewed and cleared for either build.
_COMMERCIAL_SAFE = {
    "web_risk": (
        "Google Web Risk — the commercially licensed successor to Safe "
        "Browsing. Lookup API free for the first 100,000 calls per month."
    ),
    "phishing_database": "Phishing.Database — public domain / permissive.",
    "urlhaus": (
        "URLhaus (abuse.ch) — free to use; an Auth-Key is required. Confirm "
        "the current terms before launch."
    ),
    "virustotal_user_key": (
        "The END USER's own VirusTotal key, used to call VirusTotal as them. "
        "Their key, their quota, their licence — not the product shipping one."
    ),
    "dns_auth": (
        "Public DNS records (DMARC, SPF, MX) for a sender's own domain, read "
        "over DNS-over-HTTPS. DNS carries no licence and no key, so this is "
        "one of the few sources that works identically in both builds — it "
        "improves the COMMERCIAL build, which is the one the three blocked "
        "feeds leave weaker."
    ),
}


@lru_cache(maxsize=1)
def profile() -> str:
    """
    The active deployment profile.

    Cached because it is read on every scan and cannot change within a process.
    Tests call `profile.cache_clear()`.
    """
    # THIS BUILD'S IDENTITY — the one line that differs between the two
    # deliverables. v1 ships COMMERCIAL, v2 ships NONCOMMERCIAL.
    raw = (os.getenv(_ENV_VAR) or "").strip().lower()
    if raw == COMMERCIAL:
        return COMMERCIAL
    if raw == NONCOMMERCIAL:
        return NONCOMMERCIAL
    return NONCOMMERCIAL


def is_allowed(source: str) -> bool:
    """
    May this build use `source`?

    Unknown sources are refused under the commercial profile: a feed nobody has
    reviewed has not been cleared to ship inside a paid product.
    """
    if profile() == NONCOMMERCIAL:
        return True
    return source in _COMMERCIAL_SAFE


def blocked_sources() -> list[str]:
    """Sources this build must not use, for the operator and the startup log."""
    if profile() == NONCOMMERCIAL:
        return []
    return sorted(_NON_COMMERCIAL_ONLY)


def licence_note(source: str) -> str:
    """Why a source is restricted, or what licence clears it. '' if unknown."""
    return _NON_COMMERCIAL_ONLY.get(source) or _COMMERCIAL_SAFE.get(source, "")


def describe() -> str:
    """One-paragraph summary for the startup log and the /health payload."""
    if profile() == NONCOMMERCIAL:
        return ("Deployment profile: NON-COMMERCIAL — every threat-intelligence "
                "source is enabled, including VirusTotal Public, Safe Browsing "
                "v4 and OpenPhish. This build may not be sold or used in a "
                "commercial service.")
    return ("Deployment profile: COMMERCIAL — VirusTotal Public, Safe Browsing "
            "v4 and OpenPhish are DISABLED because their free tiers forbid "
            "commercial use. Active sources: Web Risk, Phishing.Database, "
            "URLhaus, plus each user's own VirusTotal key if they supply one.")
