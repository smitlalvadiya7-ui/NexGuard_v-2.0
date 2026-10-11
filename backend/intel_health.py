"""
Can this deployment actually check anything?

Written because of a real failure on 2026-07-30. A user scanned a file of
190,542 known-malicious domains through their own running tool and every one
came back SAFE. The code was correct, 822 tests were green, and the cause was
configuration:

  * the `commercial` deployment profile blocks VirusTotal, Safe Browsing and
    OpenPhish, because their free tiers forbid commercial use — correct and
    deliberate;
  * `GOOGLE_WEB_RISK_API_KEY`, the commercially licensed source that replaces
    all three, had not been created yet.

So the scanner had **no reputation source at all**. It started normally,
answered /health with "ok", and returned confident SAFE verdicts. The same
60-domain sample scored 26.7% in that state versus 96.7% with sources reachable.

The bug was not the licence gate. It was the SILENCE. A key can be present and
valid — VIRUSTOTAL_API_KEY was 64 characters of working key the whole time — and
still never be called, so "a key is configured" is not the same as "a source is
usable". This module answers the second question, loudly.

    reputation_status()   -> what is usable, blocked, or missing a key
    warning_text()        -> "" when healthy, otherwise what to do about it
    log_startup_warning() -> shout it into the log on boot
"""

from __future__ import annotations

import logging
import os

from apis.circuit_breaker import auth_rejected_sources
from deployment_profile import is_allowed, profile

log = logging.getLogger("nexguard.intel")

# (display name, source id, env var holding its key, is it PRIMARY?)
#
# PRIMARY means broad phishing coverage — the kind of source whose absence makes
# the scanner blind. Measured across three diagnostic runs over 180
# known-malicious domains:
#
#     VirusTotal flagged   58 / 18 / 60
#     Safe Browsing        13 /  6 / 15
#     URLHaus               0 /  0 /  0
#
# URLHaus is a malware-DISTRIBUTION feed with narrow, deliberate scope. It is
# worth querying and it is not phishing coverage, so it must not be what keeps
# this module quiet. The first version of this check counted it and reported
# "Reputation sources reachable: URLHaus" on a deployment that caught almost
# nothing.
# The trailing field is the CIRCUIT-BREAKER name, which is not always the
# profile's source id (the profile distinguishes `virustotal_public` from a paid
# tier; the breaker only knows one VirusTotal). It is how this module learns
# that a source rejected the key it was given.
_REPUTATION_SOURCES = (
    ("Web Risk", "web_risk", "GOOGLE_WEB_RISK_API_KEY", True, "web_risk"),
    ("VirusTotal", "virustotal_public", "VIRUSTOTAL_API_KEY", True, "virustotal"),
    ("Safe Browsing", "safe_browsing_v4", "GOOGLE_SAFEBROWSING_API_KEY", True, "safe_browsing"),
    ("URLHaus", "urlhaus", "URLHAUS_AUTH_KEY", False, "urlhaus"),
)

_PLACEHOLDERS = {"your_key_here", "changeme", "xxx", "todo", "replace_me"}


def _has_key(env_var: str) -> bool:
    raw = (os.getenv(env_var) or "").strip()
    return bool(raw) and raw.lower() not in _PLACEHOLDERS


def reputation_status() -> dict:
    """
    Which reputation sources this deployment can actually reach.

    A source is `usable` only when it is BOTH licensed for this build AND has a
    key. Those two conditions failing independently is exactly what hid the
    2026-07-30 failure: three licensed-out sources with valid keys, and one
    licensed source with no key.
    """
    usable, usable_primary, blocked, missing, rejected = [], [], [], [], []
    refused = auth_rejected_sources()
    for name, source_id, env_var, primary, breaker in _REPUTATION_SOURCES:
        if not is_allowed(source_id):
            blocked.append(name)
        elif not _has_key(env_var):
            missing.append(name)
        elif breaker in refused:
            # A key IS configured; the source itself refused it. Reporting this
            # as usable is what let a 403-on-every-scan deployment announce
            # three healthy sources at boot.
            rejected.append(name)
        else:
            usable.append(name)
            if primary:
                usable_primary.append(name)
    return {
        "profile": profile(),
        "usable": usable,
        # Key present, source says no. Neither "usable" nor "missing" — telling
        # an operator to create a key they already have sends them nowhere.
        "rejected_key": rejected,
        # Blindness is judged on PRIMARY coverage only. A build with nothing but
        # URLHaus is technically querying something and practically blind.
        "usable_primary": usable_primary,
        "blocked_by_licence": blocked,
        "missing_key": missing,
        "blind": not usable_primary,
    }


def warning_text() -> str:
    """
    What to say when the scanner cannot check anything. "" when it can.

    Names the profile responsible, the exact key to create, and what it means
    for verdicts — because the user who hit this had all three questions and the
    application answered none of them.
    """
    status = reputation_status()
    if not status["blind"]:
        return ""

    lines = [
        "NO REPUTATION SOURCE IS REACHABLE — this scanner cannot check any URL",
        "against threat intelligence. SAFE verdicts mean 'nothing local looked",
        "wrong', NOT 'this URL was checked and is clean'. Measured on a",
        "known-malicious corpus: 26.7% caught in this state, 96.7% with sources",
        "reachable.",
        "",
        f"Deployment profile: {status['profile']}",
    ]
    if status["blocked_by_licence"]:
        lines.append(
            "  blocked by licence : " + ", ".join(status["blocked_by_licence"])
            + "  (their free tiers forbid commercial use)")
    if status["missing_key"]:
        lines.append("  licensed, NO KEY   : " + ", ".join(status["missing_key"]))
    if status["rejected_key"]:
        lines.append(
            "  key REJECTED       : " + ", ".join(status["rejected_key"])
            + "  (a key IS set and the source refused it — replace it, do not"
              " create a second one)")
    if status["usable"] and not status["usable_primary"]:
        lines.append(
            "  reachable but NOT phishing coverage : "
            + ", ".join(status["usable"])
            + "  (URLHaus flagged 0 of 180 known-malicious domains)")
    lines += ["", "FIX — pick one:"]

    if status["profile"] == "commercial":
        lines += [
            "  1. Create a Google Web Risk key (free for the first 100,000",
            "     lookups/month, and licensed for commercial use):",
            "       console.cloud.google.com -> enable Web Risk API -> API key",
            "     then in backend/.env:  GOOGLE_WEB_RISK_API_KEY=AIza...",
            "",
            "  2. Only if you are NOT selling this: run the non-commercial",
            "     build, which may use VirusTotal and Safe Browsing —",
            "       NEXGUARD_DEPLOYMENT_PROFILE=noncommercial",
        ]
    else:
        lines += [
            "  Set a key for at least one source, e.g. VIRUSTOTAL_API_KEY or",
            "  GOOGLE_SAFEBROWSING_API_KEY, in backend/.env.",
        ]
    lines += ["", "Check anytime:  cd backend && python check_env.py"]
    return "\n".join(lines)


def log_startup_warning() -> bool:
    """
    Shout it at boot. Returns True when a warning was emitted.

    Deliberately a banner rather than one line: the previous behaviour was to
    start silently, and a single line in a busy startup log is how that happens
    again.
    """
    text = warning_text()
    if not text:
        status = reputation_status()
        # "configured", not "reachable". At boot nothing has been queried yet,
        # so reachability is a claim this process has no evidence for — and
        # printing it as fact is what hid a URLHaus key that answered 403 on
        # every scan. Rejections are only known once a source has refused one.
        log.info("Reputation sources configured: %s (primary: %s)",
                 ", ".join(status["usable"]) or "none",
                 ", ".join(status["usable_primary"]) or "none")
        if status["rejected_key"]:
            log.error(
                "API key REJECTED by the source: %s — a key is set and the "
                "source refused it. Those sources are no longer being called; "
                "replace the key and restart.",
                ", ".join(status["rejected_key"]))
        return False

    bar = "!" * 72
    log.warning("\n%s\n%s\n%s", bar, text, bar)
    return True
