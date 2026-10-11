"""
Support-bot scan tools (NEXT_PHASE_PLAN C1).

The FAQ assistant can now *act*: when the user pastes a link (or a whole
scam-looking message) into /support/ask, the endpoint runs the real scanners
and this module phrases the chat reply — verdict, risk score, and the main
reasons — in the same {matched, confidence, answer, related} shape the
Support page already renders. Scan replies add `action` and `scan` so the UI
can show a verdict chip.

Leaf module: stdlib-only (like support_faq.py).
"""
import re

# Follow-up chips offered after a scan answer — real FAQ questions.
_SCAN_RELATED = [
    "What do SAFE, SUSPICIOUS and MALICIOUS mean?",
    "How do I report a wrong verdict?",
]

# A bare domain (no scheme, no www.) is only treated as a scan request when
# the user sounds like they're asking about a link — otherwise casual mentions
# ("we discussed node.js") would trigger scans.
_INTENT_WORDS = {
    "safe", "scan", "check", "checked", "legit", "legitimate", "scam",
    "phishing", "phish", "malicious", "suspicious", "virus", "link", "url",
    "site", "website", "open", "click", "clicked", "real", "fake", "fraud",
    "dangerous", "trust", "verify",
}

_SCHEME_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_WWW_URL_RE = re.compile(r"\bwww\.[^\s<>\"']+", re.IGNORECASE)
_BARE_DOMAIN_RE = re.compile(
    r"\b[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9-]{1,63})*\.[a-z]{2,24}\b(?:/[^\s<>\"']*)?",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"\S+@\S+")
_TRAILING_PUNCT = ".,;:!?)]}'\""


def _clean_match(url: str) -> str:
    return url.rstrip(_TRAILING_PUNCT)


def extract_url(text) -> str | None:
    """First URL in the text, or None. Scheme/www URLs always count; a bare
    domain only counts when the text also contains scan-intent wording.
    Email addresses are never treated as URLs."""
    if not text or not isinstance(text, str):
        return None

    m = _SCHEME_URL_RE.search(text)
    if m:
        return _clean_match(m.group(0))

    # Strip email addresses so user@domain.com can't look like a domain.
    no_emails = _EMAIL_RE.sub(" ", text)

    m = _WWW_URL_RE.search(no_emails)
    if m:
        return _clean_match(m.group(0))

    words = set(re.findall(r"[a-z]+", text.lower()))
    if words & _INTENT_WORDS:
        m = _BARE_DOMAIN_RE.search(no_emails)
        if m:
            return _clean_match(m.group(0))
    return None


# ── C3 — conversation memory ────────────────────────────────────────────────
# A follow-up like "scan it again" has no URL of its own; the endpoint pulls
# the newest URL out of the recent USER turns instead. Patterns stay tight so
# real FAQ questions ("How does the QR scanner work?") never re-scan.

_FOLLOWUP_RES = [
    re.compile(r"\bre-?scan\b", re.IGNORECASE),
    re.compile(r"\b(scan|check|test|try)\b.{0,40}\b(it|that|this|again)\b",
               re.IGNORECASE),
    re.compile(r"\bis (it|that|this) (safe|ok|okay|clean|legit)\b", re.IGNORECASE),
    re.compile(r"\bwhat about (it|that|now)\b", re.IGNORECASE),
]

_HISTORY_MAX_TURNS = 6
_HISTORY_MAX_CHARS = 2000


def is_followup_scan(text) -> bool:
    """True when the text asks to re-check something said earlier (and
    carries no URL itself — the caller checks extract_url first)."""
    if not text or not isinstance(text, str):
        return False
    return any(r.search(text) for r in _FOLLOWUP_RES)


def normalize_history(history) -> list:
    """Validate client-sent history into [{role, text}], last
    _HISTORY_MAX_TURNS turns, each text capped. Junk items are dropped —
    the client is untrusted."""
    if not isinstance(history, list):
        return []
    out = []
    for item in history:
        if not isinstance(item, dict):
            continue
        role = item.get("role")
        text = item.get("text")
        if role not in ("user", "bot") or not isinstance(text, str) or not text:
            continue
        out.append({"role": role, "text": text[:_HISTORY_MAX_CHARS]})
    return out[-_HISTORY_MAX_TURNS:]


def history_url(history) -> str | None:
    """Newest URL mentioned by the USER in the conversation, or None. Bot
    turns are ignored — the bot echoes scanned URLs in its own answers."""
    if not isinstance(history, list):
        return None
    for item in reversed(history):
        if not isinstance(item, dict) or item.get("role") != "user":
            continue
        url = extract_url(item.get("text"))
        if url:
            return url
    return None


def bot_rescan_reply(url: str, result: dict) -> dict:
    """Chat reply for a follow-up re-scan of a URL from earlier turns."""
    lines = [f"I scanned {url} again."] + _verdict_lines(result, "link")
    return {
        "matched": True,
        "confidence": 1.0,
        "question": None,
        "answer": "\n".join(lines),
        "related": list(_SCAN_RELATED),
        "action": "scanned_url",
        "scan": _scan_summary(result, url),
    }


def looks_like_message(text) -> bool:
    """True when the text reads like a pasted email/SMS rather than a
    question: header-style lines, or simply long free text."""
    if not text or not isinstance(text, str):
        return False
    if re.search(r"(?mi)^\s*(subject|from|to|dear)\s*:", text):
        return True
    return len(text.split()) >= 25


def _confidence_word(confidence) -> str | None:
    if not isinstance(confidence, (int, float)):
        return None
    return "high" if confidence >= 75 else "medium" if confidence >= 45 else "low"


def _verdict_lead(verdict: str, target_word: str) -> str:
    return {
        "MALICIOUS": f"⚠ Do NOT open this {target_word} or act on it.",
        "SUSPICIOUS": f"Be careful — this {target_word} shows warning signs.",
        "SAFE": f"This {target_word} looks safe.",
    }.get(verdict, f"I could not fully analyze this {target_word} — treat it as not cleared.")


def _verdict_lines(result: dict, target_word: str) -> list:
    """Shared verdict/score/reasons wording for URL and message replies."""
    verdict = str(result.get("verdict") or "UNKNOWN").upper()
    score = int(result.get("risk_score", result.get("score", 0)) or 0)

    line = f"Verdict: {verdict} — risk score {score}/100"
    conf = _confidence_word(result.get("confidence"))
    if conf:
        line += f" ({conf} confidence)"
    lines = [_verdict_lead(verdict, target_word), line + "."]

    if result.get("plain_summary"):
        lines.append(str(result["plain_summary"]))

    reasons = result.get("flags") or result.get("reasons") or []
    if reasons:
        top = "; ".join(str(r) for r in reasons[:3])
        lines.append(f"Main reasons: {top}.")
    elif verdict == "SAFE":
        lines.append("None of our engines or threat feeds found threat signals. "
                     "No scanner is perfect — stay cautious with logins and payments.")
    return lines


def _scan_summary(result: dict, target: str) -> dict:
    return {
        "target": target,
        "verdict": str(result.get("verdict") or "UNKNOWN").upper(),
        "risk_score": int(result.get("risk_score", result.get("score", 0)) or 0),
        "confidence": result.get("confidence"),
    }


def bot_scan_reply(url: str, result: dict) -> dict:
    """Chat reply for a URL the bot scanned via the full pipeline."""
    lines = [f"I ran a full scan on {url}."] + _verdict_lines(result, "link")
    return {
        "matched": True,
        "confidence": 1.0,
        "question": None,
        "answer": "\n".join(lines),
        "related": list(_SCAN_RELATED),
        "action": "scanned_url",
        "scan": _scan_summary(result, url),
    }


def bot_message_reply(result: dict) -> dict:
    """Chat reply for a pasted message/email the bot analyzed."""
    lines = ["I analyzed the message you pasted."] + _verdict_lines(result, "message")
    return {
        "matched": True,
        "confidence": 1.0,
        "question": None,
        "answer": "\n".join(lines),
        "related": list(_SCAN_RELATED),
        "action": "scanned_message",
        "scan": _scan_summary(result, "pasted message"),
    }


def bot_quota_reply() -> dict:
    """Polite chat answer when the caller is over the daily scan quota —
    the bot never surfaces a raw 429 in the conversation."""
    return {
        "matched": True,
        "confidence": 1.0,
        "question": None,
        "answer": (
            "You've reached today's free scan limit, so I can't run this scan "
            "right now. Sign in for a higher daily limit, or upgrade to Premium "
            "for unlimited scans — I can still answer questions about the tools."
        ),
        "related": ["What is the difference between Free and Premium?"],
        "action": "quota",
    }
