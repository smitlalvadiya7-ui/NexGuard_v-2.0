import ipaddress
import os
import re
import math

from urllib.parse import urlparse, unquote
from apis.virustotal import check_virustotal
from provider_domains import is_provider_domain
from top_domains import (is_established_registrable_host, is_top_registrable_host,
                         registrable_of)

# Optional ML classifier (loads lazily; falls back gracefully if missing)
try:
    from ml.predict import ml_phishing_probability
except Exception:
    try:
        from ml import predict as _ml
        ml_phishing_probability = _ml.ml_phishing_probability
    except Exception:
        def ml_phishing_probability(_url):
            return None

URL_RE = re.compile(
    r"https?://[^\s<>\"']+|www\.[^\s<>\"']+",
    re.IGNORECASE
)

TRUSTED_DOMAINS = {
    "google.com", "gmail.com", "youtube.com", "microsoft.com",
    "office.com", "live.com", "apple.com", "amazon.com",
    "paypal.com", "gov.uk", "github.com", "openai.com",
    "linkedin.com", "facebook.com", "instagram.com",
}

BRANDS = {
    "paypal":    ["paypal.com"],
    # Official INFRA roots (googleapis.com, amazonaws.com) are listed as legit:
    # the platform's own hostname is not impersonation — tenant-content stores
    # on them (GCS / S3 buckets) are judged on content, and a bogus
    # "impersonates google/amazon" hit would otherwise corroborate keyword
    # signals that must stay gated (see aggregator tenant_lexical_uncorroborated).
    "google":    ["google.com", "gmail.com", "googleapis.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com"],
    "apple":     ["apple.com"],
    "amazon":    ["amazon.com", "amazonaws.com"],
    "facebook":  ["facebook.com"],
    "instagram": ["instagram.com"],
    "netflix":   ["netflix.com"],
    "hsbc":      ["hsbc.co.uk", "hsbc.com"],
    "barclays":  ["barclays.co.uk"],
    "lloyds":    ["lloydsbank.com"],
    "wallet":    [],
    "bank":      [],
}

# A shortener hides the real destination, so the scanner must follow it rather
# than judge the shortener's own (reputable) domain. Audit 2026-07-27:
# goo.su/lVUOJ — a live phishing link — scored 0 because the list held only
# nine entries. Keep this broad: a false "this is a shortener" costs one extra
# redirect resolution, a miss costs the whole verdict.
SHORTENERS = {
    "bit.ly", "bitly.com", "tinyurl.com", "goo.gl", "goo.su", "t.co",
    "ow.ly", "is.gd", "cutt.ly", "rebrand.ly", "qrco.de",
    "shorturl.at", "rb.gy", "t.ly", "s.id", "shorte.st", "adf.ly",
    "buff.ly", "lnkd.in", "tiny.cc", "shrtco.de", "clck.ru",
    "v.gd", "trib.al", "soo.gd", "u.to", "bl.ink", "short.io",
    "linktr.ee", "cutt.us", "1url.com", "urlz.fr", "shorturl.com",
    "tr.im", "x.gd", "gg.gg", "shrturi.com", "urlis.net",
    "short.gy", "kutt.it", "dub.sh", "spoo.me", "tinylink.in",
}

SUSPICIOUS_TLDS = (
    ".ru", ".tk", ".xyz", ".top", ".gq",
    ".ml", ".cf", ".work", ".click", ".zip",
)

KEYWORD_WEIGHTS = {
    "login": 10, "signin": 8, "verify": 14, "secure": 8, "update": 2,
    "confirm": 10, "blocked": 16, "suspended": 16, "password": 25,
    "otp": 28, "cvv": 30, "pin": 18, "kyc": 20, "wallet": 18,
    "bank": 18, "payment": 12, "refund": 10, "free": 8, "gift": 10,
    "urgent": 15, "crypto": 15, "bitcoin": 15, "airdrop": 16,
    "malicious": 60, "phishing": 60, "scam": 50, "fake": 28, "testing-site": 45,
}

EMAIL_LANGUAGE_WEIGHTS = {
    "act now": 14, "immediately": 12, "within 24 hours": 14,
    "final warning": 18, "verify your account": 22, "click below": 12,
    "security alert": 18, "unusual activity": 18, "unauthorized": 14,
}


# ---------------------------------------------------------------------------
# URL utilities
# ---------------------------------------------------------------------------

def _clean_url(url: str) -> str:
    url = unquote((url or "").strip())
    if url and not url.startswith(("http://", "https://")):
        if "." in url:
            url = "https://" + url
    return url


def _domain_from_url(url: str) -> str:
    parsed = urlparse(url)
    domain = (parsed.netloc or parsed.path).lower().split("@")[-1].split(":")[0]
    return domain[4:] if domain.startswith("www.") else domain


def _root_domain(domain: str) -> str:
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


_HOST_LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
_TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")


def is_valid_host(host: str) -> bool:
    """
    A hostname a browser could actually visit: an IP literal, or dot-separated
    DNS labels ending in an alphabetic (or punycode) TLD. Unicode hosts are
    checked in their IDNA form. Rejects what the 2026-09-29 test-pack batch
    scanned as "URLs": comment text ('rules and (if keys are set) ...'),
    hosts with a trailing inline comment ('www.apple.com    '), and bare
    numbers ('0.001').
    """
    host = (host or "").rstrip(".").lower()   # no strip(): whitespace is invalid
    if not host or any(c.isspace() for c in host):
        return False
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    if re.fullmatch(r"[\d.]+", host):
        return False                      # '0.001', '1.2.3' — not an IP, not a name
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    labels = host.split(".")
    if len(labels) < 2 or len(host) > 253:
        return False
    return (all(_HOST_LABEL_RE.match(label) for label in labels[:-1])
            and bool(_TLD_RE.match(labels[-1])))


def is_valid_scan_url(url: str) -> bool:
    """True for an http(s) URL (scheme optional) whose host is_valid_host."""
    url = (url or "").strip()
    if not url:
        return False
    parsed = urlparse(url if "://" in url else "https://" + url)
    if parsed.scheme not in ("http", "https"):
        return False
    try:
        host = parsed.hostname
    except ValueError:
        return False
    return is_valid_host(host or "")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def _add(reasons, reason, score, amount):
    reasons.append(reason)
    return score + amount


def verdict_from_score(score: int) -> str:
    # Consistent thresholds across ALL modules (FIX 5): >=70 MALICIOUS,
    # 40-69 SUSPICIOUS, <40 SAFE.
    if score >= 70:
        return "MALICIOUS"
    if score >= 40:
        return "SUSPICIOUS"
    return "SAFE"


def _dedupe(items):
    seen = set()
    out = []
    for item in items:
        if item and item not in seen:
            out.append(item)
            seen.add(item)
    return out


# ---------------------------------------------------------------------------
# Core heuristic engine (no network I/O)
# ---------------------------------------------------------------------------

def _heuristic_core(url: str) -> dict:
    """
    Pure rule-based + local ML analysis. No external network calls.
    Returns intermediate state consumed by both analyze_url and heuristic_scan.
    """
    url = _clean_url(url)
    domain = _domain_from_url(url)
    root = _root_domain(domain)
    lower_url = url.lower()
    parsed = urlparse(url)
    score = 0
    flags = []

    if not url or "." not in domain:
        return {
            "valid": False, "url": url, "domain": domain,
            "score": 0, "flags": ["Invalid URL format"],
            "trusted": False, "ml_prob": None,
        }

    trusted = domain in TRUSTED_DOMAINS or root in TRUSTED_DOMAINS

    if parsed.scheme == "http":
        score = _add(flags, "URL uses insecure HTTP", score, 14)
    if domain in SHORTENERS or root in SHORTENERS:
        score = _add(flags, "Shortened URL detected", score, 32)
    # A provider's own TLD is not suspicious (dzen.ru / yandex.ru are the
    # allowlisted platforms themselves — live FP 2026-07-14: this +40 alone
    # crosses the SUSPICIOUS threshold). Famous registrables get the same
    # pass (eval FP 2026-07-16: mail.ru at SUSPICIOUS 40 on its TLD alone).
    if (any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
            and not is_provider_domain(domain)
            and not is_top_registrable_host(domain)):
        score = _add(flags, "Suspicious domain extension", score, 40)
    if "@" in url:
        score = _add(flags, "URL contains @ symbol", score, 35)
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", domain):
        score = _add(flags, "IP address used as domain", score, 30)
    if domain.count("-") >= 2:
        score = _add(flags, "Multiple hyphens in domain", score, 12)
    if len(domain) > 34:
        score = _add(flags, "Unusually long domain", score, 10)
    if _entropy(domain.replace(".", "")) > 3.8 and len(domain) > 18:
        score = _add(flags, "Random-looking domain pattern", score, 12)

    for word, amount in KEYWORD_WEIGHTS.items():
        if word in lower_url:
            score = _add(flags, f"Suspicious keyword: {word}", score, amount)

    # A provider's own hostname (googletagmanager.com, microsoftonline.com,
    # apple-dns.net, …) embeds its own brand by construction — that is not
    # impersonation. Same rationale as the googleapis/amazonaws legit_roots.
    # Famous registrables get the same pass (eval FP 2026-07-16:
    # amazon-adsystem.com — Amazon's own ad CDN — read as 'impersonation:
    # amazon'), and so do ESTABLISHED registrables (BUG-4 benchmark FP
    # 2026-07-18: microsoftazuread-sso.com — Microsoft's real Azure-AD SSO
    # domain — read as 'impersonation: microsoft'); tenant pages on popular
    # platforms keep their PSL label and are NOT exempted.
    if (not is_provider_domain(domain) and not is_top_registrable_host(domain)
            and not is_established_registrable_host(domain)):
        for brand, legit_roots in BRANDS.items():
            if brand in domain and root not in legit_roots and domain not in legit_roots:
                score = _add(flags, f"Possible impersonation: {brand}", score, 50)

    login_words = ["login", "signin", "verify", "secure", "account", "password"]
    value_words = ["paypal", "bank", "wallet", "amazon", "google", "otp"]
    # An OFFICIAL platform's own name is not phishing vocabulary: when the
    # registrable root is a known-legit brand root (googleapis.com,
    # amazonaws.com, ...), value words are matched against the attacker-chosen
    # parts only (subdomain + path) — otherwise EVERY GCS/S3 URL containing
    # 'login' would self-corroborate via the 'google'/'amazon' in the
    # platform's hostname. A value word in an attacker-chosen domain
    # (paypal-login.xyz) still matches as before.
    official_root = any(root in roots for roots in BRANDS.values())
    value_haystack = lower_url.replace(root, "") if official_root else lower_url
    # The same holds for any brand's OWN first-party domain, listed or not:
    # the 'bank' in secure.bankofamerica.com is the bank's name, not bait.
    # FP 2026-09-29: that page scored SUSPICIOUS 62, because this rule fired
    # on the domain itself and, as a strong flag, switched off the
    # reputable-host cap. Only the registrable is removed — a value word in
    # the path, or the brand used as a subdomain of someone else's domain
    # (bankofamerica.com.verify-account.tk), still counts.
    if (is_provider_domain(domain) or is_top_registrable_host(domain)
            or is_established_registrable_host(domain)):
        own = registrable_of(domain)
        if own:
            value_haystack = value_haystack.replace(own, "")
    if any(x in lower_url for x in login_words) and any(y in value_haystack for y in value_words):
        score = _add(flags, "Login combined with financial terms", score, 26)

    if trusted:
        score = max(0, score - 20)
        flags.append("Known domain reduces risk")

    ml_prob = ml_phishing_probability(url)

    return {
        "valid": True, "url": url, "domain": domain,
        "score": score, "flags": _dedupe(flags),
        "trusted": trusted, "ml_prob": ml_prob,
    }


def heuristic_scan(url: str) -> dict:
    """
    Public entry point for the aggregator.
    Returns heuristic score + ML probability with no network I/O.
    Safe to call via asyncio.to_thread().
    """
    return _heuristic_core(url)


# ---------------------------------------------------------------------------
# Full synchronous scan (used by QR / email / screenshot paths)
# ---------------------------------------------------------------------------

def analyze_url(url: str) -> dict:
    """
    Heuristics + VT (sync) + ML blend.
    Kept for non-/scan routes that call it directly.
    The /scan endpoint uses aggregator.full_scan() instead.
    """
    core = _heuristic_core(url)

    if not core["valid"]:
        return {
            "url": core["url"],
            "verdict": "ERROR",
            "risk_score": 0,
            "score": 0,
            "reasons": core["flags"],
            "ai_explanation": "Please enter a valid URL.",
        }

    url = core["url"]
    domain = core["domain"]
    score = core["score"]
    reasons = list(core["flags"])
    trusted = core["trusted"]
    ml_prob = core["ml_prob"]

    vt = check_virustotal(url)
    if vt["status"] == "flag":
        score = _add(reasons, f"VirusTotal: {vt['detail']}", score, 50)
    elif vt["status"] == "warn":
        score = _add(reasons, f"VirusTotal: {vt['detail']}", score, 20)

    # ML blend: final = 0.55 * ML + 0.45 * heuristic (unchanged formula)
    if ml_prob is not None and not trusted:
        ml_score = ml_prob * 100
        score = int(round(0.55 * ml_score + 0.45 * score))
        reasons.append(f"ML model phishing probability: {int(round(ml_prob * 100))}%")

    score = max(0, min(100, int(score)))
    verdict = verdict_from_score(score)

    return {
        "url": url,
        "domain": domain,
        "verdict": verdict,
        "risk_score": score,
        "score": score,
        "ml_probability": round(ml_prob, 4) if ml_prob is not None else None,
        "reasons": _dedupe(reasons),
        "ai_explanation": "; ".join(_dedupe(reasons)) if reasons else "No major suspicious URL indicators detected.",
    }


# ---------------------------------------------------------------------------
# Email / text analysis
# ---------------------------------------------------------------------------

def analyze_ai(text: str) -> dict:
    text = text or ""
    lower = text.lower()
    score = 0
    reasons = []

    urls = [_clean_url(u) for u in URL_RE.findall(text)]

    keyword_score = 0
    for phrase, amount in EMAIL_LANGUAGE_WEIGHTS.items():
        if phrase in lower:
            keyword_score = _add(reasons, f"Suspicious email language: {phrase}", keyword_score, amount)

    for word, amount in KEYWORD_WEIGHTS.items():
        if word in lower:
            keyword_score = _add(reasons, f"Suspicious keyword: {word}", keyword_score, min(amount, 18))

    # URL-derived risk is tracked separately from the body keyword bag so callers
    # (e.g. the email analyzer) can include the meaningful link risk WITHOUT the
    # noisy keyword inflation that flags legitimate mail (FIX 4).
    url_score = 0
    for u in urls:
        analysis = analyze_url(u)
        url_score += int(analysis.get("risk_score", 0))
        for r in analysis.get("reasons", []):
            reasons.append(f"URL indicator: {r}")

    score = min(100, int(keyword_score + url_score))
    verdict = verdict_from_score(score)
    reasons = _dedupe(reasons)

    return {
        "score": score,
        "risk_score": score,
        "keyword_score": min(100, int(keyword_score)),
        "url_score": min(100, int(url_score)),
        "verdict": verdict,
        "reasons": reasons,
        "urls": urls,
        "ai_explanation": "; ".join(reasons) if reasons else "No strong suspicious indicators found.",
    }
