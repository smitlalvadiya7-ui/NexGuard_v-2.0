"""
Deterministic test of the threat-intelligence fusion in aggregator.full_scan.

We stub every network source so the scan is offline and reproducible, then drive
three scenarios and assert the fused verdict:

  1. New domain + login form + brand impersonation        -> MALICIOUS (escalated)
  2. Old, reputable-age domain with the same page content  -> not escalated (FP-safe)
  3. All enrichment unavailable (breakers/feeds down)      -> fails neutral, no crash

Run:  python -m eval.test_threat_intel
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

import aggregator  # noqa: E402


def _stub_sources(monkey: dict):
    """Patch aggregator's source bindings with deterministic stubs."""
    async def _async(val):
        return val

    aggregator._resolve_chain = lambda url, **k: {
        "chain": [url], "final": url, "loop": False, "truncated": False,
        "html": None, "blocked_scheme": False,
    }
    aggregator._resolve_ip = lambda d: "203.0.113.50"
    aggregator.heuristic_scan = lambda url: {
        "score": 20, "flags": [], "ml_prob": 0.40, "trusted": False,
    }
    aggregator.check_virustotal = lambda url: {"status": "clean", "detail": "not listed"}
    aggregator.check_safe_browsing = lambda url: _async({"status": "clean", "detail": "not listed"})
    aggregator.check_urlhaus = lambda url: _async({"status": "clean", "detail": "clean"})
    aggregator.check_phish_feeds = lambda url: _async(
        {"status": "clean", "detail": "clean", "match": None})
    aggregator.check_typosquatting = lambda d: monkey["typo"]
    aggregator.analyze_page_content = lambda url, html=None: monkey["content"]
    aggregator.check_whois = lambda d: _async(monkey["whois"])
    aggregator.check_geo = lambda d: _async({"ip_location": "X", "ip_country": "X",
                                             "asn": "AS00000 Example", "hosting": "BulletproofHost"})
    aggregator.check_ssl_cert = lambda d: _async(monkey["ssl"])
    aggregator.check_urlscan = lambda url: _async(aggregator._FB_URLSCAN.copy())
    aggregator._explain_url = lambda url, top_n=5: None


PHISH_CONTENT = {
    **aggregator._FB_CONTENT,
    "has_password_field": True, "has_login_form": True,
    "brand_mismatch": True, "title_brand_mismatch": True,
    "suspicious_signals": ["Page presents 'paypal' branding"],
    "content_risk": 60, "fetched": True,
}
NEUTRAL_CONTENT = {**aggregator._FB_CONTENT, "fetched": True}
NO_TYPO = {"is_typosquat": False, "impersonated_brand": None, "technique": None, "confidence": 0}
FREE_NEW_CERT = {
    "has_cert": True, "issuer": "Let's Encrypt", "is_free_ca": True,
    "issued": "2026-06-05", "expires": "2026-09-05", "cert_age_days": 6,
    "days_to_expiry": 86, "san_count": 1, "subject_cn": "x", "detail": "free CA",
}


def scenario(name: str, monkey: dict, url: str) -> dict:
    _stub_sources(monkey)
    aggregator.cache_get = lambda k: None          # bypass result cache
    aggregator.cache_put = lambda k, v: None
    res = asyncio.run(aggregator.full_scan(url))
    print(f"\n[{name}] {url}")
    print(f"  verdict={res['verdict']} score={res['risk_score']} "
          f"escalated={res['threat_intel']['escalated']} "
          f"is_new_domain={res['threat_intel']['is_new_domain']}")
    rel = [f for f in res["flags"] if "Escalated" in f or "New" in f or "new" in f]
    for f in rel:
        print(f"    flag: {f}")
    return res


def main():
    ok = True

    # 1. New domain + login + brand mismatch -> MALICIOUS
    r1 = scenario("new+login+brand", {
        "whois": {"registrar": "NameSilo", "age": "8 d", "age_days": 8, "created": "x", "country": "X"},
        "ssl": FREE_NEW_CERT, "content": PHISH_CONTENT, "typo": NO_TYPO,
    }, "https://paypal-secure-verify.tk/login")
    if r1["verdict"] != "MALICIOUS" or not r1["threat_intel"]["escalated"]:
        print("  FAIL: expected MALICIOUS + escalated"); ok = False
    else:
        print("  PASS")

    # 2. Old domain, same content -> NOT escalated by threat-intel
    r2 = scenario("old-domain-same-content", {
        "whois": {"registrar": "MarkMonitor", "age": "12 yr", "age_days": 4400, "created": "x", "country": "US"},
        "ssl": {**FREE_NEW_CERT, "is_free_ca": False, "cert_age_days": 200, "issuer": "DigiCert"},
        "content": PHISH_CONTENT, "typo": NO_TYPO,
    }, "https://example-oldsite.com/login")
    if r2["threat_intel"]["escalated"]:
        print("  FAIL: old domain must not trigger new-domain escalation"); ok = False
    else:
        print("  PASS")

    # 3. Enrichment unavailable -> neutral, no crash
    r3 = scenario("enrichment-unavailable", {
        "whois": dict(aggregator._FB_WHOIS), "ssl": dict(aggregator._FB_SSL),
        "content": NEUTRAL_CONTENT, "typo": NO_TYPO,
    }, "https://some-unknown-site.example/page")
    if r3["threat_intel"]["is_new_domain"] or r3["threat_intel"]["escalated"]:
        print("  FAIL: missing enrichment must fail neutral"); ok = False
    else:
        print("  PASS")

    print("\n" + ("ALL PASSED" if ok else "FAILURES PRESENT"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
