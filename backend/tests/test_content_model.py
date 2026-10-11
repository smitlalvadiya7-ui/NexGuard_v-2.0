"""
M2 — content-signal model: a second, page-level model that turns the
structured features from apis/page_content.py into a calibrated phishing
probability, blended into fusion as its own channel. The channel is
OPINION-GATED like reputation: a bland/unfetched page is NEUTRAL (phishing
kits often serve empty shells to static scanners — absence of signals must
never exonerate URL evidence).

Judged by the real-world eval (eval.realworld_eval), per the plan's rule.
"""

import asyncio

import pytest

content_model = pytest.importorskip("ml.content_model")
agg = pytest.importorskip("aggregator")

from ml.content_model import (  # noqa: E402
    CONTENT_ACTIVE_PROB,
    content_phishing_probability,
)


def content(**overrides):
    c = dict(agg._FB_CONTENT)
    c["fetched"] = True
    c.update(overrides)
    return c


LOGIN_ONLY = dict(has_password_field=True, has_login_form=True)
KIT = dict(
    has_password_field=True,
    has_login_form=True,
    external_form_action=True,
    brand_mismatch=True,
    title_brand_mismatch=True,
    login_keywords_near_form=True,
    suspicious_signals=["Form submits credentials to external domain 'evil.tk'",
                        "Credential-harvesting wording in/around the login form"],
)


# ---------------------------------------------------------------------------
# The model itself
# ---------------------------------------------------------------------------

def test_no_page_means_no_opinion():
    assert content_phishing_probability(None) is None
    assert content_phishing_probability({"fetched": False}) is None
    assert content_phishing_probability({}) is None          # no fetched key


def test_clean_fetched_page_scores_very_low():
    p = content_phishing_probability(content())
    assert p is not None and p < 0.10


def test_ordinary_login_page_stays_below_conviction():
    # Most login pages are legitimate — password+login alone must not convict.
    p = content_phishing_probability(content(**LOGIN_ONLY))
    assert p < 0.5


def test_login_plus_brand_mismatch_is_high():
    p = content_phishing_probability(
        content(**LOGIN_ONLY, brand_mismatch=True,
                suspicious_signals=["Page presents 'paypal' branding"]))
    assert p > 0.6


def test_full_credential_kit_is_near_certain():
    p = content_phishing_probability(content(**KIT))
    assert p > 0.95


def test_each_added_signal_raises_the_probability():
    base = content_phishing_probability(content(**LOGIN_ONLY))
    plus_action = content_phishing_probability(
        content(**LOGIN_ONLY, external_form_action=True))
    plus_brand = content_phishing_probability(
        content(**LOGIN_ONLY, external_form_action=True, brand_mismatch=True))
    assert base < plus_action < plus_brand


def test_resource_fanout_contribution_is_capped():
    a = content_phishing_probability(content(external_resource_count=10))
    b = content_phishing_probability(content(external_resource_count=500))
    assert b - a < 0.05          # runaway counts cannot dominate


def test_junk_input_never_raises():
    p = content_phishing_probability(
        {"fetched": True, "external_resource_count": "lots",
         "suspicious_signals": None, "has_password_field": "yes"})
    assert p is None or 0.0 <= p <= 1.0


# ---------------------------------------------------------------------------
# Blending into fusion
# ---------------------------------------------------------------------------

def test_weighted_score_without_content_is_unchanged():
    # Backward compatibility: existing behavior when the channel is absent.
    assert agg._weighted_score(40, None, 0, False) == 40
    assert agg._weighted_score(40, None, 0, False, None) == 40


def test_content_channel_raises_the_blend():
    base = agg._weighted_score(20, None, 0, False)
    with_content = agg._weighted_score(20, None, 0, False, 0.9)
    assert with_content > base
    # (0.25*20 + 0.30*90) / 0.55 total weight = 58.2 -> 58
    assert with_content == 58


def test_content_channel_bounds():
    assert agg._weighted_score(0, None, 0, False, 0.0) == 0
    assert agg._weighted_score(100, 1.0, 100, True, 1.0) == 100


# ---------------------------------------------------------------------------
# full_scan integration (network stubbed, local analysis real)
# ---------------------------------------------------------------------------

@pytest.fixture
def patched_sources(monkeypatch):
    state = {
        "vt": {"status": "clean", "detail": "0 engines", "raw_positives": 0},
        "gsb": {"status": "clean", "detail": ""},
        "uh": {"status": "clean", "detail": ""},
        "feeds": {"status": "clean", "detail": "", "match": None},
        "content": dict(agg._FB_CONTENT),
        "whois": dict(agg._FB_WHOIS),
    }

    async def _async(key):
        return state[key]

    monkeypatch.setattr(agg, "_resolve_chain", lambda url, **kw: {
        "chain": [url], "final": url, "loop": False, "truncated": False,
        "html": None, "blocked_scheme": False,
    })
    monkeypatch.setattr(agg, "_resolve_ip", lambda d: "203.0.113.10")
    monkeypatch.setattr(agg, "check_virustotal", lambda u: state["vt"])
    monkeypatch.setattr(agg, "check_safe_browsing", lambda u: _async("gsb"))
    monkeypatch.setattr(agg, "check_urlhaus", lambda u: _async("uh"))
    monkeypatch.setattr(agg, "check_phish_feeds", lambda u: _async("feeds"))
    monkeypatch.setattr(agg, "analyze_page_content", lambda u, html=None: state["content"])
    monkeypatch.setattr(agg, "check_whois", lambda d: _async("whois"))

    async def _geo(d):
        return dict(agg._FB_GEO)

    async def _sslcert(d):
        return dict(agg._FB_SSL)

    async def _urlscan(u):
        return dict(agg._FB_URLSCAN)

    monkeypatch.setattr(agg, "check_geo", lambda d: _geo(d))
    monkeypatch.setattr(agg, "check_ssl_cert", lambda d: _sslcert(d))
    monkeypatch.setattr(agg, "check_urlscan", lambda u: _urlscan(u))
    monkeypatch.setattr(agg, "cache_get", lambda u: None)
    monkeypatch.setattr(agg, "cache_put", lambda u, r: None)
    return state


def scan(url):
    return asyncio.run(agg.full_scan(url))


def test_result_exposes_content_probability(patched_sources):
    patched_sources["content"] = content(**KIT, content_risk=85)
    result = scan("https://some-random-shop.com/account")
    assert result["content_probability"] is not None
    assert result["content_probability"] > 0.9
    assert result["verdict"] in ("SUSPICIOUS", "MALICIOUS")


def test_unfetched_page_has_no_content_probability(patched_sources):
    result = scan("https://quiet-unknown-domain.com/")
    assert result["content_probability"] is None


def test_bland_page_is_neutral_not_exonerating(patched_sources):
    # A fetched page with no signals must not dilute other evidence:
    # probability is reported, but the below-threshold channel stays neutral.
    patched_sources["content"] = content()
    result = scan("https://quiet-unknown-domain.com/")
    p = result["content_probability"]
    assert p is not None and p < CONTENT_ACTIVE_PROB
    assert result["verdict"] == "SAFE"


def test_credential_kit_on_unknown_domain_convicts(patched_sources):
    patched_sources["content"] = content(**KIT, content_risk=85)
    result = scan("https://login-update-portal.com/secure")
    assert result["verdict"] == "MALICIOUS"
    assert result["risk_score"] >= 70


# ---------------------------------------------------------------------------
# BUG-4 (2026-07-18) — brand on its OWN domain label is not a mismatch
# ---------------------------------------------------------------------------

_DHL_LOGIN_HTML = (
    "<html><head><title>DHL Paket — Login</title></head><body>"
    "<h1>DHL Kundenkonto</h1>"
    "<form action='/login'><input type='password' name='pw'/></form>"
    "</body></html>"
)


def test_brand_on_its_own_label_is_not_a_mismatch():
    # dhl.de presents DHL branding: the registrable's own label IS the brand.
    # Whether dhl.de is DHL's real domain is the typosquat/reputation
    # channels' establishment-aware question — not a content "mismatch".
    from apis.page_content import analyze_page_content
    res = analyze_page_content("https://www.dhl.de/de/privatkunden.html",
                               html=_DHL_LOGIN_HTML)
    assert res["brand_mismatch"] is False, res


def test_same_branding_on_a_foreign_label_still_mismatches():
    from apis.page_content import analyze_page_content
    res = analyze_page_content("https://secure-parcel-update.com/login",
                               html=_DHL_LOGIN_HTML)
    assert res["brand_mismatch"] is True, res
