"""
A batch row must not wait for a screenshot it will never show.

A batch keeps verdict, score, confidence, sources and summary per row. The
urlscan.io screenshot and the ML "why" explanation are dropped. Yet every
non-allowlisted row still submitted a urlscan job and polled up to 5 s for
the picture. That is most of the time behind the ~7 s p90 row, and it used up
the urlscan quota (HTTP 429 on 2026-10-09).

Measured on 100 test-pack URLs, 2026-10-09: with previews 49.9 s, p90 row
7.3 s; without them 19.9 s, p90 row 2.6 s. Verdicts were identical
(73 SAFE / 24 MALICIOUS / 3 SUSPICIOUS).

Neither preview feeds the score; both are display only.
"""

import asyncio

import pytest

import aggregator as agg

main = pytest.importorskip("main")

CLEAN = {"status": "clean", "detail": "not listed"}


def _stub(monkeypatch, calls, written):
    async def _a(value):
        return dict(value)

    async def urlscan(u):
        calls.append("urlscan")
        return dict(agg._FB_URLSCAN)

    def explain(u, top_n=5):
        calls.append("explain")
        return None

    monkeypatch.setattr(agg, "_resolve_chain",
                        lambda u, **kw: {"chain": [u], "final": u, "loop": False,
                                         "truncated": False, "html": None,
                                         "blocked_scheme": False})
    monkeypatch.setattr(agg, "_resolve_ip", lambda d: "203.0.113.10")
    monkeypatch.setattr(agg, "check_virustotal", lambda u: {**CLEAN, "raw_positives": 0})
    monkeypatch.setattr(agg, "check_safe_browsing", lambda u: _a(CLEAN))
    monkeypatch.setattr(agg, "check_web_risk", lambda u: _a(CLEAN))
    monkeypatch.setattr(agg, "check_urlhaus", lambda u: _a(CLEAN))
    monkeypatch.setattr(agg, "check_phish_feeds", lambda u: _a({**CLEAN, "match": None}))
    monkeypatch.setattr(agg, "check_geo", lambda d: _a(agg._FB_GEO))
    monkeypatch.setattr(agg, "check_ssl_cert", lambda d: _a(agg._FB_SSL))
    monkeypatch.setattr(agg, "check_whois", lambda d: _a(agg._FB_WHOIS))
    monkeypatch.setattr(agg, "check_urlscan", urlscan)
    monkeypatch.setattr(agg, "_explain_url", explain)
    monkeypatch.setattr(agg, "analyze_page_content", lambda u, html=None: dict(agg._FB_CONTENT))
    monkeypatch.setattr(agg, "cache_get", lambda k: None)
    monkeypatch.setattr(agg, "cache_put", lambda k, v, ttl=None: written.append(k))


# A host that is not on any allowlist, so urlscan would normally run.
URL = "https://ordinary-looking.example/"


def test_a_normal_scan_still_gets_its_previews(monkeypatch):
    calls, written = [], []
    _stub(monkeypatch, calls, written)
    asyncio.run(agg.full_scan(URL))
    assert "urlscan" in calls and "explain" in calls
    assert any(k.startswith("scan:") for k in written)


def test_without_previews_no_screenshot_or_explanation_is_fetched(monkeypatch):
    calls, written = [], []
    _stub(monkeypatch, calls, written)
    r = asyncio.run(agg.full_scan(URL, previews=False))
    assert calls == []
    assert r["verdict"] == "SAFE"
    assert r["screenshot_url"] is None and r["explainability"] is None


def test_a_result_without_previews_is_not_cached(monkeypatch):
    # Otherwise a later single scan of the same URL would be served the
    # picture-less copy for an hour.
    calls, written = [], []
    _stub(monkeypatch, calls, written)
    asyncio.run(agg.full_scan(URL, previews=False))
    assert not any(k.startswith("scan:") for k in written)


def test_the_batch_asks_for_no_previews(monkeypatch):
    seen = []

    async def fake_scan(url, **kw):
        seen.append(kw)
        return {"url": url, "verdict": "SAFE", "risk_score": 0}

    monkeypatch.setattr(main, "full_scan", fake_scan)
    monkeypatch.setattr(main, "save_scan", lambda *a, **k: None)
    jid = "np" + str(len(main._BATCH_JOBS))
    main._BATCH_JOBS[jid] = main._new_batch_job(jid, user_id=1, targets=["https://a.example"])
    asyncio.run(main._run_batch(jid, ["https://a.example"], 1))
    assert seen == [{"previews": False}]
