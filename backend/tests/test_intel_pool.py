"""
Reputation lookups must not wait in line behind slow work on the shared pool.

2026-10-09, job f99b9a2c461f, after the batch re-check was added: 6 of 200 rows
stayed UNKNOWN on both passes (youtube, microsoft, apple, instagram, linkedin,
x.com). Scanned on their own, the same URLs got a Safe Browsing answer in
0.02–0.5 s, and the breakers showed no failure. Each of those rows took ~10 s,
every budget used up.

VirusTotal, Safe Browsing and URLHaus ran through asyncio.to_thread(), which
is the event loop's one default pool (20 threads here). The same pool carries
page fetches, DNS lookups, RDAP retries and urlscan polls, and those keep
their thread after full_scan stops waiting for them. When the pool was full,
the lookup never started. full_scan's 2.2 s budget cancelled it in the queue,
and the row read "not checked".
"""

import asyncio
import threading

import pytest

import aggregator as agg
from apis import circuit_breaker as cb
from apis import quota, safe_browsing

CLEAN = {"status": "clean", "detail": "not listed"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    quota.reset()
    cb.reset_all()
    monkeypatch.setenv("NEXGUARD_DEPLOYMENT_PROFILE", "noncommercial")
    from deployment_profile import profile
    profile.cache_clear()
    yield
    quota.reset()
    cb.reset_all()
    profile.cache_clear()


def test_lookups_answer_while_the_default_pool_is_full(monkeypatch):
    async def _a(value):
        return dict(value)

    # Everything around the lookups is stubbed and quick; the lookups
    # themselves still go through their real executor path.
    monkeypatch.setattr(agg, "_resolve_chain",
                        lambda u, **kw: {"chain": [u], "final": u, "loop": False,
                                         "truncated": False, "html": None,
                                         "blocked_scheme": False})
    monkeypatch.setattr(agg, "_resolve_ip", lambda d: "203.0.113.10")
    monkeypatch.setattr(agg, "check_virustotal", lambda u: {**CLEAN, "raw_positives": 0})
    monkeypatch.setattr(safe_browsing, "_check_sync", lambda u: dict(CLEAN))
    monkeypatch.setattr(agg, "check_urlhaus", lambda u: _a(CLEAN))
    monkeypatch.setattr(agg, "check_phish_feeds", lambda u: _a({**CLEAN, "match": None}))
    monkeypatch.setattr(agg, "check_geo", lambda d: _a(agg._FB_GEO))
    monkeypatch.setattr(agg, "check_ssl_cert", lambda d: _a(agg._FB_SSL))
    monkeypatch.setattr(agg, "check_urlscan", lambda u: _a(agg._FB_URLSCAN))
    monkeypatch.setattr(agg, "check_whois", lambda d: _a(agg._FB_WHOIS))
    monkeypatch.setattr(agg, "analyze_page_content", lambda u, html=None: dict(agg._FB_CONTENT))
    monkeypatch.setattr(agg, "_explain_url", lambda u, top_n=5: None)
    monkeypatch.setattr(agg, "cache_get", lambda k: None)
    monkeypatch.setattr(agg, "cache_put", lambda k, v, ttl=None: None)
    monkeypatch.setattr(agg, "ENRICH_BUDGET_S", 0.2)

    async def scan_with_a_full_pool():
        loop = asyncio.get_running_loop()
        release = threading.Event()
        # More blocked jobs than the default pool has threads, the way slow
        # enrichment calls hold it during a busy batch.
        blockers = [loop.run_in_executor(None, release.wait, 30) for _ in range(64)]
        await asyncio.sleep(0.2)
        try:
            return await agg.full_scan("https://ordinary-looking.example/")
        finally:
            release.set()
            await asyncio.gather(*blockers)

    r = asyncio.run(scan_with_a_full_pool())
    src = {s["name"]: s for s in r["sources"]}
    assert src["Safe Browsing"]["status"] == "clean", "Safe Browsing waited behind the full pool"
    assert src["VirusTotal"]["status"] == "clean", "VirusTotal waited behind the full pool"
    assert src["URLHaus"]["status"] == "clean"
    assert r["verdict"] == "SAFE"


def test_the_pool_is_its_own(monkeypatch):
    """The lookups run on threads named for them, not the loop's default pool."""
    names = []

    def fake_sync(url):
        names.append(threading.current_thread().name)
        return dict(CLEAN)

    monkeypatch.setattr(safe_browsing, "_check_sync", fake_sync)
    asyncio.run(safe_browsing.check_safe_browsing("https://a.example/"))
    assert names and names[0].startswith("nexguard-intel")
