"""
A batch row must not stay UNKNOWN just because the batch itself was busy.

Found 2026-10-09 with the 200-URL test pack (job 042cc5a9495c): 130 UNKNOWN,
6 SAFE. The live server's breakers showed no Safe Browsing or VirusTotal
failure at all. The lookups had simply not come back inside full_scan's 2.2 s
budget while the batch was busy, so most fresh rows took ~10 s (every budget
used up) and read "not checked". The same 200 URLs scanned again a few hours
later, with the same code, came back SAFE 133 / UNKNOWN 0.

Two things turned a slow moment into a wrong report:

  * an UNKNOWN row was final. Nothing looked at it again once the load was
    gone, so "the source was late" was reported as "no source could be
    reached";
  * an UNKNOWN result went into the 1-hour result cache. The cache guard
    compared `detail == "unavailable"`, but a rate-limited VirusTotal answer
    keeps status "unavailable" with a different detail, so the guard let it
    through. Two rows of that job (amazon.com, 1 ms) were such cache replays,
    and any re-run within the hour would have replayed the rest.
"""

import asyncio

import pytest

import aggregator as agg

main = pytest.importorskip("main")

UNAVAILABLE = {"status": "unavailable", "detail": "unavailable"}
RATE_LIMITED = {"status": "unavailable",
                "detail": "rate-limited — free-tier quota used up, not checked"}
CLEAN = {"status": "clean", "detail": "not listed"}


# ---------------------------------------------------------------------------
# The result cache
# ---------------------------------------------------------------------------

def _scan(monkeypatch, *, vt, gsb, urlhaus, url="https://ordinary-looking.example/"):
    """Real full_scan with every source stubbed; returns (result, cache keys written)."""
    monkeypatch.setattr(agg, "_resolve_chain",
                        lambda u, **kw: {"chain": [u], "final": u, "loop": False,
                                         "truncated": False, "html": None,
                                         "blocked_scheme": False})
    monkeypatch.setattr(agg, "_resolve_ip", lambda d: "203.0.113.10")
    monkeypatch.setattr(agg, "check_virustotal", lambda u: {**vt, "raw_positives": 0})

    async def _a(value):
        return dict(value)

    monkeypatch.setattr(agg, "check_safe_browsing", lambda u: _a(gsb))
    monkeypatch.setattr(agg, "check_web_risk", lambda u: _a(gsb))
    monkeypatch.setattr(agg, "check_urlhaus", lambda u: _a(urlhaus))
    monkeypatch.setattr(agg, "check_phish_feeds",
                        lambda u: _a({**UNAVAILABLE, "match": None}))
    monkeypatch.setattr(agg, "check_geo", lambda d: _a(agg._FB_GEO))
    monkeypatch.setattr(agg, "check_ssl_cert", lambda d: _a(agg._FB_SSL))
    monkeypatch.setattr(agg, "check_urlscan", lambda u: _a(agg._FB_URLSCAN))
    monkeypatch.setattr(agg, "check_whois", lambda d: _a(agg._FB_WHOIS))
    monkeypatch.setattr(agg, "analyze_page_content",
                        lambda u, html=None: dict(agg._FB_CONTENT))
    monkeypatch.setattr(agg, "_explain_url", lambda u, top_n=5: None)
    monkeypatch.setattr(agg, "cache_get", lambda k: None)
    written = []
    monkeypatch.setattr(agg, "cache_put", lambda k, v, ttl=None: written.append(k))
    result = asyncio.run(agg.full_scan(url))
    return result, [k for k in written if k.startswith("scan:")]


class TestResultCache:
    def test_a_rate_limited_source_counts_as_unavailable(self):
        assert agg._reputation_all_unavailable(RATE_LIMITED, UNAVAILABLE, UNAVAILABLE) is True

    def test_an_unknown_verdict_is_never_cached(self, monkeypatch):
        # URLHaus answered, so the "all unavailable" guard alone would not
        # stop this one: the verdict itself must.
        r, cached = _scan(monkeypatch, vt=RATE_LIMITED, gsb=UNAVAILABLE, urlhaus=CLEAN)
        assert r["verdict"] == "UNKNOWN"
        assert cached == [], "an UNKNOWN result was written to the result cache"

    def test_the_jobs_own_case_is_not_cached(self, monkeypatch):
        # What the live job actually had: VirusTotal rate-limited, Safe
        # Browsing late, URLHaus key rejected.
        r, cached = _scan(monkeypatch, vt=RATE_LIMITED, gsb=UNAVAILABLE, urlhaus=UNAVAILABLE)
        assert r["verdict"] == "UNKNOWN"
        assert cached == []

    def test_a_checked_safe_result_is_still_cached(self, monkeypatch):
        r, cached = _scan(monkeypatch, vt=RATE_LIMITED, gsb=CLEAN, urlhaus=UNAVAILABLE)
        assert r["verdict"] == "SAFE"
        assert cached, "a real, checked verdict should still be cached"


# ---------------------------------------------------------------------------
# The batch re-check
# ---------------------------------------------------------------------------

def _job(targets):
    job_id = "rc" + str(len(main._BATCH_JOBS)) + str(id(targets))[-6:]
    main._BATCH_JOBS[job_id] = main._new_batch_job(job_id, user_id=1, targets=targets)
    return job_id


def _run(monkeypatch, targets, scan, pause=0.0):
    saved = []
    monkeypatch.setattr(main, "_BATCH_RECHECK_PAUSE_S", pause)
    monkeypatch.setattr(main, "full_scan", scan)
    monkeypatch.setattr(main, "save_scan",
                        lambda module, res, target, user_id=None: saved.append((target, res["verdict"])))
    jid = _job(targets)
    asyncio.run(main._run_batch(jid, targets, 1))
    return main._batch_view(main._BATCH_JOBS[jid]), saved


class TestRecheck:
    def test_a_row_that_was_only_late_is_checked_again(self, monkeypatch):
        targets = ["https://a.example", "https://b.example", "https://c.example"]
        calls = {}

        async def scan(url, **kw):
            calls[url] = calls.get(url, 0) + 1
            # b.example's sources are late the first time only.
            verdict = "UNKNOWN" if (url == "https://b.example" and calls[url] == 1) else "SAFE"
            return {"url": url, "verdict": verdict, "risk_score": 0}

        view, saved = _run(monkeypatch, targets, scan)
        assert calls["https://b.example"] == 2
        assert calls["https://a.example"] == 1, "a row with a real answer is not re-scanned"
        assert view["counts"]["UNKNOWN"] == 0
        assert view["counts"]["SAFE"] == 3
        assert view["done"] == 3 and view["status"] == "completed"
        assert [r["url"] for r in view["results"]] == targets

    def test_history_gets_one_row_per_url_with_the_final_answer(self, monkeypatch):
        targets = ["https://a.example", "https://b.example"]
        first = {"https://b.example"}

        async def scan(url, **kw):
            if url in first:
                first.discard(url)
                return {"url": url, "verdict": "UNKNOWN", "risk_score": 0}
            return {"url": url, "verdict": "SAFE", "risk_score": 0}

        _, saved = _run(monkeypatch, targets, scan)
        assert sorted(saved) == [("https://a.example", "SAFE"), ("https://b.example", "SAFE")]

    def test_a_threat_found_on_the_recheck_is_reported(self, monkeypatch):
        targets = ["https://x.example"]
        n = {"calls": 0}

        async def scan(url, **kw):
            n["calls"] += 1
            v = "UNKNOWN" if n["calls"] == 1 else "MALICIOUS"
            return {"url": url, "verdict": v, "risk_score": 0 if v == "UNKNOWN" else 95}

        view, _ = _run(monkeypatch, targets, scan)
        assert view["counts"]["MALICIOUS"] == 1 and view["counts"]["UNKNOWN"] == 0
        assert view["results"][0]["risk_score"] == 95

    def test_sources_that_are_really_down_are_not_hammered(self, monkeypatch):
        # No key / outage: every re-check is UNKNOWN again. After a few the
        # batch stops re-checking and keeps the honest UNKNOWN.
        targets = [f"https://site{i}.example" for i in range(30)]
        calls = {"n": 0}

        async def scan(url, **kw):
            calls["n"] += 1
            return {"url": url, "verdict": "UNKNOWN", "risk_score": 0}

        view, saved = _run(monkeypatch, targets, scan)
        rechecks = calls["n"] - len(targets)
        assert 0 < rechecks <= main._BATCH_RECHECK_GIVE_UP + main._BATCH_RECHECK_CONCURRENCY
        assert view["counts"]["UNKNOWN"] == 30 and view["done"] == 30
        assert len(saved) == 30, "every URL still gets exactly one history row"

    def test_a_failed_recheck_keeps_the_first_answer(self, monkeypatch):
        targets = ["https://a.example"]
        n = {"calls": 0}

        async def scan(url, **kw):
            n["calls"] += 1
            if n["calls"] == 1:
                return {"url": url, "verdict": "UNKNOWN", "risk_score": 0}
            raise RuntimeError("boom")

        view, saved = _run(monkeypatch, targets, scan)
        assert view["counts"] == {**view["counts"], "UNKNOWN": 1, "ERROR": 0}
        assert saved == [("https://a.example", "UNKNOWN")]


class TestRecheckPacing:
    """
    The re-check must not outrun Safe Browsing's budget.

    Without screenshots a batch finishes in ~35 s. Safe Browsing's limiter
    (apis.quota) allows a burst of 120 lookups and then 2 a second, so the
    last ~10 rows of a fast main pass found it empty and read UNKNOWN. A
    re-check started at once found it still empty, gave up after 4 misses,
    and left 4 rows UNKNOWN (2026-10-09, job 541d79839e08). So the re-check
    first waits for the budget to refill, then spaces its lookups out.
    """

    def test_rechecks_wait_first_and_are_spaced_out(self, monkeypatch):
        import time
        targets = [f"https://r{i}.example" for i in range(4)]
        firsts = set()
        stamps = []

        async def scan(url, **kw):
            if url not in firsts:
                firsts.add(url)
                return {"url": url, "verdict": "UNKNOWN", "risk_score": 0}
            stamps.append(time.monotonic())
            return {"url": url, "verdict": "SAFE", "risk_score": 0}

        t0 = time.monotonic()
        view, _ = _run(monkeypatch, targets, scan, pause=0.05)
        assert view["counts"]["SAFE"] == 4 and view["counts"]["UNKNOWN"] == 0
        # waited before the first re-check ...
        assert stamps[0] - t0 >= 2 * 0.05
        # ... and no worker re-checks twice without a pause in between
        per_worker = main._BATCH_RECHECK_CONCURRENCY
        gaps = [b - a for a, b in zip(stamps, stamps[per_worker:])]
        assert all(g >= 0.05 for g in gaps)
