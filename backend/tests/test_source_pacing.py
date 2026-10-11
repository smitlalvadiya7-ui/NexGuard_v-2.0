"""
A rate-limited source must never hold a worker thread longer than the scan
will wait for it.

Measured 2026-09-29 on the 200-URL test pack: 89 rows came back UNKNOWN 0%,
including paypal-secure-login.xyz (ML 1.0). The quota limiter made every
VirusTotal call sleep up to 45 s for a token INSIDE a worker thread, but
full_scan only waits 2.2 s for VirusTotal and then moves on — the thread kept
sleeping. Eight concurrent scans filled the 20-thread default pool with
sleepers, so Safe Browsing, DNS and even the local ML model queued behind them
and timed out. Replayed offline with every network call faked to succeed
instantly: 86 UNKNOWN with the shipped waits, 0 with the VirusTotal wait off.

Rules these tests pin down:
  * no token -> no request, and the answer says "rate-limited" honestly;
  * an OPEN breaker answers instantly — it never waits for a token first;
  * a source's default token wait fits inside the scan's per-source budget;
  * a URL VirusTotal has never seen costs ONE request, not a submit + polls.
"""

import time

import pytest

import aggregator as agg
from apis import circuit_breaker as cb
from apis import quota


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


def _forbid(*a, **k):
    raise AssertionError("a request was sent although no token was available")


def _drain(source):
    """Spend every token in `source`'s bucket."""
    b = quota._bucket(source)
    with b.lock:
        b.tokens = 0.0
        b.updated = time.monotonic()


def _open_breaker(name):
    for _ in range(cb.FAIL_THRESHOLD):
        cb.get_breaker(name)._on_failure("test")
    assert cb.is_open(name)


class _Resp:
    def __init__(self, code, js=None):
        self.status_code, self._js = code, js or {}

    def json(self):
        return self._js

    def raise_for_status(self):
        pass


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

class TestVirusTotalPacing:
    @pytest.fixture(autouse=True)
    def _vt(self, monkeypatch):
        from apis import virustotal
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "a-real-looking-key")
        monkeypatch.setattr(virustotal, "cache_get", lambda k: None)
        monkeypatch.setattr(virustotal, "cache_put", lambda k, v, ttl=None: None)
        monkeypatch.setenv("NEXGUARD_QUOTA_VIRUSTOTAL_PER_MIN", "1")
        monkeypatch.setenv("NEXGUARD_QUOTA_VIRUSTOTAL_WAIT", "0.3")
        self.vt = virustotal

    def test_no_token_means_no_request(self, monkeypatch):
        monkeypatch.setattr(self.vt.requests, "get", _forbid)
        monkeypatch.setattr(self.vt.requests, "post", _forbid)
        _drain("virustotal")
        res = self.vt.check_virustotal("http://x.example/")
        assert res["status"] == "unavailable"
        assert "rate" in res["detail"].lower()

    def test_an_open_breaker_never_waits_for_a_token(self, monkeypatch):
        monkeypatch.setenv("NEXGUARD_QUOTA_VIRUSTOTAL_WAIT", "5")
        monkeypatch.setattr(self.vt.requests, "get", _forbid)
        _drain("virustotal")
        _open_breaker("virustotal")
        t0 = time.monotonic()
        res = self.vt.check_virustotal("http://x.example/")
        assert time.monotonic() - t0 < 0.5, "slept for a token the breaker would discard"
        assert res["status"] == "unavailable"

    def test_an_open_breaker_does_not_spend_a_token(self, monkeypatch):
        monkeypatch.setattr(self.vt.requests, "get", _forbid)
        _open_breaker("virustotal")
        before = quota._bucket("virustotal").tokens
        self.vt.check_virustotal("http://x.example/")
        assert quota._bucket("virustotal").tokens == pytest.approx(before, abs=0.05)

    def test_an_unseen_url_costs_one_request(self, monkeypatch):
        """404 used to trigger a submit plus up to ~4 analysis polls (6 s) on a
        single token — guaranteed 429s at 4/min, and never inside 2.2 s."""
        gets = []
        monkeypatch.setattr(self.vt.requests, "get",
                            lambda *a, **k: gets.append(a) or _Resp(404))
        monkeypatch.setattr(self.vt.requests, "post", _forbid)
        res = self.vt.check_virustotal("http://never-seen.example/")
        assert len(gets) == 1
        assert res["status"] == "unavailable"
        assert "not yet" in res["detail"].lower()

    def test_a_known_url_still_answers(self, monkeypatch):
        monkeypatch.setattr(self.vt.requests, "get", lambda *a, **k: _Resp(
            200, {"data": {"attributes": {"last_analysis_stats":
                                          {"malicious": 5, "harmless": 60}}}}))
        assert self.vt.check_virustotal("http://x.example/")["status"] == "flag"


# ---------------------------------------------------------------------------
# Google (Safe Browsing v4 / Web Risk)
# ---------------------------------------------------------------------------

class TestSafeBrowsingPacing:
    @pytest.fixture(autouse=True)
    def _sb(self, monkeypatch):
        from apis import safe_browsing
        monkeypatch.setenv("GOOGLE_SAFEBROWSING_API_KEY", "a-real-looking-key")
        monkeypatch.setattr(safe_browsing, "cache_get", lambda k: None)
        monkeypatch.setattr(safe_browsing, "cache_put", lambda k, v, ttl=None: None)
        monkeypatch.setenv("NEXGUARD_QUOTA_SAFE_BROWSING_PER_MIN", "1")
        monkeypatch.setenv("NEXGUARD_QUOTA_SAFE_BROWSING_WAIT", "0.3")
        self.sb = safe_browsing

    def test_no_token_means_no_request(self, monkeypatch):
        monkeypatch.setattr(self.sb._HTTP, "post", _forbid)
        _drain("safe_browsing")
        res = self.sb._check_sync("http://x.example/")
        assert res["status"] == "unavailable"
        assert "rate" in res["detail"].lower()

    def test_an_open_breaker_never_waits_for_a_token(self, monkeypatch):
        monkeypatch.setenv("NEXGUARD_QUOTA_SAFE_BROWSING_WAIT", "5")
        monkeypatch.setattr(self.sb._HTTP, "post", _forbid)
        _drain("safe_browsing")
        _open_breaker("safe_browsing")
        t0 = time.monotonic()
        self.sb._check_sync("http://x.example/")
        assert time.monotonic() - t0 < 0.5


class TestWebRiskPacing:
    def test_no_token_means_no_request(self, monkeypatch):
        from apis import web_risk
        monkeypatch.setenv("GOOGLE_WEB_RISK_API_KEY", "a-real-looking-key")
        monkeypatch.setattr(web_risk, "cache_get", lambda k: None, raising=False)
        monkeypatch.setattr(web_risk.requests, "get", _forbid)
        monkeypatch.setenv("NEXGUARD_QUOTA_WEB_RISK_PER_MIN", "1")
        monkeypatch.setenv("NEXGUARD_QUOTA_WEB_RISK_WAIT", "0.3")
        _drain("web_risk")
        res = web_risk._check_sync("http://x.example/")
        assert res["status"] == "unavailable"


# ---------------------------------------------------------------------------
# Defaults fit the scan's budget
# ---------------------------------------------------------------------------

def test_urlscan_stops_polling_when_full_scan_stops_waiting():
    """urlscan is enrichment: full_scan cancels it after ENRICH_BUDGET_S, but a
    20 s poll loop kept its thread busy long after — on every non-allowlisted
    URL of a batch."""
    from apis import urlscan
    assert urlscan._POLL_DEADLINE_S < agg.ENRICH_BUDGET_S


@pytest.mark.parametrize("source", ["virustotal", "safe_browsing", "web_risk"])
def test_default_token_wait_fits_inside_the_scan_budget(source, monkeypatch):
    """A thread that waits longer than full_scan waits for its answer is a
    thread nobody is waiting for — it only blocks the pool."""
    monkeypatch.delenv(f"NEXGUARD_QUOTA_{source.upper()}_WAIT", raising=False)
    monkeypatch.delenv(f"NEXGUARD_QUOTA_{source.upper()}_PER_MIN", raising=False)
    assert quota._bucket(source).max_wait_s < agg.CRIT_BUDGET_S
