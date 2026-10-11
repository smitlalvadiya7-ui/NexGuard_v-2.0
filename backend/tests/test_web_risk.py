"""
Google Web Risk — the reputation source a paid build is allowed to use.

Safe Browsing v4 is "for non-commercial use only" and Google directs commercial
users here. Web Risk queries the same threat corpus, and its Lookup API is free
for the first 100,000 calls per month — roughly 3,300 scans a day, which covers
a launch.

This module is deliberately interface-compatible with apis/safe_browsing.py
({"status", "detail"}), so the aggregator swaps one import and nothing else
changes.

Every test here drives the real code with a stubbed HTTP transport. Nothing
reaches the network, and nothing asserts on the stub itself — the assertions are
about what NexGuard concludes from a given API response.
"""

import asyncio

import pytest

from apis import web_risk


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    """
    A key, no cache, and a CLOSED circuit breaker.

    The breaker reset matters: the failure tests below deliberately trip it, and
    a breaker left open would make later tests pass for the wrong reason —
    returning the fallback without ever calling the code under test.
    """
    from apis import circuit_breaker

    circuit_breaker._REGISTRY.pop("web_risk", None)
    monkeypatch.setenv("GOOGLE_WEB_RISK_API_KEY", "test-key")
    monkeypatch.setattr(web_risk, "cache_get", lambda k: None)
    monkeypatch.setattr(web_risk, "cache_put", lambda k, v, ttl=None: None)
    yield
    circuit_breaker._REGISTRY.pop("web_risk", None)


def check(url):
    return asyncio.run(web_risk.check_web_risk(url))


def stub(monkeypatch, response, record=None):
    def _get(api_url, params=None, timeout=None):
        if record is not None:
            record.append({"url": api_url, "params": params})
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(web_risk.requests, "get", _get)


# ---------------------------------------------------------------------------
# Reading the verdict
# ---------------------------------------------------------------------------

class TestVerdict:
    def test_a_listed_url_is_flagged_with_its_threat_type(self, monkeypatch):
        stub(monkeypatch, FakeResponse(200, {
            "threat": {"threatTypes": ["SOCIAL_ENGINEERING"],
                       "expireTime": "2026-07-29T12:00:00Z"}}))
        res = check("http://phishing.example/")
        assert res["status"] == "flag"
        assert "SOCIAL_ENGINEERING" in res["detail"]

    def test_multiple_threat_types_are_all_reported(self, monkeypatch):
        stub(monkeypatch, FakeResponse(200, {
            "threat": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"]}}))
        res = check("http://both.example/")
        assert res["status"] == "flag"
        assert "MALWARE" in res["detail"] and "SOCIAL_ENGINEERING" in res["detail"]

    def test_an_empty_response_means_not_listed(self, monkeypatch):
        """Web Risk returns {} — not a 404 — for a URL it has nothing on."""
        stub(monkeypatch, FakeResponse(200, {}))
        res = check("http://ordinary.example/")
        assert res["status"] == "clean"
        assert res["detail"] == "not listed"


# ---------------------------------------------------------------------------
# The request itself
# ---------------------------------------------------------------------------

class TestRequest:
    def test_it_asks_about_every_threat_type(self, monkeypatch):
        """Phishing is SOCIAL_ENGINEERING; omitting a type silently narrows
        what the scanner can ever detect."""
        seen = []
        stub(monkeypatch, FakeResponse(200, {}), record=seen)
        check("http://x.example/")
        types = seen[0]["params"]["threatTypes"]
        assert "SOCIAL_ENGINEERING" in types
        assert "MALWARE" in types
        assert "UNWANTED_SOFTWARE" in types

    def test_the_scanned_url_is_sent(self, monkeypatch):
        seen = []
        stub(monkeypatch, FakeResponse(200, {}), record=seen)
        check("http://specific-target.example/page")
        assert seen[0]["params"]["uri"] == "http://specific-target.example/page"

    def test_it_calls_web_risk_not_safe_browsing(self, monkeypatch):
        """The whole point of the module: a different, commercially licensed
        endpoint."""
        seen = []
        stub(monkeypatch, FakeResponse(200, {}), record=seen)
        check("http://x.example/")
        assert "webrisk.googleapis.com" in seen[0]["url"]
        assert "safebrowsing" not in seen[0]["url"]


# ---------------------------------------------------------------------------
# Failure — never "clean"
# ---------------------------------------------------------------------------

class TestFailureModes:
    def test_no_key_is_unavailable_not_clean(self, monkeypatch):
        monkeypatch.setenv("GOOGLE_WEB_RISK_API_KEY", "")
        res = check("http://x.example/")
        assert res["status"] == "unavailable"
        assert res["status"] != "clean"

    def test_placeholder_key_is_unavailable(self, monkeypatch):
        monkeypatch.setenv("GOOGLE_WEB_RISK_API_KEY", "your_key_here")
        res = check("http://x.example/")
        assert res["status"] == "unavailable"

    @pytest.mark.parametrize("code", [429, 500, 502, 503, 504])
    def test_transient_http_errors_are_unavailable(self, monkeypatch, code):
        """A quota exhaustion must read as 'could not check', which is exactly
        the confusion that made 190,542 malicious domains scan SAFE."""
        stub(monkeypatch, FakeResponse(code, {}))
        res = check("http://x.example/")
        assert res["status"] == "unavailable"

    def test_a_network_error_is_unavailable(self, monkeypatch):
        stub(monkeypatch, OSError("connection reset"))
        res = check("http://x.example/")
        assert res["status"] == "unavailable"

    def test_a_malformed_body_is_unavailable(self, monkeypatch):
        class Broken(FakeResponse):
            def json(self):
                raise ValueError("not json")

        stub(monkeypatch, Broken(200))
        res = check("http://x.example/")
        assert res["status"] == "unavailable"


# ---------------------------------------------------------------------------
# Quota care — 100k/month is generous, not infinite
# ---------------------------------------------------------------------------

class TestCaching:
    def test_a_clean_answer_is_cached(self, monkeypatch):
        puts = []
        monkeypatch.setattr(web_risk, "cache_put",
                            lambda k, v, ttl=None: puts.append((k, v)))
        stub(monkeypatch, FakeResponse(200, {}))
        check("http://x.example/")
        assert puts and puts[0][1]["status"] == "clean"

    def test_an_unavailable_answer_is_never_cached(self, monkeypatch):
        """Caching a failure would keep a source dark long after it recovered."""
        puts = []
        monkeypatch.setattr(web_risk, "cache_put",
                            lambda k, v, ttl=None: puts.append((k, v)))
        stub(monkeypatch, FakeResponse(503, {}))
        check("http://x.example/")
        assert puts == []

    def test_a_cached_answer_skips_the_network(self, monkeypatch):
        calls = []
        monkeypatch.setattr(web_risk, "cache_get",
                            lambda k: {"status": "flag", "detail": "cached"})
        stub(monkeypatch, FakeResponse(200, {}), record=calls)
        res = check("http://x.example/")
        assert res["detail"] == "cached"
        assert calls == [], "a cached verdict must not spend quota"


# ---------------------------------------------------------------------------
# Licensing
# ---------------------------------------------------------------------------

def test_web_risk_is_allowed_in_the_commercial_profile(monkeypatch):
    import deployment_profile as dp
    monkeypatch.setenv("NEXGUARD_DEPLOYMENT_PROFILE", "commercial")
    dp.profile.cache_clear()
    assert dp.profile() == dp.COMMERCIAL
    assert dp.is_allowed("web_risk") is True
    dp.profile.cache_clear()
