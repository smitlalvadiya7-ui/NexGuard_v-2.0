"""
The licence gate, enforced where the scan actually happens.

`deployment_profile.py` declares what each build may use. These tests check the
scan path OBEYS it — because a policy that only exists in a constants file is a
policy that gets bypassed the first time someone adds a source.

Commercial build:
    Web Risk           reputation (licensed, 100k lookups/month free)
    Phishing.Database  community feed
    URLhaus            community feed
    user's own VT key  optional, called as the user
  BLOCKED: VirusTotal Public, Safe Browsing v4, OpenPhish

Non-commercial build: everything above plus the three blocked sources.

A blocked source reports "unavailable", never "clean". "We are not licensed to
check this" is not the same claim as "we checked and it was fine" — that
conflation is what made a 190,542-domain malicious corpus scan 73% SAFE.
"""

import asyncio

import pytest

import deployment_profile as dp


@pytest.fixture
def commercial(monkeypatch):
    # Set it explicitly rather than deleting it: deleting falls back to the
    # BUILD's default, which differs between the commercial and non-commercial
    # deliverables, and a test must not change meaning depending on which
    # folder it runs in.
    monkeypatch.setenv("NEXGUARD_DEPLOYMENT_PROFILE", "commercial")
    dp.profile.cache_clear()
    yield
    dp.profile.cache_clear()


@pytest.fixture
def noncommercial(monkeypatch):
    monkeypatch.setenv("NEXGUARD_DEPLOYMENT_PROFILE", "noncommercial")
    dp.profile.cache_clear()
    yield
    dp.profile.cache_clear()


# ---------------------------------------------------------------------------
# VirusTotal public
# ---------------------------------------------------------------------------

class TestVirusTotalGate:
    def test_commercial_build_does_not_call_virustotal(self, commercial, monkeypatch):
        """Not merely 'returns unavailable' — the request must never leave the
        machine, because making it is the licence violation."""
        from apis import virustotal

        called = []
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "a-real-looking-key")
        monkeypatch.setattr(virustotal.requests, "get",
                            lambda *a, **k: called.append(a) or (_ for _ in ()).throw(
                                AssertionError("VirusTotal was called in a commercial build")))
        res = virustotal.check_virustotal("http://x.example/")
        assert called == []
        assert res["status"] == "unavailable"

    def test_the_reason_names_the_licence(self, commercial):
        from apis import virustotal
        res = virustotal.check_virustotal("http://x.example/")
        assert "licence" in res["detail"].lower() or "license" in res["detail"].lower()

    def test_noncommercial_build_still_uses_virustotal(self, noncommercial, monkeypatch):
        from apis import virustotal

        monkeypatch.setattr(virustotal, "cache_get", lambda k: None)
        monkeypatch.setattr(virustotal, "cache_put", lambda k, v, ttl=None: None)
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "a-real-looking-key")

        class Resp:
            status_code = 200

            @staticmethod
            def json():
                return {"data": {"attributes": {"last_analysis_stats":
                        {"malicious": 5, "harmless": 60}}}}

        monkeypatch.setattr(virustotal.requests, "get", lambda *a, **k: Resp())
        res = virustotal.check_virustotal("http://x.example/")
        assert res["status"] == "flag"


# ---------------------------------------------------------------------------
# Safe Browsing v4
# ---------------------------------------------------------------------------

class TestSafeBrowsingGate:
    def test_commercial_build_does_not_call_safe_browsing(self, commercial, monkeypatch):
        from apis import safe_browsing

        monkeypatch.setenv("GOOGLE_SAFEBROWSING_API_KEY", "a-real-looking-key")
        monkeypatch.setattr(safe_browsing._HTTP, "post",
                            lambda *a, **k: (_ for _ in ()).throw(
                                AssertionError("Safe Browsing v4 called in a commercial build")))
        res = asyncio.run(safe_browsing.check_safe_browsing("http://x.example/"))
        assert res["status"] == "unavailable"

    def test_web_risk_is_the_commercial_replacement(self, commercial):
        assert dp.is_allowed("web_risk") is True
        assert dp.is_allowed("safe_browsing_v4") is False


# ---------------------------------------------------------------------------
# OpenPhish
# ---------------------------------------------------------------------------

class TestOpenPhishGate:
    def test_commercial_build_excludes_openphish_from_the_feed_list(self, commercial):
        from apis import phish_feeds
        names = {f.label for f in phish_feeds.active_feeds()}
        assert "OpenPhish" not in names

    def test_commercial_build_keeps_the_permissive_feeds(self, commercial):
        from apis import phish_feeds
        names = {f.label for f in phish_feeds.active_feeds()}
        assert "Phishing.Database" in names

    def test_noncommercial_build_includes_openphish(self, noncommercial):
        from apis import phish_feeds
        names = {f.label for f in phish_feeds.active_feeds()}
        assert "OpenPhish" in names

    def test_the_full_feed_table_is_unchanged(self, commercial):
        """active_feeds() filters; FEEDS stays the complete catalogue so the
        non-commercial build has something to enable."""
        from apis import phish_feeds
        assert any(f.label == "OpenPhish" for f in phish_feeds.FEEDS)


# ---------------------------------------------------------------------------
# The scan payload tells the operator which build is running
# ---------------------------------------------------------------------------

class TestDisclosure:
    def test_health_reports_the_profile(self, commercial):
        text = dp.describe()
        assert "COMMERCIAL" in text
        assert "VirusTotal" in text and "OpenPhish" in text

    def test_blocked_sources_are_enumerable(self, commercial):
        assert set(dp.blocked_sources()) == {
            "virustotal_public", "safe_browsing_v4", "openphish"}
