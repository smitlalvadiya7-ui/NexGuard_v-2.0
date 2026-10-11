"""
The scanner must never be quietly blind.

What happened on 2026-07-30: a user scanned a file of 190,542 known-malicious
domains through their own running tool and every one came back SAFE. The code
was correct and the tests were green. The cause was configuration — the
`commercial` deployment profile blocks VirusTotal, Safe Browsing and OpenPhish
by licence, and `GOOGLE_WEB_RISK_API_KEY`, the source that replaces all three,
had not been created yet.

So the tool had **no reputation source at all**, and nothing said so. It started
normally, answered /health with "ok", and returned confident-looking SAFE
verdicts. The same 60-domain sample scored 26.7% in that state and 96.7% with
sources reachable.

That is the defect these tests exist for. Not the licence gate — that is correct
and deliberate — but the SILENCE around it. A scanner with nothing to check
against is a broken scanner, and it has to say so loudly enough that nobody
spends an evening wondering why their tool trusts a phishing corpus.
"""

import pytest

import deployment_profile as dp
import intel_health


@pytest.fixture
def commercial(monkeypatch):
    monkeypatch.setenv("NEXGUARD_DEPLOYMENT_PROFILE", "commercial")
    dp.profile.cache_clear()
    yield monkeypatch
    dp.profile.cache_clear()


@pytest.fixture
def noncommercial(monkeypatch):
    monkeypatch.setenv("NEXGUARD_DEPLOYMENT_PROFILE", "noncommercial")
    dp.profile.cache_clear()
    yield monkeypatch
    dp.profile.cache_clear()


def blind(monkeypatch):
    """No key for any reputation source."""
    for key in ("GOOGLE_WEB_RISK_API_KEY", "VIRUSTOTAL_API_KEY",
                "GOOGLE_SAFEBROWSING_API_KEY", "URLHAUS_AUTH_KEY"):
        monkeypatch.setenv(key, "")


# ---------------------------------------------------------------------------
# Detecting it
# ---------------------------------------------------------------------------

class TestDetection:
    def test_commercial_build_without_web_risk_has_no_reputation_source(self, commercial):
        blind(commercial)
        status = intel_health.reputation_status()
        assert status["usable"] == []
        assert status["blind"] is True

    def test_a_web_risk_key_makes_it_not_blind(self, commercial):
        blind(commercial)
        commercial.setenv("GOOGLE_WEB_RISK_API_KEY", "AIza-a-real-looking-key")
        status = intel_health.reputation_status()
        assert "Web Risk" in status["usable"]
        assert status["blind"] is False

    def test_noncommercial_build_with_virustotal_is_not_blind(self, noncommercial):
        blind(noncommercial)
        noncommercial.setenv("VIRUSTOTAL_API_KEY", "a-real-looking-key")
        status = intel_health.reputation_status()
        assert "VirusTotal" in status["usable"]
        assert status["blind"] is False

    def test_a_licence_blocked_key_does_not_count(self, commercial):
        """
        The exact trap. VIRUSTOTAL_API_KEY was present and valid the whole time
        — 64 characters of working key — but the commercial profile refuses to
        call it. A key that will never be used must not count as coverage.
        """
        blind(commercial)
        commercial.setenv("VIRUSTOTAL_API_KEY", "a-real-looking-key")
        commercial.setenv("GOOGLE_SAFEBROWSING_API_KEY", "another-real-one")
        status = intel_health.reputation_status()
        assert status["blind"] is True, (
            "keys blocked by licence are not coverage — this is what made a "
            "known-malicious corpus scan as SAFE")
        assert "VirusTotal" in status["blocked_by_licence"]


# ---------------------------------------------------------------------------
# Saying it
# ---------------------------------------------------------------------------

class TestTheWarning:
    def test_the_warning_names_the_cause_and_the_fix(self, commercial):
        blind(commercial)
        text = intel_health.warning_text()
        assert text
        assert "GOOGLE_WEB_RISK_API_KEY" in text, "must name the key to create"
        assert "commercial" in text.lower(), "must name the profile responsible"

    def test_the_warning_says_what_it_means_for_verdicts(self, commercial):
        blind(commercial)
        text = intel_health.warning_text().lower()
        assert "safe" in text, "must say SAFE verdicts cannot be trusted"

    def test_there_is_no_warning_when_a_source_is_usable(self, commercial):
        blind(commercial)
        commercial.setenv("GOOGLE_WEB_RISK_API_KEY", "AIza-a-real-looking-key")
        assert intel_health.warning_text() == ""

    def test_it_is_logged_at_startup(self, commercial, caplog):
        """A warning nobody prints is not a warning."""
        import logging

        blind(commercial)
        with caplog.at_level(logging.WARNING):
            intel_health.log_startup_warning()
        assert any("GOOGLE_WEB_RISK_API_KEY" in r.message for r in caplog.records)

    def test_startup_stays_quiet_when_healthy(self, commercial, caplog):
        import logging

        blind(commercial)
        commercial.setenv("GOOGLE_WEB_RISK_API_KEY", "AIza-a-real-looking-key")
        with caplog.at_level(logging.WARNING):
            intel_health.log_startup_warning()
        assert not [r for r in caplog.records if "reputation" in r.message.lower()]


# ---------------------------------------------------------------------------
# Exposing it
# ---------------------------------------------------------------------------

class TestHealthEndpoint:
    def test_health_reports_the_blind_state(self, commercial):
        blind(commercial)
        status = intel_health.reputation_status()
        assert set(status) >= {"blind", "usable", "blocked_by_licence",
                              "missing_key", "profile"}

    def test_the_profile_is_named_so_the_cause_is_obvious(self, commercial):
        blind(commercial)
        assert intel_health.reputation_status()["profile"] == "commercial"

    def test_a_source_with_no_key_is_reported_as_missing_key(self, commercial):
        blind(commercial)
        assert "Web Risk" in intel_health.reputation_status()["missing_key"]


# ---------------------------------------------------------------------------
# URLHaus is not coverage
#
# The first version of this check counted any licensed source with a key, so a
# deployment with only URLHaus reported "Reputation sources reachable: URLHaus"
# and stayed quiet — while still catching almost nothing.
#
# Measured across three diagnostic runs over 180 known-malicious domains:
#
#     VirusTotal flagged   58 / 18 / 60
#     Safe Browsing        13 /  6 / 15
#     URLHaus               0 /  0 /  0
#
# URLHaus is a malware-distribution feed with narrow, deliberate scope. It is
# worth querying and it is not a phishing reputation source, so it cannot be
# what stands between a user and a blind scanner.
# ---------------------------------------------------------------------------

class TestUrlhausIsNotCoverage:
    def test_urlhaus_alone_still_counts_as_blind(self, commercial):
        blind(commercial)
        commercial.setenv("URLHAUS_AUTH_KEY", "a-real-looking-key")
        status = intel_health.reputation_status()
        assert status["blind"] is True, (
            "URLHaus flagged 0 of 180 known-malicious domains; it cannot be the "
            "only thing standing between a user and an unchecked verdict")

    def test_urlhaus_is_still_reported_as_usable(self, commercial):
        """Not coverage, but not hidden either — it does contribute."""
        blind(commercial)
        commercial.setenv("URLHAUS_AUTH_KEY", "a-real-looking-key")
        assert "URLHaus" in intel_health.reputation_status()["usable"]

    def test_the_warning_still_fires_with_only_urlhaus(self, commercial):
        blind(commercial)
        commercial.setenv("URLHAUS_AUTH_KEY", "a-real-looking-key")
        assert "GOOGLE_WEB_RISK_API_KEY" in intel_health.warning_text()

    def test_a_primary_source_clears_the_warning(self, commercial):
        blind(commercial)
        commercial.setenv("URLHAUS_AUTH_KEY", "a-real-looking-key")
        commercial.setenv("GOOGLE_WEB_RISK_API_KEY", "AIza-a-real-looking-key")
        assert intel_health.warning_text() == ""
        assert intel_health.reputation_status()["blind"] is False

    def test_primary_sources_are_named_in_the_status(self, commercial):
        blind(commercial)
        commercial.setenv("URLHAUS_AUTH_KEY", "a-real-looking-key")
        status = intel_health.reputation_status()
        assert status["usable_primary"] == []
        assert "URLHaus" in status["usable"]
