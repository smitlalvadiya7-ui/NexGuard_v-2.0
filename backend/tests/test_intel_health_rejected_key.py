"""
A key the source REJECTS must not be reported as a working source.

intel_health was written on the principle that "a key is configured" is not the
same as "a source is usable". It then decided usability from key PRESENCE
alone — the same blind spot, one level deeper.

Real failure, 2026-08-19. `URLHAUS_AUTH_KEY` held a well-formed 48-character
key that abuse.ch answered with `403 unknown_auth_key` on every single scan.
Both operator-facing reports said it was fine:

    startup   Reputation sources reachable: VirusTotal, Safe Browsing, URLHaus
    check_env OK URLHAUS_AUTH_KEY  set (48 chars)

while every scan returned `intel_unavailable: ["URLHaus"]`. Nothing was lying;
both were answering "is a key present?" and printing it as "is the source
reachable?".

These tests drive the real intel_health against real breaker state.
"""

import logging

import pytest

import deployment_profile as dp
import intel_health
from apis import circuit_breaker
from apis.circuit_breaker import SourceAuthRejected, guarded


@pytest.fixture
def noncommercial(monkeypatch):
    monkeypatch.setenv("NEXGUARD_DEPLOYMENT_PROFILE", "noncommercial")
    dp.profile.cache_clear()
    circuit_breaker.reset_all()
    yield monkeypatch
    circuit_breaker.reset_all()
    dp.profile.cache_clear()


def keys(monkeypatch, **overrides):
    """Give every reputation source a key, then apply overrides."""
    env = {
        "GOOGLE_WEB_RISK_API_KEY": "",
        "VIRUSTOTAL_API_KEY": "vt-key",
        "GOOGLE_SAFEBROWSING_API_KEY": "gsb-key",
        "URLHAUS_AUTH_KEY": "uh-key",
    }
    env.update(overrides)
    for k, v in env.items():
        monkeypatch.setenv(k, v)


def reject(breaker_name):
    """Drive a real auth rejection through the real breaker."""
    def fn():
        raise SourceAuthRejected("403 unknown_auth_key")
    guarded(breaker_name, fn, fallback={"status": "unavailable"})


# ---------------------------------------------------------------------------
# Reporting a rejected key
# ---------------------------------------------------------------------------

class TestRejectedKeyIsReported:

    def test_a_rejected_key_is_named_as_rejected(self, noncommercial):
        keys(noncommercial)
        reject("urlhaus")
        assert "URLHaus" in intel_health.reputation_status()["rejected_key"]

    def test_a_rejected_key_is_not_counted_usable(self, noncommercial):
        keys(noncommercial)
        reject("urlhaus")
        assert "URLHaus" not in intel_health.reputation_status()["usable"]

    def test_a_present_working_key_is_still_usable(self, noncommercial):
        keys(noncommercial)
        reject("urlhaus")
        assert "VirusTotal" in intel_health.reputation_status()["usable"]

    def test_a_rejected_key_is_not_reported_as_missing(self, noncommercial):
        """'Missing' sends the operator to create a key they already have."""
        keys(noncommercial)
        reject("urlhaus")
        assert "URLHaus" not in intel_health.reputation_status()["missing_key"]

    def test_nothing_is_rejected_when_every_key_works(self, noncommercial):
        keys(noncommercial)
        assert intel_health.reputation_status()["rejected_key"] == []

    def test_a_merely_failing_source_is_not_called_rejected(self, noncommercial):
        """An outage is not a bad key — don't send the operator key-hunting."""
        keys(noncommercial)
        guarded("urlhaus", lambda: (_ for _ in ()).throw(RuntimeError("timeout")),
                fallback={"status": "unavailable"})
        assert intel_health.reputation_status()["rejected_key"] == []


# ---------------------------------------------------------------------------
# It counts toward blindness
# ---------------------------------------------------------------------------

class TestBlindness:

    def test_rejected_primary_keys_make_the_scanner_blind(self, noncommercial):
        keys(noncommercial)
        reject("virustotal")
        reject("safe_browsing")
        assert intel_health.reputation_status()["blind"] is True

    def test_a_rejected_secondary_key_alone_is_not_blindness(self, noncommercial):
        keys(noncommercial)
        reject("urlhaus")
        assert intel_health.reputation_status()["blind"] is False

    def test_the_warning_names_the_rejected_source(self, noncommercial):
        keys(noncommercial)
        reject("virustotal")
        reject("safe_browsing")
        assert "VirusTotal" in intel_health.warning_text()

    def test_the_warning_says_the_key_was_rejected_not_missing(self, noncommercial):
        keys(noncommercial)
        reject("virustotal")
        reject("safe_browsing")
        assert "rejected" in intel_health.warning_text().lower()


# ---------------------------------------------------------------------------
# The startup line
# ---------------------------------------------------------------------------

class TestStartupLine:

    def messages(self, caplog):
        return " | ".join(r.getMessage() for r in caplog.records)

    def test_startup_does_not_claim_reachable_before_calling_anything(
            self, noncommercial, caplog):
        """At boot nothing has been queried. 'Reachable' is a claim the process
        has no evidence for — and it is exactly the claim that hid this bug."""
        keys(noncommercial)
        with caplog.at_level(logging.INFO):
            intel_health.log_startup_warning()
        assert "reachable" not in self.messages(caplog).lower()

    def test_startup_says_the_keys_are_configured(self, noncommercial, caplog):
        keys(noncommercial)
        with caplog.at_level(logging.INFO):
            intel_health.log_startup_warning()
        assert "configured" in self.messages(caplog).lower()

    def test_a_rejected_key_is_shouted_at_startup(self, noncommercial, caplog):
        keys(noncommercial)
        reject("urlhaus")
        with caplog.at_level(logging.INFO):
            intel_health.log_startup_warning()
        assert "URLHaus" in self.messages(caplog)
