"""
A rejected API key is permanent, and the breaker must treat it as permanent.

Real failure, 2026-08-19. A running deployment answered every scan with
`intel_unavailable: ["URLHaus"]` while the startup banner announced URLHaus as
reachable. abuse.ch was returning:

    403  {"query_status": "unknown_auth_key"}

The key was simply not one abuse.ch knows. The breaker classified that with
outages: two attempts and a backoff sleep on every scan, then OPEN for the
cooldown, then another probe, forever. No amount of retrying turns an unknown
key into a known one, so every one of those calls was latency spent on an
answer that could not change.

A transient failure and a rejected credential need different handling, which is
what `SourceAuthRejected` marks. These tests drive the real breaker — nothing
here asserts on a mock.
"""

import pytest

from apis import circuit_breaker
from apis.circuit_breaker import (
    SourceAuthRejected,
    SourceUnavailable,
    guarded,
    snapshot_all,
)

FALLBACK = {"status": "unavailable", "detail": "unavailable"}


@pytest.fixture(autouse=True)
def _clean_registry():
    """Each test gets its own breaker state; a leaked OPEN breaker would make
    later tests pass for the wrong reason (fallback returned, fn never run)."""
    circuit_breaker.reset_all()
    yield
    circuit_breaker.reset_all()


def rejecting(calls):
    def fn():
        calls.append(1)
        raise SourceAuthRejected("URLHaus 403 unknown_auth_key")
    return fn


def flaky(calls):
    def fn():
        calls.append(1)
        raise SourceUnavailable("URLHaus HTTP 503")
    return fn


# ---------------------------------------------------------------------------
# A rejection is not retried
# ---------------------------------------------------------------------------

class TestNoRetry:

    def test_a_rejected_key_is_attempted_once(self):
        calls = []
        guarded("src", rejecting(calls), fallback=FALLBACK)
        assert len(calls) == 1

    def test_a_transient_failure_is_still_retried(self):
        """Guards the change above from over-reaching onto real outages."""
        calls = []
        guarded("src", flaky(calls), fallback=FALLBACK)
        assert len(calls) == 2

    def test_a_rejection_still_returns_the_neutral_fallback(self):
        result = guarded("src", rejecting([]), fallback=FALLBACK)
        assert result == FALLBACK

    def test_a_rejection_never_raises_to_the_caller(self):
        """The breaker's whole contract: one bad source cannot fail a scan."""
        guarded("src", rejecting([]), fallback=FALLBACK)


# ---------------------------------------------------------------------------
# A rejection is permanent
# ---------------------------------------------------------------------------

class TestPermanence:

    def test_later_calls_never_reach_a_rejected_source(self):
        calls = []
        fn = rejecting(calls)
        for _ in range(6):
            guarded("src", fn, fallback=FALLBACK)
        assert len(calls) == 1

    def test_the_cooldown_does_not_re_probe_a_rejected_key(self, monkeypatch):
        monkeypatch.setattr(circuit_breaker, "COOLDOWN_S", 0.0)
        calls = []
        fn = rejecting(calls)
        guarded("src", fn, fallback=FALLBACK)
        guarded("src", fn, fallback=FALLBACK)
        assert len(calls) == 1

    def test_a_normal_outage_still_heals_after_the_cooldown(self, monkeypatch):
        """The counterpart: self-healing must survive for real outages."""
        monkeypatch.setattr(circuit_breaker, "COOLDOWN_S", 0.0)
        monkeypatch.setattr(circuit_breaker, "FAIL_THRESHOLD", 1)
        calls = []
        fn = flaky(calls)
        guarded("src", fn, fallback=FALLBACK, retries=0)
        guarded("src", fn, fallback=FALLBACK, retries=0)
        assert len(calls) == 2

    def test_one_rejected_source_does_not_silence_another(self):
        rejected, healthy = [], []
        guarded("bad", rejecting(rejected), fallback=FALLBACK)
        guarded("good", lambda: healthy.append(1) or {"status": "clean"},
                fallback=FALLBACK)
        guarded("good", lambda: healthy.append(1) or {"status": "clean"},
                fallback=FALLBACK)
        assert len(healthy) == 2


# ---------------------------------------------------------------------------
# Saying so
# ---------------------------------------------------------------------------

class TestReporting:

    def test_the_snapshot_marks_the_source_rejected(self):
        guarded("src", rejecting([]), fallback=FALLBACK)
        snap = {b["name"]: b for b in snapshot_all()}["src"]
        assert snap["auth_rejected"] is True

    def test_the_snapshot_keeps_the_reason(self):
        guarded("src", rejecting([]), fallback=FALLBACK)
        snap = {b["name"]: b for b in snapshot_all()}["src"]
        assert "unknown_auth_key" in (snap["last_error"] or "")

    def test_a_healthy_source_is_not_marked_rejected(self):
        guarded("src", lambda: {"status": "clean"}, fallback=FALLBACK)
        snap = {b["name"]: b for b in snapshot_all()}["src"]
        assert snap["auth_rejected"] is False

    def test_a_merely_failing_source_is_not_marked_rejected(self):
        guarded("src", flaky([]), fallback=FALLBACK)
        snap = {b["name"]: b for b in snapshot_all()}["src"]
        assert snap["auth_rejected"] is False

    def test_rejected_sources_are_listed_by_name(self):
        guarded("urlhaus", rejecting([]), fallback=FALLBACK)
        assert "urlhaus" in circuit_breaker.auth_rejected_sources()

    def test_nothing_is_listed_when_no_key_was_rejected(self):
        guarded("urlhaus", flaky([]), fallback=FALLBACK)
        assert circuit_breaker.auth_rejected_sources() == set()
