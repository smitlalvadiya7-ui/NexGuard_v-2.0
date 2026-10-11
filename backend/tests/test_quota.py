"""
Spend a source's quota instead of burning it.

Measured 2026-07-30: a 200-URL batch at 8 concurrent scans fired ~240
VirusTotal requests in the first minute. VirusTotal's free tier allows 4. It
answered 4, returned HTTP 429 to the rest, the circuit breaker opened after 5
failures, and every remaining scan got no VirusTotal at all — 169 of 200
known-malicious domains came back unchecked.

The requests were not too many. They were too fast.
"""

import threading
import time

import pytest

from apis import quota


@pytest.fixture(autouse=True)
def _clean():
    quota.reset()
    yield
    quota.reset()


class TestPacing:
    def test_the_first_burst_is_not_penalised(self, monkeypatch):
        """The bucket starts full, so a single scan is never slowed down."""
        monkeypatch.setenv("NEXGUARD_QUOTA_VIRUSTOTAL_PER_MIN", "4")
        t0 = time.monotonic()
        for _ in range(4):
            with quota.quota("virustotal") as ok:
                assert ok
        assert time.monotonic() - t0 < 1.0

    def test_the_fifth_request_waits_for_a_refill(self, monkeypatch):
        """
        4/min means a token every 15s. Exhaust the bucket and the next caller
        must WAIT rather than spend a request on a certain 429.
        """
        monkeypatch.setenv("NEXGUARD_QUOTA_VIRUSTOTAL_PER_MIN", "60")  # 1/s
        monkeypatch.setenv("NEXGUARD_QUOTA_VIRUSTOTAL_WAIT", "5")
        for _ in range(60):
            with quota.quota("virustotal"):
                pass
        t0 = time.monotonic()
        with quota.quota("virustotal") as ok:
            waited = time.monotonic() - t0
        assert ok, "should have waited and then succeeded"
        assert waited >= 0.5, f"returned immediately ({waited:.2f}s) — not pacing"

    def test_it_gives_up_rather_than_hanging(self, monkeypatch):
        """
        A live /scan must not block for a minute because a batch is draining the
        bucket. When the wait budget expires the caller proceeds and the source
        reports unavailable — which now yields UNKNOWN, not a false SAFE.
        """
        monkeypatch.setenv("NEXGUARD_QUOTA_VIRUSTOTAL_PER_MIN", "1")
        monkeypatch.setenv("NEXGUARD_QUOTA_VIRUSTOTAL_WAIT", "1")
        with quota.quota("virustotal"):
            pass
        t0 = time.monotonic()
        with quota.quota("virustotal") as ok:
            elapsed = time.monotonic() - t0
        assert ok is False
        assert elapsed < 3.0, f"blocked for {elapsed:.1f}s — the budget is not bounded"

    def test_concurrent_callers_are_serialised(self, monkeypatch):
        """Eight batch workers must not all get through at once."""
        monkeypatch.setenv("NEXGUARD_QUOTA_VIRUSTOTAL_PER_MIN", "120")  # 2/s
        monkeypatch.setenv("NEXGUARD_QUOTA_VIRUSTOTAL_WAIT", "10")
        for _ in range(120):
            with quota.quota("virustotal"):
                pass

        granted, lock = [], threading.Lock()

        def worker():
            with quota.quota("virustotal") as ok:
                with lock:
                    granted.append((time.monotonic(), ok))

        threads = [threading.Thread(target=worker) for _ in range(6)]
        t0 = time.monotonic()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=20)

        times = sorted(ts for ts, ok in granted if ok)
        assert len(times) >= 4
        # 2 tokens/s, so six callers cannot all be served inside a second.
        assert times[-1] - t0 > 1.0, "all callers passed at once — no pacing"


class TestConfiguration:
    def test_an_unknown_source_is_unlimited(self):
        """Adding an adapter must never accidentally deadlock it."""
        t0 = time.monotonic()
        for _ in range(50):
            with quota.quota("some_new_source") as ok:
                assert ok
        assert time.monotonic() - t0 < 1.0

    def test_a_paid_tier_can_raise_the_limit(self, monkeypatch):
        monkeypatch.setenv("NEXGUARD_QUOTA_VIRUSTOTAL_PER_MIN", "1000")
        t0 = time.monotonic()
        for _ in range(200):
            with quota.quota("virustotal"):
                pass
        assert time.monotonic() - t0 < 2.0

    def test_it_can_be_switched_off(self, monkeypatch):
        monkeypatch.setenv("NEXGUARD_QUOTA_VIRUSTOTAL_WAIT", "0")
        t0 = time.monotonic()
        for _ in range(100):
            with quota.quota("virustotal") as ok:
                assert ok
        assert time.monotonic() - t0 < 1.0


class TestObservability:
    def test_the_snapshot_explains_a_slow_batch(self, monkeypatch):
        monkeypatch.setenv("NEXGUARD_QUOTA_VIRUSTOTAL_PER_MIN", "60")
        monkeypatch.setenv("NEXGUARD_QUOTA_VIRUSTOTAL_WAIT", "3")
        for _ in range(62):
            with quota.quota("virustotal"):
                pass
        snap = quota.snapshot()
        assert "virustotal" in snap
        assert snap["virustotal"]["total_wait_s"] > 0, (
            "time spent waiting must be visible, or a slow batch looks like a hang")
