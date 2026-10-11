"""
URLHaus must recognise a rejected auth key as permanent, not as an outage.

Real failure, 2026-08-19. A running deployment returned
`intel_unavailable: ["URLHaus"]` on every scan. abuse.ch was answering:

    403  {"query_status": "unknown_auth_key"}

for a 48-character key that was present, well-formed, and no longer recognised
(abuse.ch moved to account-linked auth keys). The scanner treated it as a flaky
endpoint and re-sent the same dead key twice per scan, plus a cooldown probe
every 30 seconds, indefinitely.

Every test drives the real code with a stubbed HTTP transport. Nothing reaches
the network, and nothing asserts on the stub — the assertions are about what
NexGuard does with a given API response.
"""

import asyncio

import pytest

from apis import blocklists, circuit_breaker


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
    """A key, no cache, and a clean breaker registry.

    The reset matters both ways: a breaker left OPEN by an earlier test would
    make a later one pass without ever calling the code under test, and the
    permanent rejection these tests create would leak into every test after."""
    circuit_breaker.reset_all()
    monkeypatch.setenv("URLHAUS_AUTH_KEY", "test-key")
    monkeypatch.setattr(blocklists, "cache_get", lambda k: None)
    monkeypatch.setattr(blocklists, "cache_put", lambda k, v: None)
    yield
    circuit_breaker.reset_all()


def stub(monkeypatch, response, record):
    def _post(api_url, data=None, headers=None, timeout=None):
        record.append({"url": api_url, "data": data})
        return response

    monkeypatch.setattr(blocklists.requests, "post", _post)


def check(url="https://example.org"):
    return asyncio.run(blocklists.check_urlhaus(url))


REJECTED = FakeResponse(403, {"query_status": "unknown_auth_key"})


# ---------------------------------------------------------------------------
# A rejected key stops costing us calls
# ---------------------------------------------------------------------------

class TestRejectedKey:

    def test_an_unknown_auth_key_is_sent_once_not_retried(self, monkeypatch):
        calls = []
        stub(monkeypatch, REJECTED, calls)
        check()
        assert len(calls) == 1

    def test_later_scans_stop_calling_urlhaus_entirely(self, monkeypatch):
        calls = []
        stub(monkeypatch, REJECTED, calls)
        for i in range(5):
            check(f"https://example-{i}.org")
        assert len(calls) == 1

    def test_a_bare_401_is_also_treated_as_a_rejection(self, monkeypatch):
        calls = []
        stub(monkeypatch, FakeResponse(401, {"error": "Unauthorized"}), calls)
        check()
        check("https://other.org")
        assert len(calls) == 1

    def test_the_source_is_reported_unavailable_never_clean(self, monkeypatch):
        """The one thing that must not happen: a dead source reading as 'clean'
        and contributing a safe signal to the verdict."""
        stub(monkeypatch, REJECTED, [])
        assert check()["status"] == "unavailable"

    def test_the_breaker_names_urlhaus_as_rejected(self, monkeypatch):
        stub(monkeypatch, REJECTED, [])
        check()
        assert "urlhaus" in circuit_breaker.auth_rejected_sources()


# ---------------------------------------------------------------------------
# Everything else keeps working
# ---------------------------------------------------------------------------

class TestUnaffected:

    def test_a_real_outage_is_still_retried(self, monkeypatch):
        calls = []
        stub(monkeypatch, FakeResponse(503), calls)
        check()
        assert len(calls) == 2

    def test_an_outage_does_not_mark_the_key_rejected(self, monkeypatch):
        stub(monkeypatch, FakeResponse(503), [])
        check()
        assert circuit_breaker.auth_rejected_sources() == set()

    def test_a_clean_lookup_still_reads_clean(self, monkeypatch):
        stub(monkeypatch, FakeResponse(200, {"query_status": "no_results"}), [])
        assert check()["status"] == "clean"

    def test_a_listed_url_still_flags(self, monkeypatch):
        stub(monkeypatch, FakeResponse(
            200, {"query_status": "ok", "threat": "malware_download"}), [])
        result = check()
        assert result["status"] == "flag"
        assert "malware_download" in result["detail"]

    def test_no_key_configured_still_short_circuits_without_a_call(self, monkeypatch):
        monkeypatch.setenv("URLHAUS_AUTH_KEY", "")
        calls = []
        stub(monkeypatch, REJECTED, calls)
        assert check()["status"] == "unavailable"
        assert calls == []
