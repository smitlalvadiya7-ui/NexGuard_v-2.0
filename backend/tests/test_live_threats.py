"""
GET /live-threats (WORK_PLAN Task 5): an honest feed object —
{status: live|unavailable, threats, sources, fetched_at, detail?} —
and the hardcoded _DEMO_THREATS fallback is gone for good.

Skipped in the slim CI env (fastapi + app deps not installed there).
"""

import pytest

main = pytest.importorskip("main")

from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture()
def client(monkeypatch):
    # fresh cache per test
    monkeypatch.setattr(main, "_THREAT_CACHE", {"data": None, "ts": 0.0})
    with TestClient(main.app) as c:
        yield c


def test_live_feed_reports_sources_and_fetch_time(client, monkeypatch):
    monkeypatch.setattr(main, "_fetch_urlhaus", lambda: [
        {"type": "MALWARE", "target": "http://bad.example/x", "severity": "CRITICAL", "source": "URLHaus"},
    ])
    monkeypatch.setattr(main, "_fetch_openphish", lambda: [
        {"type": "PHISHING", "target": "http://phish.example/y", "severity": "HIGH", "source": "OpenPhish"},
    ])

    data = client.get("/live-threats").json()

    assert data["status"] == "live"
    assert len(data["threats"]) == 2
    assert set(data["sources"]) == {"URLHaus", "OpenPhish"}
    assert data["fetched_at"]  # ISO timestamp for "updated N min ago"


def test_one_source_down_still_live(client, monkeypatch):
    def boom():
        raise RuntimeError("feed down")

    monkeypatch.setattr(main, "_fetch_urlhaus", boom)
    monkeypatch.setattr(main, "_fetch_openphish", lambda: [
        {"type": "PHISHING", "target": "http://phish.example/y", "severity": "HIGH", "source": "OpenPhish"},
    ])

    data = client.get("/live-threats").json()

    assert data["status"] == "live"
    assert data["sources"] == ["OpenPhish"]


def test_both_sources_down_is_honest_not_demo(client, monkeypatch):
    def boom():
        raise RuntimeError("feed down")

    monkeypatch.setattr(main, "_fetch_urlhaus", boom)
    monkeypatch.setattr(main, "_fetch_openphish", boom)

    data = client.get("/live-threats").json()

    assert data["status"] == "unavailable"
    assert data["threats"] == []
    assert "retry" in (data.get("detail") or "").lower()
    # the old hardcoded demo rows must never come back
    assert "Demo" not in str(data)
    assert not hasattr(main, "_DEMO_THREATS")
