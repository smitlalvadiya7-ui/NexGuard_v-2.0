"""
Prior-scan history lookup (WORK_PLAN Task 6): GET /history/lookup?target=
returns how many times this target/domain was scanned before and the recent
verdicts, so a repeat target is obvious on the result.

Skipped in the slim CI env (fastapi + app deps not installed there).
"""

from types import SimpleNamespace

import pytest

main = pytest.importorskip("main")

from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture()
def client():
    with TestClient(main.app) as c:
        yield c


def _user(uid=5, role="user"):
    return SimpleNamespace(id=uid, email="u@e.com", role=role, tier="free", status="active")


def test_anonymous_gets_empty_lookup(client):
    main.app.dependency_overrides[main.get_optional_user] = lambda: None
    try:
        data = client.get("/history/lookup", params={"target": "https://x.example"}).json()
        assert data["count"] == 0
        assert data["recent"] == []
    finally:
        main.app.dependency_overrides.pop(main.get_optional_user, None)


def test_lookup_counts_prior_scans_of_same_domain(client, monkeypatch):
    rows = [
        SimpleNamespace(module="URL Scanner", verdict="MALICIOUS", score=80,
                        target="https://evil.example/login", user_id=5,
                        created_at=main._utcnow()),
        SimpleNamespace(module="URL Scanner", verdict="SUSPICIOUS", score=55,
                        target="https://evil.example/other", user_id=5,
                        created_at=main._utcnow()),
        SimpleNamespace(module="QR Scanner", verdict="MALICIOUS", score=80,
                        target="https://evil.example/qr", user_id=5,
                        created_at=main._utcnow()),
    ]

    class FakeQuery:
        def __init__(self, data): self._d = data
        def filter(self, *a, **k): return self
        def order_by(self, *a, **k): return self
        def limit(self, *a, **k): return self
        def all(self): return self._d

    class FakeDB:
        def query(self, *a, **k): return FakeQuery(rows)
        def close(self): pass

    monkeypatch.setattr(main, "SessionLocal", lambda: FakeDB())
    main.app.dependency_overrides[main.get_optional_user] = lambda: _user()
    try:
        data = client.get("/history/lookup", params={"target": "https://evil.example/new"}).json()
        assert data["domain"] == "evil.example"
        assert data["count"] == 3
        assert data["verdicts"]["MALICIOUS"] == 2
        assert data["verdicts"]["SUSPICIOUS"] == 1
        assert len(data["recent"]) == 3
        assert data["recent"][0]["verdict"] in ("MALICIOUS", "SUSPICIOUS")
    finally:
        main.app.dependency_overrides.pop(main.get_optional_user, None)


def test_lookup_requires_target(client):
    main.app.dependency_overrides[main.get_optional_user] = lambda: _user()
    try:
        assert client.get("/history/lookup").status_code == 422  # missing query param
    finally:
        main.app.dependency_overrides.pop(main.get_optional_user, None)
