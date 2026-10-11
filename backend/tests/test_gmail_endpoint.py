"""
GET /gmail-emails contract (WORK_PLAN Task 2): the endpoint returns a status
OBJECT — {"status": connected|not_connected|error|demo, "emails": [...]} —
instead of the old bare array that silently swapped in demo emails.

Skipped in the slim CI env (fastapi + app deps not installed there).
"""

import pytest

main = pytest.importorskip("main")

from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture()
def client(monkeypatch):
    async def no_links(_text):
        return {"links_found": 0, "scanned_links": [], "worst_score": 0}

    monkeypatch.setattr(main, "scan_embedded_links", no_links)
    monkeypatch.setattr(main, "enforce_scan_quota", lambda user, request: None)
    monkeypatch.setattr(main, "save_scan", lambda *a, **k: None)
    main.app.dependency_overrides[main.get_optional_active_user] = lambda: None
    with TestClient(main.app) as c:
        yield c
    main.app.dependency_overrides.pop(main.get_optional_active_user, None)


def test_gmail_endpoint_not_connected(client, monkeypatch):
    monkeypatch.setattr(main, "read_gmail", lambda: {
        "status": "not_connected",
        "detail": "backend/credentials.json not found",
        "emails": [],
    })

    data = client.get("/gmail-emails").json()

    assert isinstance(data, dict)
    assert data["status"] == "not_connected"
    assert data.get("emails", []) == []


def test_gmail_endpoint_error_has_no_fake_rows(client, monkeypatch):
    monkeypatch.setattr(main, "read_gmail", lambda: {
        "status": "error",
        "detail": "token refresh failed",
        "emails": [],
    })

    data = client.get("/gmail-emails").json()

    assert data["status"] == "error"
    assert data.get("emails", []) == []
    # the old fallback fabricated a SUSPICIOUS row — must never happen again
    assert "SUSPICIOUS" not in str(data.get("emails"))


def test_gmail_endpoint_connected_returns_full_detail(client, monkeypatch):
    monkeypatch.setattr(main, "read_gmail", lambda: {
        "status": "connected",
        "emails": [{
            "subject": "Verify your account",
            "from": "security@paypa1.example",
            "verdict": "MALICIOUS",
            "score": 88,
            "risk_score": 88,
            "reasons": ["Brand impersonation"],
            "auth_results": {"spf": "fail", "dkim": "none", "dmarc": "fail"},
            "body": "click http-less body",
            "source": "gmail",
        }],
    })

    data = client.get("/gmail-emails").json()

    assert data["status"] == "connected"
    assert len(data["emails"]) == 1
    email = data["emails"][0]
    assert email["auth_results"] == {"spf": "fail", "dkim": "none", "dmarc": "fail"}
    assert email["reasons"] == ["Brand impersonation"]
    assert "links_found" in email
    assert "body" not in email  # body is internal — only needed for link scanning


def test_gmail_endpoint_demo_only_with_explicit_param(client, monkeypatch):
    monkeypatch.setattr(main, "read_sample_emails", lambda: [{
        "subject": "Sample phishing email",
        "from": "attacker@example",
        "verdict": "MALICIOUS",
        "score": 90,
        "risk_score": 90,
        "reasons": ["Urgency"],
        "auth_results": {"spf": "none", "dkim": "none", "dmarc": "none"},
        "body": "pay now",
        "source": "sample",
    }])
    # live path must NOT be consulted in demo mode
    monkeypatch.setattr(main, "read_gmail", lambda: pytest.fail("read_gmail called in demo mode"))

    data = client.get("/gmail-emails", params={"demo": 1}).json()

    assert data["status"] == "demo"
    assert len(data["emails"]) == 1
    assert all(e["source"] == "sample" for e in data["emails"])
