"""
Support center endpoints (WORK_PLAN Task 12): FAQ assistant, ticket creation
(anyone, even anonymous), the user's own tickets, and the admin Support inbox
with reply + status flow. Email notification is fired but never blocks.

Skipped in the slim CI env (fastapi + app deps not installed there).
"""

import pytest

main = pytest.importorskip("main")

from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture()
def client():
    with TestClient(main.app) as c:
        yield c


@pytest.fixture()
def anon(client):
    main.app.dependency_overrides[main.get_optional_active_user] = lambda: None
    yield client
    main.app.dependency_overrides.pop(main.get_optional_active_user, None)


def _fake_admin():
    from types import SimpleNamespace
    return SimpleNamespace(id=1, email="admin@nexguard.local", role="superadmin",
                           tier="premium", status="active")


# --- FAQ assistant ---------------------------------------------------------

def test_support_ask_returns_faq_answer(client):
    data = client.post("/support/ask", json={"question": "how does the voice scanner work"}).json()
    assert data["matched"] is True
    assert data["answer"]


def test_support_faq_list_is_public(client):
    data = client.get("/support/faq").json()
    assert isinstance(data, list) and len(data) >= 5
    assert "question" in data[0] and "answer" in data[0]


# --- ticket creation -------------------------------------------------------

def test_anonymous_can_open_a_ticket(anon, monkeypatch):
    sent = {}
    monkeypatch.setattr(main, "send_ticket_notification", lambda t: sent.update(t) or {"sent": False, "detail": "x"})

    resp = anon.post("/support/tickets", json={
        "email": "visitor@example.com",
        "subject": "Is this link safe?",
        "message": "I got a suspicious SMS, can you help?",
        "category": "question",
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True
    assert body["ticket"]["status"] == "open"
    assert body["ticket"]["email"] == "visitor@example.com"
    # the owner-notification was attempted with the created ticket
    assert sent.get("id") == body["ticket"]["id"]


def test_ticket_requires_email_and_message(anon):
    r1 = anon.post("/support/tickets", json={"email": "", "message": "hi"})
    assert r1.status_code == 400
    r2 = anon.post("/support/tickets", json={"email": "a@b.com", "message": "  "})
    assert r2.status_code == 400


def test_ticket_creation_survives_email_failure(anon, monkeypatch):
    def boom(_t):
        raise RuntimeError("smtp exploded")
    monkeypatch.setattr(main, "send_ticket_notification", boom)

    resp = anon.post("/support/tickets", json={
        "email": "visitor@example.com", "message": "help please",
    })
    assert resp.status_code == 200
    assert resp.json()["ticket"]["status"] == "open"


# --- admin inbox + reply ---------------------------------------------------

def test_admin_lists_and_replies_moving_status(client, monkeypatch):
    monkeypatch.setattr(main, "send_ticket_notification", lambda t: {"sent": False, "detail": "x"})
    main.app.dependency_overrides[main.get_optional_active_user] = lambda: None
    created = client.post("/support/tickets", json={
        "email": "u@example.com", "message": "why was my email flagged?",
    }).json()["ticket"]
    main.app.dependency_overrides.pop(main.get_optional_active_user, None)

    main.app.dependency_overrides[main.require_admin] = _fake_admin
    try:
        listing = client.get("/admin/support/tickets?status=open").json()
        assert any(t["id"] == created["id"] for t in listing)

        replied = client.post(f"/admin/support/tickets/{created['id']}/reply", json={
            "reply": "It was flagged because the sender domain did not match the brand.",
            "status": "answered",
        }).json()
        assert replied["status"] == "answered"
        assert "sender domain" in replied["admin_reply"]
        assert replied["replied_at"]
    finally:
        main.app.dependency_overrides.pop(main.require_admin, None)


def test_reply_rejects_bad_status(client, monkeypatch):
    monkeypatch.setattr(main, "send_ticket_notification", lambda t: {"sent": False, "detail": "x"})
    main.app.dependency_overrides[main.get_optional_active_user] = lambda: None
    created = client.post("/support/tickets", json={"email": "u@e.com", "message": "hi"}).json()["ticket"]
    main.app.dependency_overrides.pop(main.get_optional_active_user, None)

    main.app.dependency_overrides[main.require_admin] = _fake_admin
    try:
        r = client.post(f"/admin/support/tickets/{created['id']}/reply", json={
            "reply": "x", "status": "banana",
        })
        assert r.status_code == 400
    finally:
        main.app.dependency_overrides.pop(main.require_admin, None)


def test_admin_endpoint_requires_admin(anon):
    # anonymous (get_optional_active_user -> None) must not reach the inbox
    assert anon.get("/admin/support/tickets").status_code in (401, 403)
