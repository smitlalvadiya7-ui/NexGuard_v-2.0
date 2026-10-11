"""
A01 (Broken Access Control) — /ws/live-alerts used to accept ANY connection and
then push every user's scan target to it, so an anonymous listener saw the URLs
everyone else was scanning.

Two properties are locked in here:
  1. the handshake requires a valid JWT (?token=) — anonymous and garbage
     tokens are refused before the socket is accepted;
  2. an alert is delivered only to the socket belonging to the user whose scan
     produced it. An alert with no owner reaches nobody, because the only
     alternative is leaking one user's targets to every other listener.

Skipped in the slim CI env (fastapi + app deps not installed there).
"""

import asyncio
from types import SimpleNamespace

import pytest

main = pytest.importorskip("main")

from fastapi.testclient import TestClient  # noqa: E402
from starlette.websockets import WebSocketDisconnect  # noqa: E402


@pytest.fixture()
def client():
    with TestClient(main.app) as c:
        yield c


def _user(uid=7, status="active"):
    return SimpleNamespace(id=uid, email="u@e.com", role="user",
                           tier="free", status=status)


def patch_db_user(monkeypatch, user):
    """Point main.SessionLocal at a DB that returns `user` for any lookup."""
    class FakeQuery:
        def filter(self, *a, **k): return self
        def first(self): return user

    class FakeDB:
        def query(self, *a, **k): return FakeQuery()
        def close(self): pass

    monkeypatch.setattr(main, "SessionLocal", lambda: FakeDB())


# ---------------------------------------------------------------------------
# Handshake authentication
# ---------------------------------------------------------------------------

def test_anonymous_handshake_is_rejected(client):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/live-alerts"):
            pass


def test_garbage_token_is_rejected(client):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/live-alerts?token=not-a-jwt"):
            pass


def test_token_signed_with_the_wrong_secret_is_rejected(client):
    from jose import jwt
    forged = jwt.encode({"sub": "7", "role": "user"}, "attacker-secret",
                        algorithm="HS256")
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws/live-alerts?token={forged}"):
            pass


def test_token_for_a_deleted_user_is_rejected(client, monkeypatch):
    patch_db_user(monkeypatch, None)
    token = main.create_access_token(7, "user")
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws/live-alerts?token={token}"):
            pass


def test_suspended_user_is_rejected(client, monkeypatch):
    patch_db_user(monkeypatch, _user(status="suspended"))
    token = main.create_access_token(7, "user")
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(f"/ws/live-alerts?token={token}"):
            pass


def test_valid_token_is_accepted(client, monkeypatch):
    patch_db_user(monkeypatch, _user())
    token = main.create_access_token(7, "user")
    with client.websocket_connect(f"/ws/live-alerts?token={token}") as ws:
        assert ws is not None  # handshake completed without a disconnect


# ---------------------------------------------------------------------------
# Alerts are scoped to their owner
# ---------------------------------------------------------------------------

class FakeWS:
    async def accept(self):
        pass


def test_alert_reaches_only_the_owning_user():
    async def scenario():
        mgr = main.ConnectionManager()
        alice = await mgr.connect(FakeWS(), user_id=1)
        bob = await mgr.connect(FakeWS(), user_id=2)

        await mgr.broadcast({"target": "https://alice-private.example"}, user_id=1)

        assert alice.qsize() == 1
        assert bob.qsize() == 0, "Bob received Alice's scan target"
        assert alice.get_nowait()["target"] == "https://alice-private.example"

    asyncio.run(scenario())


def test_every_socket_of_the_same_user_gets_the_alert():
    """One user with two tabs open should see the alert in both."""
    async def scenario():
        mgr = main.ConnectionManager()
        tab1 = await mgr.connect(FakeWS(), user_id=1)
        tab2 = await mgr.connect(FakeWS(), user_id=1)

        await mgr.broadcast({"target": "https://x.example"}, user_id=1)

        assert tab1.qsize() == 1
        assert tab2.qsize() == 1

    asyncio.run(scenario())


def test_ownerless_alert_is_not_broadcast_to_anyone():
    """An anonymous scan has no owner — it must not fan out to every listener."""
    async def scenario():
        mgr = main.ConnectionManager()
        alice = await mgr.connect(FakeWS(), user_id=1)

        await mgr.broadcast({"target": "https://anon.example"}, user_id=None)

        assert alice.qsize() == 0

    asyncio.run(scenario())


def test_disconnect_removes_only_that_socket():
    async def scenario():
        mgr = main.ConnectionManager()
        tab1 = await mgr.connect(FakeWS(), user_id=1)
        tab2 = await mgr.connect(FakeWS(), user_id=1)

        mgr.disconnect(tab1)
        await mgr.broadcast({"target": "https://x.example"}, user_id=1)

        assert tab1.qsize() == 0
        assert tab2.qsize() == 1

    asyncio.run(scenario())
