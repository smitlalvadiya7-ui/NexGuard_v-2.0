"""
A07 / A02 / A01 — authentication hardening.

Four properties, all previously missing:
  * /auth/login throttles + temporarily locks out repeated FAILED attempts,
    keyed by email+IP (credential stuffing was completely unthrottled);
  * registration requires a 12-character password (was 6);
  * get_current_user refuses a suspended account (only the *optional* scan
    dependency checked, so a suspended admin kept admin power);
  * JWT_SECRET is mandatory unless NEXGUARD_DEBUG is set — the old random
    per-process fallback silently broke multi-worker deploys.

Skipped in the slim CI env (fastapi + app deps not installed there).
"""

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

main = pytest.importorskip("main")

import auth  # noqa: E402
from apis import rate_limit  # noqa: E402
from fastapi import HTTPException  # noqa: E402
from fastapi.security import HTTPAuthorizationCredentials  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

BACKEND_DIR = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def clean_rate_limit():
    """Login counters are process-global — never leak between tests."""
    rate_limit._MEM.clear()
    yield
    rate_limit._MEM.clear()


@pytest.fixture()
def client():
    with TestClient(main.app) as c:
        yield c


def _user(**kw):
    base = dict(id=3, email="u@e.com", role="user", tier="free",
                status="active", password_hash=auth.hash_password("correct-horse-battery"))
    base.update(kw)
    return SimpleNamespace(**base)


def patch_db_user(monkeypatch, user, target=main):
    class FakeQuery:
        def filter(self, *a, **k): return self
        def first(self): return user

    class FakeDB:
        def query(self, *a, **k): return FakeQuery()
        def close(self): pass

    monkeypatch.setattr(target, "SessionLocal", lambda: FakeDB())
    return FakeDB()


# ---------------------------------------------------------------------------
# Password policy
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("password", ["", "short", "elevenchar", "11characte"])
def test_register_rejects_passwords_under_12_chars(password):
    with pytest.raises(HTTPException) as exc:
        auth.do_register(object(), "new@example.com", password)
    assert exc.value.status_code == 400
    assert "12" in exc.value.detail


def test_register_accepts_a_12_char_password(monkeypatch):
    monkeypatch.setattr(auth, "get_user_by_email", lambda db, e: None)
    monkeypatch.setattr(auth, "create_user",
                        lambda db, e, p: SimpleNamespace(id=1, email=e, role="user"))

    out = auth.do_register(object(), "new@example.com", "abcdefghijkl")  # exactly 12
    assert out["email"] == "new@example.com"


# ---------------------------------------------------------------------------
# Suspension is enforced on the main auth dependency
# ---------------------------------------------------------------------------

def _creds(token):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


class _DB:
    def __init__(self, user): self._u = user
    def query(self, *a, **k): return self
    def filter(self, *a, **k): return self
    def first(self): return self._u


def test_get_current_user_blocks_a_suspended_account():
    token = auth.create_access_token(3, "admin")
    with pytest.raises(HTTPException) as exc:
        auth.get_current_user(_creds(token), _DB(_user(status="suspended", role="admin")))
    assert exc.value.status_code == 403
    assert "suspend" in exc.value.detail.lower()


def test_get_current_user_still_allows_an_active_account():
    token = auth.create_access_token(3, "user")
    user = auth.get_current_user(_creds(token), _DB(_user()))
    assert user.id == 3


def test_suspended_admin_cannot_reach_require_admin():
    """The concrete escalation: a suspended admin kept admin power."""
    token = auth.create_access_token(3, "admin")
    with pytest.raises(HTTPException) as exc:
        auth.require_admin(
            auth.get_current_user(_creds(token), _DB(_user(status="suspended", role="admin")))
        )
    assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# JWT_SECRET is mandatory outside debug
# ---------------------------------------------------------------------------

def test_secret_from_env_is_used(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "a-real-strong-secret")
    assert auth._resolve_jwt_secret() == "a-real-strong-secret"


def test_missing_secret_outside_debug_is_fatal(monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.delenv("NEXGUARD_DEBUG", raising=False)
    with pytest.raises(RuntimeError) as exc:
        auth._resolve_jwt_secret()
    assert "JWT_SECRET" in str(exc.value)


def test_missing_secret_in_debug_falls_back_to_a_random_one(monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.setenv("NEXGUARD_DEBUG", "1")
    secret = auth._resolve_jwt_secret()
    assert secret and len(secret) >= 32


def test_blank_secret_counts_as_missing(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "   ")
    monkeypatch.delenv("NEXGUARD_DEBUG", raising=False)
    with pytest.raises(RuntimeError):
        auth._resolve_jwt_secret()


def test_importing_auth_without_a_secret_fails_at_startup():
    """The wiring, not just the helper: a real import must refuse to boot."""
    env = {k: v for k, v in os.environ.items()
           if k not in ("JWT_SECRET", "NEXGUARD_DEBUG")}
    env["PYTHONPATH"] = str(BACKEND_DIR)

    proc = subprocess.run(
        [sys.executable, "-c", "import auth"],
        cwd=str(BACKEND_DIR), env=env, capture_output=True, text=True,
    )

    assert proc.returncode != 0, "auth imported cleanly with no JWT_SECRET"
    assert "JWT_SECRET" in proc.stderr


# ---------------------------------------------------------------------------
# Login rate-limit + temporary lockout
# ---------------------------------------------------------------------------

def test_repeated_bad_logins_get_locked_out(client, monkeypatch):
    patch_db_user(monkeypatch, _user())

    codes = []
    for _ in range(auth.LOGIN_MAX_ATTEMPTS + 2):
        r = client.post("/auth/login",
                        json={"email": "u@e.com", "password": "wrong-password"})
        codes.append(r.status_code)

    assert codes[:auth.LOGIN_MAX_ATTEMPTS] == [401] * auth.LOGIN_MAX_ATTEMPTS
    assert codes[auth.LOGIN_MAX_ATTEMPTS] == 429, f"no lockout after N failures: {codes}"
    assert codes[-1] == 429, "lockout did not persist"


def test_lockout_blocks_even_the_correct_password(client, monkeypatch):
    """Otherwise the lockout is trivially bypassed by the attacker who guesses."""
    patch_db_user(monkeypatch, _user())

    for _ in range(auth.LOGIN_MAX_ATTEMPTS):
        client.post("/auth/login", json={"email": "u@e.com", "password": "nope"})

    r = client.post("/auth/login",
                    json={"email": "u@e.com", "password": "correct-horse-battery"})
    assert r.status_code == 429


def test_a_good_login_is_not_blocked_before_the_limit(client, monkeypatch):
    patch_db_user(monkeypatch, _user())

    for _ in range(auth.LOGIN_MAX_ATTEMPTS - 1):
        client.post("/auth/login", json={"email": "u@e.com", "password": "nope"})

    r = client.post("/auth/login",
                    json={"email": "u@e.com", "password": "correct-horse-battery"})
    assert r.status_code == 200
    assert r.json()["token"]


def test_success_clears_the_failure_counter(client, monkeypatch):
    """A user who mistypes twice then succeeds starts clean again."""
    patch_db_user(monkeypatch, _user())

    for _ in range(2):
        client.post("/auth/login", json={"email": "u@e.com", "password": "nope"})
    client.post("/auth/login",
                json={"email": "u@e.com", "password": "correct-horse-battery"})

    assert rate_limit.count(auth._login_key("u@e.com", "testclient")) == 0


def test_lockout_is_scoped_to_email_plus_ip():
    """A locked-out attacker must not lock every other user out (or himself
    out of every other victim's account) — the key is email+IP."""
    for _ in range(auth.LOGIN_MAX_ATTEMPTS):
        auth.record_login_failure("victim@e.com", "1.2.3.4")

    assert auth.is_login_locked("victim@e.com", "1.2.3.4") is True
    assert auth.is_login_locked("victim@e.com", "5.6.7.8") is False   # other IP
    assert auth.is_login_locked("other@e.com", "1.2.3.4") is False    # other email


def test_lockout_key_ignores_email_case_and_padding():
    for _ in range(auth.LOGIN_MAX_ATTEMPTS):
        auth.record_login_failure("Victim@E.com", "1.2.3.4")

    assert auth.is_login_locked("  victim@e.com  ", "1.2.3.4") is True


# ---------------------------------------------------------------------------
# rate_limit gained a non-consuming read + a reset (needed by the lockout)
# ---------------------------------------------------------------------------

def test_count_does_not_consume_an_attempt():
    key = "unit:test"
    rate_limit.allow(key, limit=3, window_s=60)

    assert rate_limit.count(key) == 1
    assert rate_limit.count(key) == 1, "count() consumed a slot"


def test_count_of_an_unseen_key_is_zero():
    assert rate_limit.count("never:seen") == 0


def test_reset_clears_the_counter():
    key = "unit:reset"
    rate_limit.allow(key, limit=3, window_s=60)
    rate_limit.reset(key)

    assert rate_limit.count(key) == 0
