"""
A09 — security logging.

Two gaps from the review:
  * auth events (login success / failure / lockout) were not logged at all, so
    a brute-force attempt left no trace to detect;
  * `except Exception: pass` on critical paths — save_scan, tempfile cleanup —
    made real failures invisible. Lost history and leaked tempfiles looked
    exactly like success.

These tests assert the events reach the log. They deliberately check the log
rather than a mock, so deleting the logging call fails them.

Skipped in the slim CI env (fastapi + app deps not installed there).
"""

from types import SimpleNamespace

import pytest

main = pytest.importorskip("main")

import auth  # noqa: E402
from apis import rate_limit  # noqa: E402
from fastapi import HTTPException  # noqa: E402


@pytest.fixture(autouse=True)
def clean_rate_limit():
    rate_limit._MEM.clear()
    yield
    rate_limit._MEM.clear()


def _user(**kw):
    base = dict(id=4, email="u@e.com", role="user", tier="free", status="active",
                password_hash=auth.hash_password("correct-horse-battery"))
    base.update(kw)
    return SimpleNamespace(**base)


class _DB:
    def __init__(self, user): self._u = user
    def query(self, *a, **k): return self
    def filter(self, *a, **k): return self
    def first(self): return self._u


# ---------------------------------------------------------------------------
# Auth events
# ---------------------------------------------------------------------------

def test_successful_login_is_logged(caplog):
    with caplog.at_level("INFO", logger="nexguard.auth"):
        auth.do_login(_DB(_user()), "u@e.com", "correct-horse-battery", ip="1.2.3.4")

    assert "login_success" in caplog.text or "Login success" in caplog.text
    assert "u@e.com" in caplog.text


def test_failed_login_is_logged(caplog):
    with caplog.at_level("WARNING", logger="nexguard.auth"):
        with pytest.raises(HTTPException):
            auth.do_login(_DB(_user()), "u@e.com", "wrong", ip="1.2.3.4")

    assert "login_failure" in caplog.text or "Failed login" in caplog.text
    assert "1.2.3.4" in caplog.text


def test_lockout_is_logged(caplog):
    for _ in range(auth.LOGIN_MAX_ATTEMPTS):
        with pytest.raises(HTTPException):
            auth.do_login(_DB(_user()), "u@e.com", "wrong", ip="1.2.3.4")

    with caplog.at_level("WARNING", logger="nexguard.auth"):
        with pytest.raises(HTTPException) as exc:
            auth.do_login(_DB(_user()), "u@e.com", "wrong", ip="1.2.3.4")

    assert exc.value.status_code == 429
    assert "lockout" in caplog.text.lower()


def test_login_never_logs_the_password(caplog):
    with caplog.at_level("DEBUG"):
        with pytest.raises(HTTPException):
            auth.do_login(_DB(_user()), "u@e.com", "hunter2-secret-pw", ip="1.2.3.4")

    assert "hunter2-secret-pw" not in caplog.text


# ---------------------------------------------------------------------------
# Critical paths no longer fail silently
# ---------------------------------------------------------------------------

def test_save_scan_failure_is_logged(monkeypatch, caplog):
    def boom():
        raise RuntimeError("db is on fire")

    monkeypatch.setattr(main, "SessionLocal", boom)

    with caplog.at_level("ERROR", logger="nexguard.api"):
        main.save_scan("URL Scanner", {"verdict": "SAFE"}, "https://x.example")

    assert "db is on fire" in caplog.text, "save_scan swallowed the failure silently"


def test_save_scan_still_does_not_raise(monkeypatch):
    """Logging must not turn a storage failure into a failed scan."""
    def boom():
        raise RuntimeError("db is on fire")

    monkeypatch.setattr(main, "SessionLocal", boom)

    main.save_scan("URL Scanner", {"verdict": "SAFE"}, "https://x.example")  # no raise


def test_tempfile_cleanup_failure_is_logged(monkeypatch, caplog):
    def boom(path):
        raise PermissionError("file is locked")

    monkeypatch.setattr(main.os, "remove", boom)

    with caplog.at_level("WARNING", logger="nexguard.api"):
        main._cleanup_temp("/tmp/nexguard-scan-xyz")

    assert "nexguard-scan-xyz" in caplog.text


def test_tempfile_cleanup_is_quiet_when_the_file_is_already_gone(monkeypatch, caplog):
    """An already-deleted tempfile is normal, not a warning worth raising."""
    def gone(path):
        raise FileNotFoundError(path)

    monkeypatch.setattr(main.os, "remove", gone)

    with caplog.at_level("WARNING", logger="nexguard.api"):
        main._cleanup_temp("/tmp/already-gone")

    assert caplog.text == ""


def test_tempfile_cleanup_never_raises(monkeypatch):
    def boom(path):
        raise OSError("nope")

    monkeypatch.setattr(main.os, "remove", boom)

    main._cleanup_temp("/tmp/whatever")  # must not raise out of a finally block
