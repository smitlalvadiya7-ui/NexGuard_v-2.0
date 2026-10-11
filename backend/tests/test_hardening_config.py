"""
A05 / A04 / A06 — misconfiguration, insecure design, supply chain.

  * exception text (str(e)) must never reach a client — it names internal
    modules, paths and third-party failure modes. It goes to the log instead;
  * anonymous /health must not expose which API keys are configured, nor the
    raw last_error strings from the circuit breakers (recon);
  * /export-report takes an arbitrary dict from anonymous callers and renders
    it to a PDF — it needs a size and shape limit;
  * the container must not run as root, and dependencies must be pinned.

Skipped in the slim CI env (fastapi + app deps not installed there).
"""

import io
import json
import re
from pathlib import Path

import pytest

main = pytest.importorskip("main")

from fastapi.testclient import TestClient  # noqa: E402

BACKEND_DIR = Path(__file__).resolve().parents[1]
SECRET_DETAIL = "InternalSecretPathDetail-/srv/nexguard/private"


@pytest.fixture()
def client():
    with TestClient(main.app) as c:
        yield c


@pytest.fixture()
def anon(client):
    main.app.dependency_overrides[main.get_optional_user] = lambda: None
    main.app.dependency_overrides[main.get_optional_active_user] = lambda: None
    yield client
    main.app.dependency_overrides.pop(main.get_optional_user, None)
    main.app.dependency_overrides.pop(main.get_optional_active_user, None)


def _admin():
    from types import SimpleNamespace
    return SimpleNamespace(id=1, email="admin@nexguard.local", role="admin",
                           tier="premium", status="active")


# ---------------------------------------------------------------------------
# Exception text never reaches the client
# ---------------------------------------------------------------------------

def test_email_analyzer_crash_does_not_leak_the_exception(anon, monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError(SECRET_DETAIL)

    monkeypatch.setattr(main, "parse_email", boom)

    resp = anon.post("/analyze-email",
                     files={"file": ("m.eml", io.BytesIO(b"From: a@b.com\n\nhi"),
                                     "message/rfc822")})

    assert SECRET_DETAIL not in resp.text, "internal exception text leaked to client"
    assert resp.json()["verdict"] == "ERROR"


def test_email_analyzer_crash_is_logged(anon, monkeypatch, caplog):
    def boom(*a, **kw):
        raise RuntimeError(SECRET_DETAIL)

    monkeypatch.setattr(main, "parse_email", boom)

    with caplog.at_level("ERROR"):
        anon.post("/analyze-email",
                  files={"file": ("m.eml", io.BytesIO(b"From: a@b.com\n\nhi"),
                                  "message/rfc822")})

    assert SECRET_DETAIL in caplog.text, "the detail was dropped instead of logged"


def test_stripe_checkout_error_is_generic(client, monkeypatch):
    main.app.dependency_overrides[main.get_current_user] = lambda: _admin()
    try:
        monkeypatch.setattr(main.billing, "is_enabled", lambda: True)

        def boom(*a, **kw):
            raise RuntimeError(SECRET_DETAIL)

        monkeypatch.setattr(main.billing, "create_checkout_session", boom)
        monkeypatch.setattr(main, "_is_premium_viewer", lambda u: False)

        resp = client.post("/billing/create-checkout-session", json={})

        assert resp.status_code == 502
        assert SECRET_DETAIL not in resp.text
    finally:
        main.app.dependency_overrides.pop(main.get_current_user, None)


def test_stripe_webhook_error_is_generic(client, monkeypatch):
    monkeypatch.setattr(main.billing, "is_enabled", lambda: True)

    def boom(*a, **kw):
        raise RuntimeError(SECRET_DETAIL)

    monkeypatch.setattr(main.billing, "construct_event", boom)

    resp = client.post("/billing/webhook", content=b"{}",
                       headers={"stripe-signature": "bad"})

    assert resp.status_code == 400
    assert SECRET_DETAIL not in resp.text


# ---------------------------------------------------------------------------
# /health is quiet for anonymous callers
# ---------------------------------------------------------------------------

def test_anonymous_health_hides_last_error_and_key_config(anon):
    body = anon.get("/health").text

    assert "last_error" not in body
    assert "keyless" not in body, "per-source key configuration exposed anonymously"
    assert json.loads(body)["status"] == "ok"


def test_anonymous_health_still_reports_liveness(anon):
    data = anon.get("/health").json()

    assert data["status"] == "ok"
    assert "modules" in data  # enough for a container healthcheck / status page


def test_admin_health_names_the_community_blocklist_not_phishtank(client, monkeypatch):
    # The source-config view must describe checks that exist: the PhishTank
    # entry was hardcoded "disabled" for a stub that never ran.
    main.app.dependency_overrides[main.get_optional_user] = lambda: _admin()
    try:
        monkeypatch.delenv("NEXGUARD_DISABLE_FEEDS", raising=False)
        data = client.get("/health").json()
        assert data["sources"]["community_blocklist"]["config"] == "keyless"
        assert "phishtank" not in json.dumps(data).lower()

        # ...and it tracks the kill switch the evals use.
        monkeypatch.setenv("NEXGUARD_DISABLE_FEEDS", "1")
        data = client.get("/health").json()
        assert data["sources"]["community_blocklist"]["config"] == "disabled"
    finally:
        main.app.dependency_overrides.pop(main.get_optional_user, None)


def test_admin_health_keeps_the_full_detail(client):
    main.app.dependency_overrides[main.get_optional_user] = lambda: _admin()
    try:
        data = client.get("/health").json()

        assert "sources" in data
        assert "last_error" in json.dumps(data)
        assert data["database"]
    finally:
        main.app.dependency_overrides.pop(main.get_optional_user, None)


# ---------------------------------------------------------------------------
# /export-report input limits
# ---------------------------------------------------------------------------

def test_export_report_rejects_an_oversized_payload(anon):
    huge = {"module": "URL Scanner", "blob": "A" * (main.EXPORT_MAX_BYTES + 1000)}

    resp = anon.post("/export-report", json=huge)

    assert resp.status_code == 413


def test_export_report_rejects_a_non_object_payload(anon):
    resp = anon.post("/export-report", json=["not", "an", "object"])

    assert resp.status_code in (400, 422)


def test_export_report_rejects_too_many_keys(anon):
    resp = anon.post("/export-report",
                     json={f"k{i}": i for i in range(main.EXPORT_MAX_KEYS + 5)})

    assert resp.status_code == 400


def test_export_report_still_accepts_a_normal_report(anon, monkeypatch):
    monkeypatch.setattr(main, "generate_report",
                        lambda data, path: Path(path).write_bytes(b"%PDF-1.4 fake"))

    resp = anon.post("/export-report", json={
        "module": "URL Scanner",
        "target": "https://example.com",
        "verdict": "SAFE",
        "risk_score": 5,
        "reasons": ["Nothing suspicious"],
    })

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"


# ---------------------------------------------------------------------------
# Container + dependency hygiene
# ---------------------------------------------------------------------------

def test_dockerfile_runs_as_a_non_root_user():
    dockerfile = (BACKEND_DIR / "Dockerfile").read_text(encoding="utf-8")

    users = re.findall(r"^\s*USER\s+(\S+)", dockerfile, re.MULTILINE)

    assert users, "Dockerfile has no USER directive — the app runs as root"
    assert users[-1] not in ("root", "0"), f"last USER is {users[-1]!r}"


def test_every_requirement_is_pinned():
    text = (BACKEND_DIR / "requirements.txt").read_text(encoding="utf-8")

    unpinned = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        if "==" not in line:
            unpinned.append(line)

    assert not unpinned, f"unpinned dependencies: {unpinned}"


def test_a_hashed_lockfile_exists():
    lock = BACKEND_DIR / "requirements.lock"

    assert lock.is_file(), "no requirements.lock — builds are not reproducible"
    assert "--hash=sha256:" in lock.read_text(encoding="utf-8")
