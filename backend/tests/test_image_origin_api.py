"""
POST /analyze-image-origin — mirrors /analyze-screenshot: quota first,
temp upload cleaned, history for signed-in users, no live-threat broadcast.
The engine itself is unit-tested in test_image_origin.py; here it is
monkeypatched so these are pure endpoint-contract tests.
"""

import io
from types import SimpleNamespace

import pytest

main = pytest.importorskip("main")

from fastapi.testclient import TestClient  # noqa: E402
from fastapi.responses import JSONResponse  # noqa: E402


FAKE_RESULT = {
    "verdict": "LIKELY_AI", "confidence": 91, "generator": None,
    "generator_link": None, "ai_probability": 91,
    "reasons": ["The local detector model rates this 91% likely AI-generated."],
    "actions": [{"label": "Verify Content Credentials yourself",
                 "url": "https://contentcredentials.org/verify"}],
    "analysis": "Likely AI-generated (confidence 91%).",
}


def _post_image(client):
    return client.post(
        "/analyze-image-origin",
        files={"file": ("pic.png", io.BytesIO(b"png-bytes"), "image/png")},
    )


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(main, "enforce_scan_quota", lambda user, request: None)
    monkeypatch.setattr(main, "save_scan", lambda *a, **k: None)
    monkeypatch.setattr(main, "analyze_image_origin", lambda path: dict(FAKE_RESULT))
    main.app.dependency_overrides[main.get_optional_active_user] = lambda: None
    with TestClient(main.app) as c:
        yield c
    main.app.dependency_overrides.pop(main.get_optional_active_user, None)


def test_engine_result_passes_through_for_anonymous(client):
    res = _post_image(client)
    assert res.status_code == 200
    data = res.json()
    assert data["verdict"] == "LIKELY_AI"
    assert data["confidence"] == 91
    assert data["actions"]


def test_quota_block_returns_the_429(monkeypatch):
    monkeypatch.setattr(main, "enforce_scan_quota", lambda user, request:
                        JSONResponse(status_code=429, content={"detail": "limit"}))
    def boom(path):
        raise AssertionError("engine must not run when quota blocks")
    monkeypatch.setattr(main, "analyze_image_origin", boom)
    main.app.dependency_overrides[main.get_optional_active_user] = lambda: None
    try:
        with TestClient(main.app) as c:
            assert _post_image(c).status_code == 429
    finally:
        main.app.dependency_overrides.pop(main.get_optional_active_user, None)


def test_signed_in_scan_is_recorded_in_history(monkeypatch):
    saved = {}
    def fake_save(module, result, target="", user_id=None):
        saved.update(module=module, target=target, user_id=user_id)
    monkeypatch.setattr(main, "enforce_scan_quota", lambda user, request: None)
    monkeypatch.setattr(main, "save_scan", fake_save)
    monkeypatch.setattr(main, "analyze_image_origin", lambda path: dict(FAKE_RESULT))
    user = SimpleNamespace(id=7, tier="premium", role="user")
    main.app.dependency_overrides[main.get_optional_active_user] = lambda: user
    try:
        with TestClient(main.app) as c:
            assert _post_image(c).status_code == 200
    finally:
        main.app.dependency_overrides.pop(main.get_optional_active_user, None)
    assert saved == {"module": "AI Image Check", "target": "pic.png", "user_id": 7}


def test_unreadable_file_is_still_a_200_honest_uncertain(client, monkeypatch):
    monkeypatch.setattr(main, "analyze_image_origin", lambda path: {
        "verdict": "UNCERTAIN", "confidence": 0, "generator": None,
        "generator_link": None, "ai_probability": None,
        "reasons": ["The file is not a readable image."], "actions": [],
        "analysis": "This file could not be read as an image — nothing was analyzed.",
    })
    data = _post_image(client).json()
    assert data["verdict"] == "UNCERTAIN"
    assert "could not be read" in data["analysis"]
