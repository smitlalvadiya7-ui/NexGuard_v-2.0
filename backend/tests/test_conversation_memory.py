"""
C3 — conversation memory. The support bot remembers the last few turns:
a follow-up like "scan it again" or "is it safe now?" re-runs the scan on the
URL from earlier in the conversation instead of answering with a confused FAQ
match. Pure logic in support_tools.py; endpoint behavior with the scanners
monkeypatched (same harness as the C1 tests).
"""

import pytest

support_tools = pytest.importorskip("support_tools")
main = pytest.importorskip("main")

from fastapi.testclient import TestClient  # noqa: E402

from support_tools import (  # noqa: E402
    history_url,
    is_followup_scan,
    normalize_history,
)


# ---------------------------------------------------------------------------
# is_followup_scan — tight patterns, no URL in the text
# ---------------------------------------------------------------------------

def test_followup_phrases_match():
    for q in ("scan it again", "please check that again", "rescan",
              "re-scan it", "is it safe now?", "what about now?",
              "check this again"):
        assert is_followup_scan(q), q

def test_normal_questions_do_not_match():
    for q in ("How does the QR scanner work?", "can you scan a qr code",
              "what is phishing", "how do I report a wrong verdict",
              ""):
        assert not is_followup_scan(q), q


# ---------------------------------------------------------------------------
# history_url — newest user URL wins; bot turns are ignored
# ---------------------------------------------------------------------------

def test_history_url_finds_newest_user_url():
    hist = [
        {"role": "user", "text": "is https://old.example/a safe?"},
        {"role": "bot", "text": "Verdict: SAFE …"},
        {"role": "user", "text": "and what about https://new.example/b ?"},
        {"role": "bot", "text": "Verdict: MALICIOUS …"},
    ]
    assert history_url(hist) == "https://new.example/b"

def test_history_url_ignores_bot_turns_and_junk():
    hist = [
        {"role": "bot", "text": "I ran a full scan on https://bot-echo.example/."},
        {"role": "user", "text": "thanks!"},
    ]
    assert history_url(hist) is None
    assert history_url(None) is None
    assert history_url([{"bad": "shape"}, "junk", 42]) is None


# ---------------------------------------------------------------------------
# normalize_history — caps + shape validation (client data is untrusted)
# ---------------------------------------------------------------------------

def test_normalize_history_caps_turns_and_length():
    hist = [{"role": "user", "text": f"turn {i} " + "x" * 5000} for i in range(20)]
    out = normalize_history(hist)
    assert len(out) == 6                      # last 6 turns only
    assert out[-1]["text"].startswith("turn 19")
    assert all(len(t["text"]) <= 2000 for t in out)

def test_normalize_history_drops_junk_items():
    out = normalize_history([
        {"role": "user", "text": "ok"},
        {"role": "evil", "text": "x"},          # unknown role
        {"role": "user", "text": ""},           # empty
        "junk", 42, None,
    ])
    assert out == [{"role": "user", "text": "ok"}]
    assert normalize_history("junk") == []


# ---------------------------------------------------------------------------
# /support/ask — the endpoint honors history
# ---------------------------------------------------------------------------

MALICIOUS_RESULT = {
    "verdict": "MALICIOUS", "risk_score": 88, "confidence": 80,
    "plain_summary": "Fake login page.", "reasons": ["Credential form"],
}


@pytest.fixture()
def client(monkeypatch):
    async def fake_full_scan(url):
        return dict(MALICIOUS_RESULT, url=url)

    monkeypatch.setattr(main, "full_scan", fake_full_scan)
    monkeypatch.setattr(main, "enforce_scan_quota", lambda user, request: None)
    monkeypatch.setattr(main, "save_scan", lambda *a, **k: None)
    main.app.dependency_overrides[main.get_optional_active_user] = lambda: None
    with TestClient(main.app) as c:
        yield c
    main.app.dependency_overrides.pop(main.get_optional_active_user, None)


def test_followup_rescan_uses_history_url(client):
    data = client.post("/support/ask", json={
        "question": "scan it again",
        "history": [
            {"role": "user", "text": "is https://evil.tk/login a scam?"},
            {"role": "bot", "text": "Verdict: MALICIOUS — risk score 88/100."},
        ],
    }).json()
    assert data["action"] == "scanned_url"
    assert data["scan"]["target"] == "https://evil.tk/login"
    assert "again" in data["answer"].lower()

def test_followup_without_history_url_stays_a_faq_answer(client):
    data = client.post("/support/ask", json={
        "question": "scan it again",
        "history": [{"role": "user", "text": "hello"}],
    }).json()
    assert data.get("action") != "scanned_url"

def test_history_field_is_optional(client):
    data = client.post("/support/ask", json={"question": "How do I scan a QR code?"}).json()
    assert data["matched"] is True
