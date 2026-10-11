"""
C1 — the support bot gets scan tools: a pasted link (or scam-looking message)
in /support/ask runs the REAL scanners and answers with the verdict + why,
while plain questions still get FAQ answers. Pure logic in support_tools.py;
endpoint behavior with the scanners monkeypatched.

Skipped in the slim CI env (fastapi + app deps not installed there).
"""

import pytest

support_tools = pytest.importorskip("support_tools")
main = pytest.importorskip("main")

from fastapi.testclient import TestClient  # noqa: E402

from support_tools import (  # noqa: E402
    bot_message_reply,
    bot_quota_reply,
    bot_scan_reply,
    extract_url,
    looks_like_message,
)

# ---------------------------------------------------------------------------
# extract_url
# ---------------------------------------------------------------------------

def test_extract_url_finds_scheme_urls():
    assert extract_url("is https://evil.tk/login a scam?") == "https://evil.tk/login"
    assert extract_url("check http://paypal-verify.com please") == "http://paypal-verify.com"


def test_extract_url_finds_www_urls():
    assert extract_url("what about www.free-iphone.club then") == "www.free-iphone.club"


def test_extract_url_bare_domain_needs_scan_intent():
    # with intent wording -> detected
    assert extract_url("is paypal-verify.tk safe?") == "paypal-verify.tk"
    assert extract_url("can you scan bit.ly/x7 for me") == "bit.ly/x7"
    # without any scan-intent wording -> not treated as a scan request
    assert extract_url("we discussed node.js at work today") is None


def test_extract_url_strips_trailing_punctuation():
    assert extract_url("look at https://evil.tk/login. Is it ok?") == "https://evil.tk/login"


def test_extract_url_ignores_email_addresses():
    assert extract_url("I got mail from support@paypal.com — is that normal?") is None


def test_extract_url_plain_questions_have_none():
    assert extract_url("How does the URL scanner work?") is None
    assert extract_url("") is None
    assert extract_url(None) is None


# ---------------------------------------------------------------------------
# looks_like_message
# ---------------------------------------------------------------------------

def test_looks_like_message_on_header_lines():
    assert looks_like_message("Subject: You won!\nFrom: prize@lotto.biz\nClaim now")


def test_looks_like_message_on_long_text():
    long_text = ("dear customer your account will be suspended unless you "
                 "verify your identity immediately please send your card "
                 "number and otp code to avoid permanent closure of account")
    assert looks_like_message(long_text)


def test_short_questions_are_not_messages():
    assert not looks_like_message("How do I scan a QR code?")


# ---------------------------------------------------------------------------
# Reply composition
# ---------------------------------------------------------------------------

MALICIOUS_RESULT = {
    "verdict": "MALICIOUS",
    "risk_score": 100,
    "confidence": 100,
    "plain_summary": "Dangerous site — do not enter login or payment details.",
    "flags": ["Suspicious domain extension", "Possible impersonation: paypal", "x", "y"],
}


def test_bot_scan_reply_carries_verdict_and_reasons():
    reply = bot_scan_reply("https://evil.tk/login", MALICIOUS_RESULT)
    assert reply["matched"] is True
    assert reply["action"] == "scanned_url"
    assert "MALICIOUS" in reply["answer"]
    assert "100/100" in reply["answer"]
    assert "Possible impersonation: paypal" in reply["answer"]
    assert reply["scan"]["verdict"] == "MALICIOUS"
    assert reply["scan"]["target"] == "https://evil.tk/login"
    assert reply["related"]  # follow-up questions offered


def test_bot_scan_reply_safe_is_reassuring_but_honest():
    reply = bot_scan_reply("https://example.com", {"verdict": "SAFE", "risk_score": 0, "confidence": 95})
    assert "SAFE" in reply["answer"]
    assert reply["scan"]["risk_score"] == 0


def test_bot_message_reply_summarizes_the_message_verdict():
    reply = bot_message_reply({
        "verdict": "SUSPICIOUS", "risk_score": 55,
        "flags": ["Urgency pressure wording", "Asks for OTP"],
    })
    assert reply["action"] == "scanned_message"
    assert "SUSPICIOUS" in reply["answer"]
    assert "Urgency pressure wording" in reply["answer"]


def test_bot_quota_reply_is_polite_not_an_error():
    reply = bot_quota_reply()
    assert reply["matched"] is True
    assert "limit" in reply["answer"].lower()


# ---------------------------------------------------------------------------
# /support/ask endpoint
# ---------------------------------------------------------------------------

@pytest.fixture()
def client(monkeypatch):
    async def fake_full_scan(url):
        return dict(MALICIOUS_RESULT, url=url)

    monkeypatch.setattr(main, "full_scan", fake_full_scan)
    monkeypatch.setattr(main, "analyze_email", lambda text: {
        "verdict": "SUSPICIOUS", "risk_score": 60, "flags": ["Asks for OTP"],
    })
    monkeypatch.setattr(main, "enforce_scan_quota", lambda user, request: None)
    monkeypatch.setattr(main, "save_scan", lambda *a, **k: None)
    main.app.dependency_overrides[main.get_optional_active_user] = lambda: None
    with TestClient(main.app) as c:
        yield c
    main.app.dependency_overrides.pop(main.get_optional_active_user, None)


def test_ask_with_url_runs_the_scanner(client):
    data = client.post("/support/ask", json={"question": "is https://evil.tk/login a scam?"}).json()
    assert data["action"] == "scanned_url"
    assert "MALICIOUS" in data["answer"]
    assert data["scan"]["target"] == "https://evil.tk/login"


def test_ask_plain_faq_still_answers_from_faq(client):
    data = client.post("/support/ask", json={"question": "How do I scan a QR code?"}).json()
    assert data["matched"] is True
    assert "action" not in data or data.get("action") is None
    assert "QR" in data["answer"] or "qr" in data["answer"].lower()


def test_ask_pasted_scam_message_runs_message_analysis(client):
    scam = ("Subject: Account locked\nFrom: security@fake-bank.biz\n"
            "Dear customer verify your OTP immediately or lose access")
    data = client.post("/support/ask", json={"question": scam}).json()
    assert data["action"] == "scanned_message"
    assert "SUSPICIOUS" in data["answer"]


def test_ask_over_quota_answers_politely(client, monkeypatch):
    from fastapi.responses import JSONResponse
    monkeypatch.setattr(main, "enforce_scan_quota",
                        lambda user, request: JSONResponse(status_code=429, content={"error": "free_limit"}))
    r = client.post("/support/ask", json={"question": "scan https://evil.tk please"})
    assert r.status_code == 200          # the BOT answers; no raw 429 at the chat surface
    data = r.json()
    assert "limit" in data["answer"].lower()
