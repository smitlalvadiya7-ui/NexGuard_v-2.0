"""
POST /analyze-email merge rule (WORK_PLAN Task 9): a VERIFIED sender's
embedded links only escalate the email when a link carries a CONFIRMED
blocklist flag — lexical/ML/VT-noise link scores never override a verified
origin. Unverified senders keep the plain worst-score merge.

Skipped in the slim CI env (fastapi + app deps not installed there).
"""

import io

import pytest

main = pytest.importorskip("main")

from fastapi.testclient import TestClient  # noqa: E402


GENUINE_EML = (
    "From: ICICI Bank <alerts@icicibank.com>\n"
    "Subject: Your monthly statement\n"
    "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass\n"
    "\n"
    "Dear customer, your statement is ready. Never share your OTP with anyone.\n"
    "View it at https://links.icicibank-mailer.example/track/abc123\n"
)


def _lexical_only_link(score):
    return {
        "links_found": 1,
        "worst_score": score,
        "worst_verdict": "MALICIOUS" if score >= 70 else "SUSPICIOUS",
        "scanned_links": [{
            "url": "https://links.icicibank-mailer.example/track/abc123",
            "verdict": "MALICIOUS" if score >= 70 else "SUSPICIOUS",
            "risk_score": score,
            "sources": [
                {"name": "VirusTotal", "status": "warn", "detail": "2/92 engines flagged"},
                {"name": "Safe Browsing", "status": "clean", "detail": "not listed"},
                {"name": "URLHaus", "status": "clean", "detail": "clean"},
            ],
        }],
    }


def _blocklisted_link(score):
    scan = _lexical_only_link(score)
    scan["scanned_links"][0]["sources"][1] = {
        "name": "Safe Browsing", "status": "flag", "detail": "SOCIAL_ENGINEERING",
    }
    return scan


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setattr(main, "enforce_scan_quota", lambda user, request: None)
    monkeypatch.setattr(main, "save_scan", lambda *a, **k: None)
    main.app.dependency_overrides[main.get_optional_active_user] = lambda: None
    with TestClient(main.app) as c:
        yield c
    main.app.dependency_overrides.pop(main.get_optional_active_user, None)


def _post_eml(client, content):
    return client.post(
        "/analyze-email",
        files={"file": ("mail.eml", io.BytesIO(content.encode()), "message/rfc822")},
    ).json()


def test_lexical_link_noise_never_overrides_verified_sender(client, monkeypatch):
    async def fake_links(_text):
        return _lexical_only_link(80)

    monkeypatch.setattr(main, "scan_embedded_links", fake_links)

    data = _post_eml(client, GENUINE_EML)

    assert data["sender_origin"]["status"] == "verified"
    assert data["verdict"] == "SAFE", data["reasons"]
    assert data["risk_score"] <= 20
    assert data["genuine_ratio"] >= 80
    # transparency: the decision is explained, and the links stay listed
    assert any("not held against" in r for r in data["reasons"])
    assert len(data["scanned_links"]) == 1


def test_blocklisted_link_still_escalates_verified_sender(client, monkeypatch):
    async def fake_links(_text):
        return _blocklisted_link(85)

    monkeypatch.setattr(main, "scan_embedded_links", fake_links)

    data = _post_eml(client, GENUINE_EML)

    assert data["sender_origin"]["status"] == "verified"
    assert data["verdict"] == "MALICIOUS"
    assert data["risk_score"] >= 80


def test_unverified_sender_keeps_plain_worst_score_merge(client, monkeypatch):
    async def fake_links(_text):
        return _lexical_only_link(80)

    monkeypatch.setattr(main, "scan_embedded_links", fake_links)

    eml = (
        "From: Prize Team <win@lucky-draws.example>\n"
        "Subject: You have won\n"
        "\n"
        "Claim at https://links.icicibank-mailer.example/track/abc123\n"
    )
    data = _post_eml(client, eml)

    assert data["sender_origin"]["status"] != "verified"
    assert data["risk_score"] >= 80
    assert data["verdict"] == "MALICIOUS"
