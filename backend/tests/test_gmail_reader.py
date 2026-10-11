"""
Gmail reader honesty contract (WORK_PLAN Task 2).

read_gmail() must NEVER fabricate an inbox:
  * credentials.json missing  -> {"status": "not_connected", "detail": ...}
  * live fetch raises         -> {"status": "error", "detail": ...}
  * live fetch succeeds       -> {"status": "connected", "emails": [...]}
Demo samples exist ONLY behind the explicit read_sample_emails(), labeled
source="sample" — never mixed into a live-looking response.
"""

from pathlib import Path

import gmail_reader


def test_read_gmail_not_connected_when_credentials_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(gmail_reader, "CREDENTIALS_PATH", tmp_path / "credentials.json")

    result = gmail_reader.read_gmail()

    assert isinstance(result, dict)
    assert result["status"] == "not_connected"
    assert "credentials.json" in result.get("detail", "")
    assert result.get("emails", []) == []


def test_read_gmail_error_returns_error_status_without_fake_rows(monkeypatch, tmp_path):
    fake_creds = tmp_path / "credentials.json"
    fake_creds.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(gmail_reader, "CREDENTIALS_PATH", fake_creds)

    def boom():
        raise RuntimeError("boom: token refresh failed")

    monkeypatch.setattr(gmail_reader, "_fetch_live_emails", boom)

    result = gmail_reader.read_gmail()

    assert result["status"] == "error"
    assert "boom" in result["detail"]
    # the old behavior injected a fake "SUSPICIOUS 35" row — must be gone
    assert result.get("emails", []) == []


def test_read_gmail_connected_returns_live_emails(monkeypatch, tmp_path):
    fake_creds = tmp_path / "credentials.json"
    fake_creds.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(gmail_reader, "CREDENTIALS_PATH", fake_creds)

    live = [{
        "subject": "Hello", "from": "a@b.example", "verdict": "SAFE",
        "score": 0, "risk_score": 0, "reasons": [],
        "auth_results": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "body": "hi", "source": "gmail",
    }]
    monkeypatch.setattr(gmail_reader, "_fetch_live_emails", lambda: live)

    result = gmail_reader.read_gmail()

    assert result["status"] == "connected"
    assert result["emails"] == live


def test_read_gmail_connected_empty_inbox_stays_connected(monkeypatch, tmp_path):
    """An empty inbox must NOT fall back to demo samples (old bug)."""
    fake_creds = tmp_path / "credentials.json"
    fake_creds.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(gmail_reader, "CREDENTIALS_PATH", fake_creds)
    monkeypatch.setattr(gmail_reader, "_fetch_live_emails", lambda: [])

    result = gmail_reader.read_gmail()

    assert result["status"] == "connected"
    assert result["emails"] == []


def test_read_sample_emails_labeled_as_samples(tmp_path, monkeypatch):
    """
    Demo-mode samples are labelled `source="sample"` and never fabricated.

    This used to assert `len(samples) >= 1` on the comment "repo ships .eml
    files in samples/". It does not — `samples/` is gitignored, so the files it
    was reading were leftover scan artifacts in one developer's working copy.
    Any fresh clone failed here, which is how it surfaced: building a clean
    deployment from `git archive` produced a tree with no samples/ at all.

    So the test now provides its own .eml instead of depending on whatever
    happens to be lying around.
    """
    sample_dir = tmp_path / "samples"
    sample_dir.mkdir()
    (sample_dir / "temp_test.eml").write_text(
        "From: sender@example.com\n"
        "To: victim@example.com\n"
        "Subject: Verify your account now\n"
        "\n"
        "Your account will be closed. Confirm at http://verify-account.example/\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(gmail_reader, "__file__", str(tmp_path / "backend" / "gmail_reader.py"))

    samples = gmail_reader.read_sample_emails()

    assert len(samples) >= 1
    for email in samples:
        assert email["source"] == "sample"
        assert "subject" in email and "verdict" in email
    # the fabricated fallback rows of the old implementation must be gone
    subjects = {e["subject"] for e in samples}
    assert "Gmail scan fallback" not in subjects
    assert "Gmail not connected" not in subjects
