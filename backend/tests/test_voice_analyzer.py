"""
Voice analyzer v2 (WORK_PLAN Task 10):
  * BUG 3 — no transcript -> verdict UNKNOWN, never SAFE
  * scam coverage beyond banking: social media, delivery/customs, job offers,
    investment, lottery/KBC — not just "otp bank immediately"
  * any spoken language: Whisper translates to English before intent scoring,
    and the detected language is reported
  * a fake-vs-real ratio + confidence level on every result

Skipped in the slim CI env (numpy not installed there).
"""

import pytest

voice_analyzer = pytest.importorskip("voice_analyzer")


def _fake_stt(monkeypatch, text, note=None, language="en"):
    monkeypatch.setattr(voice_analyzer, "_speech_to_text", lambda p: (text, note, language))


def _analyze(tmp_path):
    p = tmp_path / "call.wav"
    p.write_bytes(b"RIFFfake")
    return voice_analyzer.analyze_voice(str(p))


# ---------------------------------------------------------------------------
# BUG 3 — honesty
# ---------------------------------------------------------------------------

def test_no_transcript_is_unknown_not_safe(monkeypatch, tmp_path):
    _fake_stt(monkeypatch, "", note=None, language=None)
    res = _analyze(tmp_path)
    assert res["verdict"] == "UNKNOWN"
    assert any("transcript" in r.lower() for r in res["reasons"])


def test_failed_stt_is_unknown_with_note(monkeypatch, tmp_path):
    _fake_stt(monkeypatch, "", note="Whisper transcription failed: boom", language=None)
    res = _analyze(tmp_path)
    assert res["verdict"] == "UNKNOWN"
    assert any("failed" in r.lower() for r in res["reasons"])


# ---------------------------------------------------------------------------
# New scam categories — all platforms, not just banking
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text,category", [
    ("your instagram account will be banned today, verify your account to keep your blue tick",
     "social_media"),
    ("your parcel is held at customs, pay the customs duty of 250 rupees to release the package",
     "delivery"),
    ("simple work from home job, earn 5000 per day, just pay a small registration fee to join",
     "job_offer"),
    ("join our trading group for guaranteed returns, we will double your money in one month",
     "investment"),
    ("congratulations you have won the kbc lucky draw prize money of 25 lakh",
     "lottery"),
])
def test_wider_scam_categories_fire(monkeypatch, tmp_path, text, category):
    _fake_stt(monkeypatch, text)
    res = _analyze(tmp_path)
    assert category in res["matched_cues"], res
    assert res["verdict"] in ("SUSPICIOUS", "MALICIOUS"), (res["score"], res["reasons"])


def test_normal_conversation_stays_safe(monkeypatch, tmp_path):
    _fake_stt(monkeypatch, "hey are we still on for lunch tomorrow at the usual place")
    res = _analyze(tmp_path)
    assert res["verdict"] == "SAFE"
    assert res["scam_ratio"] <= 10


# ---------------------------------------------------------------------------
# Language handling
# ---------------------------------------------------------------------------

def test_detected_language_is_reported(monkeypatch, tmp_path):
    # Whisper translates non-English speech to English before scoring, so the
    # English intent rules catch a Hindi scam call; the language is surfaced.
    _fake_stt(monkeypatch,
              "your bank account has been blocked, share the one time password to unblock",
              language="hi")
    res = _analyze(tmp_path)
    assert res["language"] == "hi"
    assert res["verdict"] in ("SUSPICIOUS", "MALICIOUS")


# ---------------------------------------------------------------------------
# Ratio + confidence
# ---------------------------------------------------------------------------

def test_ratio_and_confidence_always_present(monkeypatch, tmp_path):
    _fake_stt(monkeypatch, "hello this is a normal voicemail about the meeting agenda")
    res = _analyze(tmp_path)
    assert "scam_ratio" in res and "genuine_ratio" in res and "confidence" in res
    assert res["genuine_ratio"] == 100 - res["scam_ratio"]


def test_classic_vishing_scores_high_ratio_high_confidence(monkeypatch, tmp_path):
    _fake_stt(monkeypatch,
              "this is your bank security team, your account will be blocked today, "
              "read me the one time password immediately to keep it active")
    res = _analyze(tmp_path)
    assert res["scam_ratio"] >= 70
    assert res["confidence"] == "High"
    assert res["verdict"] == "MALICIOUS"


def test_unknown_has_low_confidence_and_no_fake_ratio_claim(monkeypatch, tmp_path):
    _fake_stt(monkeypatch, "", note=None, language=None)
    res = _analyze(tmp_path)
    assert res["confidence"] == "Low"
    assert res["scam_ratio"] is None
