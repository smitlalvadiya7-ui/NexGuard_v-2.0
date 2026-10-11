"""
Screenshot analyzer honesty (BUG 2, WORK_PLAN Task 1): when OCR reads only
garbage or nothing, the analyzer must say UNKNOWN — "could not read enough
text" — never a confident SAFE 0 (live finding 2026-07-16: both phishing
sample screenshots returned SAFE 0 on OCR noise like "ofa ty a A").

Skipped in the slim CI env (PIL/pytesseract not installed there).
"""

import pytest

ocr_analyzer = pytest.importorskip("ocr_analyzer")


def _fake_ocr(monkeypatch, texts):
    monkeypatch.setattr(ocr_analyzer, "_ocr_variants", lambda path: texts)


def test_garbage_ocr_is_unknown_not_safe(monkeypatch, tmp_path):
    # the exact noise class seen live on the phishing sample screenshots
    _fake_ocr(monkeypatch, ["ofa\nty a A\noO a"])
    res = ocr_analyzer.analyze_screenshot(str(tmp_path / "shot.png"))
    assert res["verdict"] == "UNKNOWN"
    assert any("enough" in r.lower() or "read" in r.lower() for r in res["reasons"])


def test_no_text_at_all_is_unknown(monkeypatch, tmp_path):
    _fake_ocr(monkeypatch, ["   "])
    res = ocr_analyzer.analyze_screenshot(str(tmp_path / "shot.png"))
    assert res["verdict"] == "UNKNOWN"


def test_readable_clean_text_stays_safe(monkeypatch, tmp_path):
    _fake_ocr(monkeypatch, ["meeting notes for tomorrow agenda items and budget review"])
    res = ocr_analyzer.analyze_screenshot(str(tmp_path / "shot.png"))
    assert res["verdict"] == "SAFE"


def test_scam_text_still_scores_even_when_short(monkeypatch, tmp_path):
    # A thin read that DID match scam signals keeps its verdict — thinness
    # only blocks confident-SAFE, never detection.
    _fake_ocr(monkeypatch, ["enter OTP and password to verify bank account urgent"])
    res = ocr_analyzer.analyze_screenshot(str(tmp_path / "shot.png"))
    assert res["verdict"] in ("SUSPICIOUS", "MALICIOUS")


def test_ocr_engine_failure_stays_error(monkeypatch, tmp_path):
    _fake_ocr(monkeypatch, [])
    res = ocr_analyzer.analyze_screenshot(str(tmp_path / "shot.png"))
    assert res["verdict"] == "ERROR"


def test_noise_yielding_several_junk_fragments_is_unknown(monkeypatch, tmp_path):
    # Live 2026-08-12: testdata/screenshots/screenshot_unreadable.png (pure
    # noise, no readable text) came back SAFE 0. The guard counted runs of 3+
    # letters and this noise happens to contain four — "orn", "oll", "ail",
    # "fun" — so the "< 3" threshold never fired. None of them is a word.
    # Counting letter-runs cannot tell four words from four fragments.
    _fake_ocr(monkeypatch, [
        "a. ! wa .\u201d \u201che\nLa a, ay\u2019 f\norn r| oll > PL |\n"
        "i \u201c= ail\n\u2018_\u00ab I \u2018 +\u201d ' fun\n( ry . ty, :\n1 Se ! : ?"
    ])
    res = ocr_analyzer.analyze_screenshot(str(tmp_path / "shot.png"))
    assert res["verdict"] == "UNKNOWN", f"noise graded {res['verdict']}, not UNKNOWN"


def test_short_but_real_chat_text_stays_safe(monkeypatch, tmp_path):
    # Guarding the other direction: a screenshot of an ordinary short message
    # is readable and harmless. It must not be downgraded to UNKNOWN just
    # because its words are short — chat screenshots are a core input.
    _fake_ocr(monkeypatch, ["see you at the gym"])
    res = ocr_analyzer.analyze_screenshot(str(tmp_path / "shot.png"))
    assert res["verdict"] == "SAFE", f"readable chat graded {res['verdict']}"
