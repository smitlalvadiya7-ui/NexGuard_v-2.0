"""
Scam-wording coverage for the big Indian scam families (2026-07-19).

Found via the expanded testdata set: OCR read the lottery / job-fee
screenshots perfectly but score_scam_intent had NO cues for them
(intent 0 -> false SAFE), and the voice rules scored a blatant
digital-arrest script at a false SAFE 36 ("transfer YOUR funds" missed
the money regex; "digital arrest" / "safe account" were not cues).
These tests pin the coverage for both text scorers.
"""

from email_analyzer import score_scam_intent
from voice_analyzer import _score_text

LOTTERY = ("CONGRATULATIONS! You won Rs 25,00,000 in the KBC Lucky Draw "
           "Lottery! To claim, pay the processing fee of Rs 4,999 today. "
           "Send payment now.")
JOB = ("Work from home! Earn Rs 5000 daily. No experience needed. Selected! "
       "Pay Rs 999 registration fee now to receive your offer letter today.")
INVEST = ("GUARANTEED 200% RETURNS in 30 days! Our crypto trading experts "
          "double your money. Minimum invest Rs 10,000. Limited slots - "
          "deposit today!")
CUSTOMS = ("Your parcel is on hold at customs. Pay Rs 250 import duty within "
           "24 hours or the package will be returned.")
ARREST = ("This is inspector Sharma from the cyber crime police. A money "
          "laundering case is registered against your Aadhaar number. You "
          "are under digital arrest. Stay on this call and transfer your "
          "funds to the safe account for verification, or an arrest warrant "
          "will be issued today.")
NORMAL = ("Happy birthday! Hope you have a wonderful day with the family. "
          "We will visit next weekend. Love from all of us!")


# ---------------------------------------------------------------------------
# email / OCR text scorer
# ---------------------------------------------------------------------------

def test_lottery_wording_is_flagged():
    r = score_scam_intent(LOTTERY)
    assert r["intent_score"] >= 40
    assert r["money_request"] is True

def test_job_fee_wording_is_flagged():
    r = score_scam_intent(JOB)
    assert r["intent_score"] >= 40
    assert r["money_request"] is True

def test_investment_wording_is_flagged():
    assert score_scam_intent(INVEST)["intent_score"] >= 40

def test_customs_duty_wording_is_flagged():
    assert score_scam_intent(CUSTOMS)["intent_score"] >= 40

def test_digital_arrest_wording_is_flagged():
    assert score_scam_intent(ARREST)["intent_score"] >= 40

def test_normal_text_stays_clean():
    assert score_scam_intent(NORMAL)["intent_score"] < 20

def test_phrases_match_across_line_wraps():
    # OCR and quoted-printable email bodies wrap lines mid-phrase; "double
    # your\nmoney" must still count (root cause of the investment screenshot
    # under-scoring).
    wrapped = INVEST.replace("double your money", "double\nyour money") \
                    .replace("Minimum invest", "Minimum\ninvest")
    assert score_scam_intent(wrapped)["intent_score"] >= 40


# ---------------------------------------------------------------------------
# voice transcript scorer
# ---------------------------------------------------------------------------

def test_voice_digital_arrest_script_is_malicious():
    r = _score_text(ARREST)
    assert r["verdict"] == "MALICIOUS"
    assert "authority_threat" in r["categories"]
    assert "money" in r["categories"]          # "transfer your funds" must count

def test_voice_normal_text_stays_safe():
    assert _score_text(NORMAL)["verdict"] == "SAFE"


# ---------------------------------------------------------------------------
# screenshot OCR path — must use the SHARED scam brain, not only its own
# small keyword list (root cause of the false SAFE 0: two separate tables)
# ---------------------------------------------------------------------------

def test_screenshot_scorer_uses_the_shared_scam_brain(monkeypatch):
    import ocr_analyzer
    monkeypatch.setattr(ocr_analyzer, "_ocr_variants", lambda p: [LOTTERY])
    r = ocr_analyzer.analyze_screenshot("fake.png")
    assert r["verdict"] in ("SUSPICIOUS", "MALICIOUS")
    assert r["risk_score"] >= 40

def test_screenshot_normal_text_still_safe(monkeypatch):
    import ocr_analyzer
    monkeypatch.setattr(ocr_analyzer, "_ocr_variants", lambda p: [NORMAL])
    r = ocr_analyzer.analyze_screenshot("fake.png")
    assert r["verdict"] == "SAFE"
