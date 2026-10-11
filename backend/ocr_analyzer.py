from PIL import Image, ImageOps, ImageFilter
import os
import re
import shutil
import pytesseract

# Use Tesseract if installed. Do not hard-crash on PCs where path is different.
DEFAULT_TESSERACT = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
if os.path.exists(DEFAULT_TESSERACT):
    pytesseract.pytesseract.tesseract_cmd = DEFAULT_TESSERACT
elif shutil.which("tesseract"):
    pytesseract.pytesseract.tesseract_cmd = shutil.which("tesseract")

SCAM_WORDS = {
    "otp": 30,
    "verify": 20,
    "bank": 20,
    "password": 28,
    "security alert": 26,
    "urgent": 18,
    "account blocked": 30,
    "send money": 35,
    "gift card": 28,
    "crypto": 18,
    "wallet": 18,
    "cvv": 35,
    "kyc": 24,
    "login": 16,
    "limited time": 18,
    "click here": 18,
    "payment failed": 24,
    "update account": 26,
}


def _verdict(score):
    return "MALICIOUS" if score >= 70 else "SUSPICIOUS" if score >= 40 else "SAFE"


# ---------------------------------------------------------------------------
# Image preprocessing — grayscale + upscale + threshold to lift OCR accuracy
# on small / low-contrast phishing screenshots. Uses OpenCV when available
# (adaptive + Otsu threshold) and falls back to a pure-PIL pipeline otherwise.
# ---------------------------------------------------------------------------

_MIN_OCR_WIDTH = 1000   # upscale anything narrower than this — Tesseract likes ~300 DPI


def _preprocess_pil(image: "Image.Image") -> "Image.Image":
    """Pure-PIL fallback: EXIF-normalise, grayscale, autocontrast, upscale, sharpen."""
    image = ImageOps.exif_transpose(image)
    image = image.convert("L")
    image = ImageOps.autocontrast(image)
    # Upscale small images so thin glyphs survive thresholding.
    if image.width < _MIN_OCR_WIDTH:
        scale = min(3.0, _MIN_OCR_WIDTH / max(1, image.width))
        image = image.resize(
            (int(image.width * scale), int(image.height * scale)),
            Image.LANCZOS,
        )
    image = image.filter(ImageFilter.SHARPEN)
    return image


def _preprocess_cv(image: "Image.Image"):
    """
    OpenCV pipeline -> returns a PIL image ready for OCR, or None if cv2 is
    unavailable / the conversion fails (caller then uses the PIL fallback).
    Steps: grayscale -> upscale -> denoise -> Otsu threshold (binarise).
    """
    try:
        import cv2
        import numpy as np

        image = ImageOps.exif_transpose(image).convert("RGB")
        arr = np.array(image)[:, :, ::-1]            # PIL RGB -> OpenCV BGR
        gray = cv2.cvtColor(arr, cv2.COLOR_BGR2GRAY)

        h, w = gray.shape[:2]
        if w < _MIN_OCR_WIDTH:
            scale = min(3.0, _MIN_OCR_WIDTH / max(1, w))
            gray = cv2.resize(gray, (int(w * scale), int(h * scale)),
                              interpolation=cv2.INTER_CUBIC)

        gray = cv2.fastNlMeansDenoising(gray, h=10)
        # Otsu picks the threshold automatically — robust across light/dark UIs.
        _, binary = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        return Image.fromarray(binary)
    except Exception:
        return None


def _ocr_variants(image_path: str) -> list[str]:
    """
    Run OCR over a few preprocessing variants and Tesseract page-segmentation
    modes, returning every non-empty text result. Combining variants recovers
    URLs that one mode splits or drops. Fail-safe: returns [] if OCR can't run.
    """
    try:
        original = Image.open(image_path)
    except Exception:
        return []

    candidates = []
    cv_img = _preprocess_cv(original)
    if cv_img is not None:
        candidates.append(cv_img)
    candidates.append(_preprocess_pil(original))

    texts: list[str] = []
    # psm 3 = full auto page; psm 6 = assume a uniform block (better for chat/UI
    # screenshots where text is one column). Try both per variant.
    for img in candidates:
        for psm in (3, 6):
            try:
                t = pytesseract.image_to_string(img, config=f"--oem 3 --psm {psm}")
                if t and t.strip():
                    texts.append(t)
            except Exception:
                continue
    return texts


def _reassembled_urls(text: str) -> list[str]:
    """Reassemble OCR-split URLs using the shared aggregator logic (lazy import)."""
    try:
        from aggregator import extract_urls
        return extract_urls(text or "")
    except Exception:
        return []


def analyze_screenshot(image_path):
    texts = _ocr_variants(image_path)

    if not texts:
        # OCR engine genuinely couldn't run (missing Tesseract) or image unreadable.
        return {
            "verdict": "ERROR",
            "score": 0,
            "risk_score": 0,
            "text": "",
            "extracted_urls": [],
            "reasons": ["OCR could not read this image"],
            "indicators": ["OCR could not read this image"],
            "highlighted_words": [],
            "ai_explanation": (
                "OCR engine failed or the image was unreadable. Check the Tesseract "
                "installation or upload a clearer screenshot."
            ),
        }

    # Pick the variant whose text yields the most reassembled URLs, then the most
    # characters — i.e. the cleanest read of any embedded link.
    best_text = max(texts, key=lambda t: (len(_reassembled_urls(t)), len(t)))
    text = best_text.strip()
    urls = _reassembled_urls(text)
    lower = text.lower()

    if not text:
        # Image was readable but contained no recognisable text. Nothing was
        # analyzed, so nothing is "safe" (BUG 2, WORK_PLAN Task 1).
        return {
            "verdict": "UNKNOWN",
            "score": 0,
            "risk_score": 0,
            "text": "",
            "extracted_urls": [],
            "reasons": ["No readable text found in the image — could not judge it"],
            "indicators": ["No readable text found in the image — could not judge it"],
            "highlighted_words": [],
            "ai_explanation": (
                "No readable text was detected, so this screenshot could not be "
                "judged. This is NOT a safe verdict — try a clearer screenshot."
            ),
        }

    score = 0
    reasons = []
    highlights = []

    for word, amount in SCAM_WORDS.items():
        if word in lower:
            score += amount
            reasons.append(f"Scam indicator detected: {word}")
            highlights.append(word)

    # The SHARED scam-wording brain (email_analyzer.score_scam_intent) covers
    # whole scam families this small keyword list does not (lottery fees, job
    # registration fees, customs duty, digital arrest…). Take the stronger of
    # the two reads — 2026-07-19: lottery/job screenshots scored a false SAFE 0
    # because the two scorers were separate tables.
    from email_analyzer import score_scam_intent
    intent = score_scam_intent(text)
    if intent["intent_score"] > score:
        score = intent["intent_score"]
    for cue in intent["matched_cues"]:
        if cue not in highlights:
            reasons.append(f"Scam wording detected: {cue}")
            highlights.append(cue)

    if "urgent" in lower and any(x in lower for x in ["verify", "bank", "otp", "password", "login"]):
        score += 20
        reasons.append("Urgency pressure combined with banking/security request")

    if "http" in lower and any(x in lower for x in [".ru", ".xyz", ".tk", "bit.ly", "tinyurl"]):
        score += 20
        reasons.append("Suspicious URL/domain pattern visible in screenshot")

    if urls:
        reasons.append(f"Embedded link(s) found: {', '.join(urls[:3])}")

    score = min(100, int(score))
    verdict = _verdict(score)

    # OCR-noise guard (BUG 2): if the read yielded almost no real words AND
    # nothing matched, the image was not actually analyzed — say so instead
    # of a confident SAFE 0 (live: phishing screenshots read as "ofa ty a A"
    # and sailed through as safe). A thin read that DID match keeps its
    # verdict — thinness never blocks detection.
    # Counting runs of letters is not enough: the 2026-08-12 noise sample
    # ("orn r| oll > PL | ... ail ... fun") yields four such runs and none is
    # a word, so it scored a confident SAFE 0. Require WORD-shaped evidence,
    # via either of two routes, because prose and chat look different:
    #   (a) three or more longer words (4+ letters) — ordinary prose; or
    #   (b) three or more short whole words (3+ letters) in text that is
    #       mostly letters — "see you at the gym".
    # Both noise samples fail both routes: the old one ("ofa ty a A") has only
    # one 3-letter token, and the new one floats its fragments in punctuation
    # (56% letters, well under the 80% a real read shows).
    long_words = re.findall(r"[a-zA-Z]{4,}", text)
    word_tokens = [t for t in text.split() if t.isalpha() and len(t) >= 3]
    dense = [c for c in text if not c.isspace()]
    letter_ratio = sum(c.isalpha() for c in dense) / max(1, len(dense))
    legible = len(long_words) >= 3 or (len(word_tokens) >= 3 and letter_ratio >= 0.8)
    if score == 0 and not legible:
        return {
            "verdict": "UNKNOWN",
            "score": 0,
            "risk_score": 0,
            "text": text,
            "extracted_urls": urls,
            "reasons": ["Could not read enough text from this image to judge it"],
            "indicators": ["Could not read enough text from this image to judge it"],
            "highlighted_words": [],
            "ai_explanation": (
                "OCR could not extract enough readable text to analyze this "
                "screenshot. This is NOT a safe verdict — try a clearer or "
                "higher-resolution screenshot."
            ),
        }

    return {
        "verdict": verdict,
        "score": score,
        "risk_score": score,
        "text": text,
        "extracted_urls": urls,
        "reasons": reasons,
        "indicators": reasons,
        "highlighted_words": highlights,
        "ai_explanation": "; ".join(reasons) if reasons else "No major scam indicators detected in screenshot.",
    }
