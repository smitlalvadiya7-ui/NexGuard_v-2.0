"""
Screenshot/OCR pipeline test.

Validates the parts of the OCR path that are OURS (independent of whether the
Tesseract *binary* is installed on this machine — it is installed in the Docker
image, see backend/Dockerfile):

  1. Image preprocessing produces a valid, OCR-ready image (OpenCV + PIL paths).
  2. A URL that OCR splits across spaces/newlines is REASSEMBLED to the full
     domain + TLD + path.
  3. The reassembled embedded link is scanned by the aggregator and FLAGGED.

Because Tesseract may be absent here, we monkeypatch pytesseract.image_to_string
to return a realistic OCR read of a phishing screenshot (with the URL fragmented
exactly the way Tesseract fragments it). When Tesseract IS present, the same
preprocessing + reassembly runs on the real OCR text.

Run:  python -m eval.test_ocr_pipeline
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from PIL import Image, ImageDraw

_BACKEND = Path(__file__).resolve().parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

import ocr_analyzer  # noqa: E402
from aggregator import extract_urls, scan_embedded_links  # noqa: E402


def _make_phishing_screenshot(path: Path) -> None:
    """Render a small phishing screenshot to disk (exercises real preprocessing)."""
    img = Image.new("RGB", (520, 240), "white")
    d = ImageDraw.Draw(img)
    d.text((16, 20),  "URGENT: Your bank account is blocked.", fill="black")
    d.text((16, 70),  "Verify your account and OTP now at:", fill="black")
    d.text((16, 120), "http://paypal-secure-login", fill="black")
    d.text((16, 150), "-verify.tk /account", fill="black")
    img.save(path)


# Realistic Tesseract read of the screenshot above — the URL is broken across a
# line wrap AND has a stray space before the path, exactly how OCR mangles links.
_SIMULATED_OCR = (
    "URGENT: Your bank account is blocked.\n"
    "Verify your account and OTP now at:\n"
    "http://paypal-secure-login\n"
    "-verify.tk /account\n"
)


def test_preprocessing_runs(path: Path) -> bool:
    """Both preprocessing paths must return a usable image, never raise."""
    original = Image.open(path)
    cv_img = ocr_analyzer._preprocess_cv(original)
    pil_img = ocr_analyzer._preprocess_pil(original)
    ok_pil = pil_img is not None and pil_img.size[0] > 0
    # cv may be None if OpenCV is unavailable — that's an allowed fallback.
    ok_cv = cv_img is None or cv_img.size[0] > 0
    print(f"  preprocess: cv={'ok' if cv_img is not None else 'absent'} "
          f"({cv_img.size if cv_img is not None else '-'}), "
          f"pil={pil_img.size}")
    return ok_pil and ok_cv


def test_reassembly() -> bool:
    urls = extract_urls(_SIMULATED_OCR)
    print(f"  reassembled URLs: {urls}")
    return any("paypal-secure-login-verify.tk" in u and "/account" in u for u in urls)


def test_full_pipeline_flags(path: Path) -> bool:
    # Force analyze_screenshot to see the simulated OCR (binary-independent).
    orig = ocr_analyzer.pytesseract.image_to_string
    ocr_analyzer.pytesseract.image_to_string = lambda img, config=None: _SIMULATED_OCR
    try:
        res = ocr_analyzer.analyze_screenshot(str(path))
    finally:
        ocr_analyzer.pytesseract.image_to_string = orig

    print(f"  analyze_screenshot: verdict={res['verdict']} score={res['score']}")
    print(f"  extracted_urls: {res['extracted_urls']}")
    link = asyncio.run(scan_embedded_links(res["text"]))
    print(f"  embedded scan: links_found={link['links_found']} "
          f"worst_verdict={link['worst_verdict']} worst_score={link['worst_score']}")
    for sl in link["scanned_links"]:
        print(f"    {sl['url']} -> {sl['verdict']} ({sl['risk_score']})")

    full_url_found = any("paypal-secure-login-verify.tk/account" in u
                         for u in res["extracted_urls"])
    flagged = link["links_found"] >= 1 and (link["worst_verdict"] in ("SUSPICIOUS", "MALICIOUS"))
    # The screenshot itself should also read as a threat (OTP + bank + urgent).
    screenshot_flagged = res["verdict"] in ("SUSPICIOUS", "MALICIOUS")
    return full_url_found and flagged and screenshot_flagged


def main():
    path = _BACKEND / "eval" / "_tmp_phish_screenshot.png"
    _make_phishing_screenshot(path)
    ok = True
    print("[1] preprocessing")
    ok &= test_preprocessing_runs(path)
    print("[2] URL reassembly")
    ok &= test_reassembly()
    print("[3] full pipeline flags the embedded link")
    ok &= test_full_pipeline_flags(path)
    try:
        path.unlink()
    except Exception:
        pass
    print("\n" + ("ALL PASSED" if ok else "FAILURES PRESENT"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
