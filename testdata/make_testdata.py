"""
Generate the binary NexGuard test files (WORK_PLAN Task 11): QR images,
rendered screenshots, and TTS voice clips. Text files (.eml, urls.txt) are
committed directly; this script produces the assets that are awkward to store
by hand. Re-run any time — it overwrites in place.

    py testdata/make_testdata.py

Dependencies are all already in the backend venv (opencv, Pillow). Voice
clips use Windows SAPI (pyttsx3 if present, else PowerShell System.Speech),
so they only generate on Windows; everything else is cross-platform.
"""
import os
import subprocess
import sys
import wave

HERE = os.path.dirname(os.path.abspath(__file__))
QR_DIR = os.path.join(HERE, "qr")
SHOT_DIR = os.path.join(HERE, "screenshots")
VOICE_DIR = os.path.join(HERE, "voice")
IMG_AI_DIR = os.path.join(HERE, "image_origin", "ai")
IMG_REAL_DIR = os.path.join(HERE, "image_origin", "real")
CORPUS = os.path.join(HERE, "..", "backend", "eval", "_image_corpus")

PHISH_TEST_URL = "http://testsafebrowsing.appspot.com/s/phishing.html"
MALWARE_TEST_URL = "http://testsafebrowsing.appspot.com/s/malware.html"


def _ensure_dirs():
    for d in (QR_DIR, SHOT_DIR, VOICE_DIR, IMG_AI_DIR, IMG_REAL_DIR):
        os.makedirs(d, exist_ok=True)


# ---------------------------------------------------------------------------
# QR codes
# ---------------------------------------------------------------------------
def make_qr(data, path):
    import cv2
    enc = cv2.QRCodeEncoder.create()
    img = enc.encode(data)
    img = cv2.resize(img, (480, 480), interpolation=cv2.INTER_NEAREST)
    cv2.imwrite(path, img)
    print(f"  wrote {os.path.relpath(path, HERE)}  <- {data}")


# ---------------------------------------------------------------------------
# Screenshots — render text crisply so OCR reads it reliably
# ---------------------------------------------------------------------------
def _render_text(lines, path, size=(720, 420)):
    from PIL import Image, ImageDraw, ImageFont
    img = Image.new("RGB", size, "white")
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("arial.ttf", 28)
    except Exception:
        font = ImageFont.load_default()
    y = 30
    for line in lines:
        draw.text((30, y), line, fill="black", font=font)
        y += 46
    img.save(path)
    print(f"  wrote {os.path.relpath(path, HERE)}")


def _render_noise(path, size=(400, 300)):
    # A realistic "too blurry / low-contrast to read" screenshot. Pure
    # high-frequency RGB noise makes Tesseract HALLUCINATE gibberish words;
    # a smooth low-contrast blur is the honest unreadable case and yields no
    # OCR text -> the analyzer correctly returns UNKNOWN (BUG 2).
    import numpy as np
    from PIL import Image, ImageFilter
    base = 150 + (np.random.rand(size[1], size[0], 3) * 24 - 12)  # faint mottling
    img = Image.fromarray(base.clip(0, 255).astype("uint8"))
    img = img.filter(ImageFilter.GaussianBlur(6))
    img.save(path)
    print(f"  wrote {os.path.relpath(path, HERE)}  (blurry / unreadable)")


# ---------------------------------------------------------------------------
# Voice — Windows TTS -> WAV
# ---------------------------------------------------------------------------
def make_voice(text, path, voice_hint=None):
    # Preferred: pyttsx3 (offline SAPI wrapper) if installed.
    try:
        import pyttsx3
        engine = pyttsx3.init()
        if voice_hint:
            for v in engine.getProperty("voices"):
                if voice_hint.lower() in (v.name or "").lower() or voice_hint.lower() in (v.id or "").lower():
                    engine.setProperty("voice", v.id)
                    break
        engine.setProperty("rate", 160)
        engine.save_to_file(text, path)
        engine.runAndWait()
        if os.path.exists(path) and os.path.getsize(path) > 1000:
            print(f"  wrote {os.path.relpath(path, HERE)}")
            return True
    except Exception:
        pass

    # Fallback: PowerShell System.Speech (Windows only).
    if sys.platform == "win32":
        ps = (
            "Add-Type -AssemblyName System.Speech; "
            "$s = New-Object System.Speech.Synthesis.SpeechSynthesizer; "
            f"$s.SetOutputToWaveFile('{path}'); "
            f"$s.Speak(@'\n{text}\n'@); $s.Dispose()"
        )
        try:
            subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           check=True, timeout=60,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if os.path.exists(path) and os.path.getsize(path) > 1000:
                print(f"  wrote {os.path.relpath(path, HERE)}")
                return True
        except Exception as e:
            print(f"  [skip] {os.path.relpath(path, HERE)}: TTS failed ({e})")
            return False
    print(f"  [skip] {os.path.relpath(path, HERE)}: no TTS engine available")
    return False


def _hindi_voice_available() -> bool:
    if sys.platform != "win32":
        return False
    try:
        import pyttsx3
        engine = pyttsx3.init()
        for v in engine.getProperty("voices"):
            blob = f"{v.name} {v.id}".lower()
            if "hi-in" in blob or "hindi" in blob or "kalpana" in blob or "hemant" in blob:
                return True
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# AI-image-origin examples — metadata-proof files built from scratch, plus
# genuine AI / real samples copied from the frozen benchmark corpus when it
# exists (backend/eval/_image_corpus, created by eval/image_model_benchmark).
# ---------------------------------------------------------------------------
def make_image_origin_examples(n_corpus=10):
    import shutil
    from PIL import Image
    from PIL.PngImagePlugin import PngInfo

    def note(path, extra=""):
        print(f"  wrote {os.path.relpath(path, HERE)}  {extra}")

    # 1) PROOF-level AI files (the metadata itself says "AI-made")
    img = Image.new("RGB", (1024, 1024), (18, 52, 86))
    info = PngInfo()
    info.add_text("parameters",
                  "a photorealistic portrait, masterpiece, 8k, Steps: 30, "
                  "Sampler: DPM++ 2M, CFG scale: 7, Model: sd_xl_base_1.0")
    p = os.path.join(IMG_AI_DIR, "ai_stable_diffusion_chunk.png")
    img.save(p, pnginfo=info); note(p, "(SD 'parameters' chunk -> AI_GENERATED)")

    info = PngInfo()
    info.add_text("prompt", '{"3": {"class_type": "KSampler"}}')
    info.add_text("workflow", '{"nodes": [{"type": "KSampler"}]}')
    p = os.path.join(IMG_AI_DIR, "ai_comfyui_chunks.png")
    img.save(p, pnginfo=info); note(p, "(ComfyUI chunks -> AI_GENERATED)")

    exif = Image.Exif(); exif[305] = "Midjourney v6.1"
    p = os.path.join(IMG_AI_DIR, "ai_midjourney_exif.jpg")
    img.convert("RGB").save(p, "JPEG", exif=exif.tobytes())
    note(p, "(EXIF Software=Midjourney -> AI_GENERATED)")

    p = os.path.join(IMG_AI_DIR, "ai_content_credentials_marker.png")
    img.save(p)
    with open(p, "ab") as fh:            # C2PA marker after IEND — PIL-safe
        fh.write(b"....urn:c2pa:manifest....")
    note(p, "(C2PA marker -> Content Credentials finding)")

    # 2) A real-photo-style file with full camera EXIF
    exif = Image.Exif()
    exif[271], exif[272] = "Samsung", "Galaxy S23"
    exif[306] = "2026:05:14 18:03:21"
    p = os.path.join(IMG_REAL_DIR, "real_camera_exif.jpg")
    Image.new("RGB", (4000, 3000), (120, 140, 110)).save(
        p, "JPEG", exif=exif.tobytes())
    note(p, "(camera EXIF -> supports LIKELY_REAL)")

    # 3) Genuine samples from the frozen benchmark corpus (when present)
    copied = 0
    for sub, dest in (("ai", IMG_AI_DIR), ("real", IMG_REAL_DIR)):
        src_dir = os.path.join(CORPUS, sub)
        if not os.path.isdir(src_dir):
            continue
        pngs = sorted(f for f in os.listdir(src_dir) if f.endswith(".png"))
        for f in pngs[:n_corpus]:
            dst = os.path.join(dest, f"corpus_{sub}_{f}")
            shutil.copyfile(os.path.join(src_dir, f), dst)
            copied += 1
    if copied:
        print(f"  copied {copied} genuine samples from the benchmark corpus")
    else:
        print("  [skip] benchmark corpus not found — run "
              "`py -m eval.image_model_benchmark` (from backend/) first")


def main():
    _ensure_dirs()

    print("QR codes:")
    make_qr("https://www.google.com", os.path.join(QR_DIR, "qr_safe_google.png"))
    make_qr("https://www.wikipedia.org", os.path.join(QR_DIR, "qr_safe_wikipedia.png"))
    make_qr("https://github.com", os.path.join(QR_DIR, "qr_safe_github.png"))
    make_qr(PHISH_TEST_URL, os.path.join(QR_DIR, "qr_phishing_test.png"))
    make_qr(MALWARE_TEST_URL, os.path.join(QR_DIR, "qr_malware_test.png"))
    make_qr("http://secure-login-verify-account.xyz/bank/update-kyc",
            os.path.join(QR_DIR, "qr_phishy_lexical.png"))

    print("Screenshots:")
    _render_text(
        [
            "SECURITY ALERT",
            "Your bank account has been blocked.",
            "Verify your OTP immediately to unlock.",
            "Enter your card number and CVV now.",
            "This is urgent - act within 24 hours.",
        ],
        os.path.join(SHOT_DIR, "screenshot_otp_scam.png"),
    )
    _render_text(
        [
            "Hey! Are we still on for lunch",
            "tomorrow at 1pm?",
            "Let me know if the usual place works.",
            "See you then!",
        ],
        os.path.join(SHOT_DIR, "screenshot_normal_chat.png"),
    )
    _render_noise(os.path.join(SHOT_DIR, "screenshot_unreadable.png"))
    _render_text(
        [
            "CONGRATULATIONS! You won Rs 25,00,000",
            "in the KBC Lucky Draw Lottery!",
            "To claim, pay the processing fee of",
            "Rs 4,999 today. Send payment now.",
        ],
        os.path.join(SHOT_DIR, "screenshot_lottery_scam.png"),
    )
    _render_text(
        [
            "Work from home! Earn Rs 5000 daily.",
            "No experience needed. Selected!",
            "Pay Rs 999 registration fee now to",
            "receive your offer letter today.",
        ],
        os.path.join(SHOT_DIR, "screenshot_job_scam.png"),
    )
    _render_text(
        [
            "Your parcel is on hold at customs.",
            "Pay Rs 250 import duty within 24 hours",
            "or the package will be returned.",
            "Pay here: bit.ly/pay-duty-now",
        ],
        os.path.join(SHOT_DIR, "screenshot_delivery_scam.png"),
    )
    _render_text(
        [
            "GUARANTEED 200% RETURNS in 30 days!",
            "Our crypto trading experts double",
            "your money. Minimum invest Rs 10,000.",
            "Limited slots - deposit today!",
        ],
        os.path.join(SHOT_DIR, "screenshot_investment_scam.png"),
    )
    _render_text(
        [
            "Happy birthday! Hope you have a",
            "wonderful day with the family.",
            "We will visit next weekend.",
            "Love from all of us!",
        ],
        os.path.join(SHOT_DIR, "screenshot_normal_family.png"),
    )

    print("AI-image-origin examples:")
    make_image_origin_examples()

    print("Voice (Windows TTS):")
    make_voice(
        "This is your bank security team. Your account will be blocked today. "
        "Read me the one time password immediately to keep it active.",
        os.path.join(VOICE_DIR, "voice_bank_scam_en.wav"),
    )
    make_voice(
        "Your parcel is held at customs. Pay the customs duty of two hundred fifty "
        "rupees to release the package before it is returned.",
        os.path.join(VOICE_DIR, "voice_delivery_scam_en.wav"),
    )
    make_voice(
        "Hi, it's me. Just calling to confirm our meeting tomorrow at eleven. "
        "Give me a ring back when you get a chance. Thanks, bye.",
        os.path.join(VOICE_DIR, "voice_normal_en.wav"),
    )
    make_voice(
        "This is inspector Sharma from the cyber crime police. A money laundering "
        "case is registered against your Aadhaar number. You are under digital "
        "arrest. Stay on this call and transfer your funds to the safe account "
        "for verification, or an arrest warrant will be issued today.",
        os.path.join(VOICE_DIR, "voice_digital_arrest_scam_en.wav"),
    )
    make_voice(
        "Congratulations! Your mobile number has won twenty five lakh rupees in "
        "the lucky draw lottery. To claim your prize money, pay the processing "
        "fee of five thousand rupees right now.",
        os.path.join(VOICE_DIR, "voice_lottery_scam_en.wav"),
    )
    make_voice(
        "You have been selected for a work from home job paying five thousand "
        "rupees per day. Pay the registration fee of nine hundred ninety nine "
        "rupees now to receive your offer letter.",
        os.path.join(VOICE_DIR, "voice_job_scam_en.wav"),
    )
    make_voice(
        "Good afternoon, this is the dental clinic confirming your appointment "
        "on Thursday at four thirty. Please arrive ten minutes early. "
        "See you then.",
        os.path.join(VOICE_DIR, "voice_normal_appointment_en.wav"),
    )

    if _hindi_voice_available():
        make_voice(
            "Aapka bank account aaj block ho jayega. OTP turant share kijiye.",
            os.path.join(VOICE_DIR, "voice_scam_hi.wav"),
            voice_hint="hindi",
        )
    else:
        print("  [skip] voice_scam_hi.wav: no Hindi TTS voice installed.")
        print("         Record ~15s yourself (Hindi): 'aapka bank account aaj")
        print("         block ho jayega, OTP turant share kijiye' -> voice/voice_scam_hi.wav")

    print("\nDone. See testdata/README.md for the expected verdict of each file.")


if __name__ == "__main__":
    main()
