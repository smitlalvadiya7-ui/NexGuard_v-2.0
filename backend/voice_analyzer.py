from pathlib import Path
import os
import tempfile
import subprocess
import threading
import wave
import numpy as np

# ---------------------------------------------------------------------------
# Whisper lazy singleton — loaded once on first transcription request
# ---------------------------------------------------------------------------
_whisper_model = None
_whisper_lock = threading.Lock()
_whisper_unavailable = False  # flipped True on ImportError so we stop retrying


def _get_whisper_model():
    """Return the cached Whisper model, loading it on first call."""
    global _whisper_model, _whisper_unavailable
    if _whisper_unavailable:
        raise ImportError("openai-whisper is not installed")
    if _whisper_model is not None:
        return _whisper_model
    with _whisper_lock:
        # double-checked locking
        if _whisper_unavailable:
            raise ImportError("openai-whisper is not installed")
        if _whisper_model is None:
            try:
                import whisper as _whisper
                model_name = os.getenv("NEXGUARD_WHISPER_MODEL", "base")
                _whisper_model = _whisper.load_model(model_name)
            except ImportError:
                _whisper_unavailable = True
                raise
    return _whisper_model


# ---------------------------------------------------------------------------
# WAV → float32 numpy loader — bypasses ffmpeg for Whisper input
# ---------------------------------------------------------------------------

def _load_wav_as_numpy(wav_path: Path):
    """
    Decode a WAV file to a float32 mono array at 16 kHz without ffmpeg.
    Returns None on any error so callers can fall back gracefully.
    """
    try:
        with wave.open(str(wav_path), "rb") as wf:
            n_channels = wf.getnchannels()
            samp_width = wf.getsampwidth()
            framerate  = wf.getframerate()
            raw        = wf.readframes(wf.getnframes())

        if samp_width == 1:
            samples = (np.frombuffer(raw, dtype=np.uint8).astype(np.float32) - 128.0) / 128.0
        elif samp_width == 2:
            samples = np.frombuffer(raw, dtype=np.int16).astype(np.float32) / 32768.0
        elif samp_width == 4:
            samples = np.frombuffer(raw, dtype=np.int32).astype(np.float32) / 2147483648.0
        else:
            return None

        if n_channels > 1:
            samples = samples.reshape(-1, n_channels).mean(axis=1)

        if framerate != 16000:
            target_len = int(len(samples) * 16000 / framerate)
            indices = np.linspace(0, len(samples) - 1, target_len)
            samples = np.interp(indices, np.arange(len(samples)), samples)

        return samples.astype(np.float32)
    except Exception:
        return None


# ---------------------------------------------------------------------------

import re

# ---------------------------------------------------------------------------
# Intent-based scam-speech detection (FIX 3)
# ---------------------------------------------------------------------------
# We detect scam INTENT, not literal keywords. The transcript is normalised
# (lowercased, punctuation stripped, whitespace collapsed) and matched against
# paraphrase-aware regexes grouped by manipulation category. Scoring is driven
# by category presence and combinations, so "give me your one time pin",
# "read me the verification code", "share the one-time code", etc. all fire.

# A "code term": OTP / 2FA / verification / security / access codes & PINs.
_CODE_TERM = (
    r"(?:one[\s-]?time[\s-]?(?:pin|password|code|passcode|pass\s?code)"
    r"|o\.?t\.?p\.?|otp"
    r"|verification\s+code|security\s+code|secure\s+code|auth(?:entication)?\s+code"
    r"|login\s+code|access\s+code|confirmation\s+code|sign[\s-]?in\s+code"
    r"|2fa|two[\s-]?factor|passcode|\bpin\b)"
)
# A verb that means "hand the code over to me".
_SHARE_VERB = r"(?:share|read|give|tell|provide|send|type|enter|confirm|repeat|say|forward|text|dictate)"

# category -> (compiled regexes, base weight, human label)
_INTENT_RULES = {
    "code_request": (
        [
            re.compile(_SHARE_VERB + r"(?:\s+\w+){0,4}\s+" + _CODE_TERM),
            re.compile(_CODE_TERM + r"(?:\s+\w+){0,3}\s+(?:that|which|we|i)?\s*(?:just\s+)?(?:sent|texted)"),
            re.compile(r"code\s+(?:sent|texted)\s+to\s+your\s+(?:phone|mobile|device|number)"),
            re.compile(r"what\s+(?:is|s)\s+(?:the|your)\s+" + _CODE_TERM),
        ],
        50, "request to share a one-time / verification code",
    ),
    "code_mention": (
        [re.compile(_CODE_TERM)],
        25, "one-time / verification code or PIN mentioned",
    ),
    "urgency": (
        [
            re.compile(r"act\s+now|right\s+(?:now|away)|immediately|as\s+soon\s+as\s+possible"),
            re.compile(r"urgent|final\s+warning|last\s+(?:chance|warning)|today\s+only|expires?\b"),
            re.compile(r"within\s+\d+\s*(?:minute|min|hour|hr|second|sec)"),
            re.compile(r"account\s+(?:will\s+be|has\s+been)\s+(?:closed|suspended|blocked|terminated|locked|deactivated)"),
        ],
        18, "urgency / time-pressure language",
    ),
    "money": (
        [
            re.compile(r"gift\s+card|wire\s+transfer|western\s+union|money\s+gram"),
            re.compile(r"bank\s+(?:details|account|account\s+number)|account\s+number|routing\s+number"),
            re.compile(r"card\s+number|credit\s+card|debit\s+card|\bcvv\b|card\s+verification"),
            re.compile(r"bitcoin|crypto(?:currency)?|wallet\s+address"),
            # "transfer YOUR funds" / "all your money" must count too — the
            # digital-arrest script scored a false SAFE 36 without it.
            re.compile(r"(?:send|transfer|pay|deposit)\s+(?:me\s+)?(?:all\s+)?(?:the\s+|your\s+)?(?:money|funds|payment|\$?\d+)"),
            re.compile(r"safe\s+account"),
        ],
        26, "money / payment-detail request",
    ),
    "credential": (
        [
            re.compile(r"\bpassword\b|\bpasscode\b|\busername\b|login\s+(?:details|credentials)|credentials"),
            re.compile(r"social\s+security(?:\s+number)?|\bssn\b|date\s+of\s+birth|mother'?s\s+maiden"),
        ],
        24, "credential / identity request",
    ),
    "impersonation": (
        [
            re.compile(r"microsoft|windows\s+support|amazon|apple|paypal|google|netflix"),
            re.compile(r"your\s+bank|bank\s+of\b|\bvisa\b|mastercard|\birs\b|\bhmrc\b|tax\s+(?:office|department)"),
            re.compile(r"social\s+security\s+administration|\bpolice\b|customs|government|federal\s+agent"),
            re.compile(r"support\s+team|security\s+(?:team|department)|fraud\s+department|technical\s+support"),
        ],
        14, "claims to be a bank / company / authority",
    ),
    "remote_access": (
        [re.compile(r"anydesk|team\s?viewer|remote\s+access|install\s+(?:the\s+)?app|share\s+your\s+screen|screen\s+share")],
        32, "asks to install remote-access / screen-sharing software",
    ),
    "secrecy": (
        [re.compile(r"do\s?n'?t\s+tell\s+(?:anyone|anybody)|keep\s+this\s+(?:a\s+)?secret|between\s+(?:us|you\s+and\s+me)|do\s+not\s+share\s+this")],
        30, "asks you to keep the call secret",
    ),
    "authority_threat": (
        [
            re.compile(r"\barrest|warrant|legal\s+action|lawsuit|you\s+will\s+be\s+(?:fined|prosecuted)|suspend\s+your\s+account"),
            # the Indian "digital arrest" script (fake police + case + stay on call)
            re.compile(r"digital\s+arrest|money\s+laundering|case\s+(?:is\s+)?registered|cyber\s*crime"),
        ],
        22, "threat of arrest / legal / account action",
    ),
    # ---- Task 10: scam coverage beyond banking ----------------------------
    "social_media": (
        [
            re.compile(r"(?:instagram|facebook|whatsapp|telegram|youtube|snapchat)\s+account"),
            re.compile(r"account\s+will\s+be\s+(?:banned|deleted|closed|suspended|deactivated)"),
            re.compile(r"blue\s+tick|verified\s+badge|verification\s+badge"),
        ],
        30, "social-media account threat / verification lure",
    ),
    "delivery": (
        [
            re.compile(r"customs\s+(?:duty|fee|charge|clearance)"),
            re.compile(r"(?:parcel|package|shipment|courier)\s+(?:is\s+)?(?:held|stuck|on\s+hold|detained|pending|seized)"),
            re.compile(r"(?:redelivery|delivery|release)\s+(?:fee|charge)"),
            re.compile(r"fedex|dhl|blue\s?dart|india\s+post|usps|royal\s+mail"),
        ],
        30, "parcel / customs fee scam pattern",
    ),
    "job_offer": (
        [
            re.compile(r"work\s+from\s+home"),
            re.compile(r"earn\s+(?:rs\.?\s*)?\d[\d,]*\s*(?:per|a|every)\s+(?:day|week|hour|month)"),
            re.compile(r"(?:registration|joining|training|activation)\s+fee"),
            re.compile(r"part\s+time\s+job|simple\s+tasks?|online\s+tasks?"),
        ],
        30, "too-good job offer with an upfront fee",
    ),
    "investment": (
        [
            re.compile(r"guaranteed\s+(?:returns?|profits?)"),
            re.compile(r"double\s+your\s+(?:money|investment)"),
            re.compile(r"(?:trading|investment|stock)\s+(?:tips|group|plan|scheme|advice)"),
            re.compile(r"high\s+returns?"),
        ],
        30, "investment / trading returns lure",
    ),
    "lottery": (
        [
            re.compile(r"you\s+(?:have\s+)?won|lucky\s+draw|lottery|prize\s+money"),
            re.compile(r"\bkbc\b|crorepati"),
            re.compile(r"\d+\s*(?:lakh|crore|million)\b"),
        ],
        30, "lottery / prize winning claim",
    ),
}


def _normalize(text: str) -> str:
    t = (text or "").lower()
    t = re.sub(r"[^a-z0-9\s]", " ", t)   # strip punctuation so paraphrases match
    t = re.sub(r"\s+", " ", t).strip()
    return t


def _verdict(score):

    return (
        "MALICIOUS"
        if score >= 70
        else "SUSPICIOUS"
        if score >= 40
        else "SAFE"
    )


def _score_text(text: str) -> dict:
    """
    Intent-based scoring. Returns
        {"verdict", "score", "reasons", "matched_cues", "categories"}.
    A transcript with text but no scam intent scores 0 with empty cues.
    """
    norm = _normalize(text)
    score = 0
    reasons = []
    categories = []

    if norm:
        for cat, (patterns, weight, label) in _INTENT_RULES.items():
            n_hits = sum(1 for p in patterns if p.search(norm))
            if n_hits:
                categories.append(cat)
                # Several distinct patterns of the SAME category firing is a
                # stronger signal than one ("parcel held" + "customs duty" +
                # "release fee" reads like a script, not a coincidence).
                score += weight + min(20, 10 * (n_hits - 1))
                reasons.append(f"Scam intent ({cat}): {label}")

    # Combination bonuses: a code/credential/money ASK plus pressure or an
    # impersonated authority is the classic vishing structure -> escalate.
    cat_set = set(categories)
    ask = cat_set & {"code_request", "credential", "money"}
    if ask and ("urgency" in cat_set or "authority_threat" in cat_set):
        score += 18
        reasons.append("Sensitive request combined with urgency / threat")
    if ask and "impersonation" in cat_set:
        score += 12
        reasons.append("Sensitive request combined with brand/authority impersonation")
    if len(cat_set) >= 3:
        score += 10
        reasons.append("Multiple independent scam-intent signals present")

    score = max(0, min(100, int(score)))
    intent_score = score

    return {
        "verdict": _verdict(score),
        "score": score,
        "intent_score": intent_score,
        "reasons": reasons,
        "matched_cues": list(cat_set),
        "categories": categories,
    }


def _convert_to_wav(path: Path) -> Path | None:

    out = Path(
        tempfile.mktemp(
            prefix="nexguard_audio_",
            suffix=".wav"
        )
    )

    try:

        subprocess.run(
            [
                "ffmpeg",
                "-y",
                "-i",
                str(path),
                "-vn",
                "-acodec",
                "pcm_s16le",
                "-ar",
                "16000",
                "-ac",
                "1",
                str(out)
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=35,
            check=True
        )

        return out if out.exists() else None

    except Exception:

        return None


def _speech_to_text(path: Path) -> tuple[str, str | None, str | None]:
    """Returns (english_text, error_note, detected_language_code)."""
    # Direct transcript file — no STT needed
    if path.suffix.lower() in [".txt", ".log"]:
        return path.read_text(errors="ignore"), None, None

    # ----------------------------------------------------------------
    # Primary path: local Whisper (offline, free, default)
    # Enabled by NEXGUARD_ENABLE_WHISPER=1 (set in .env by default).
    # Model defaults to "base"; override via NEXGUARD_WHISPER_MODEL.
    #
    # task="translate" (Task 10): Whisper detects the spoken language and
    # outputs ENGLISH, so the English intent rules catch scam calls in
    # Hindi/Gujarati/any language. The detected language is returned.
    #
    # WAV files are decoded to a numpy array here so Whisper never
    # needs to call ffmpeg — Whisper accepts np.ndarray directly.
    # Non-WAV files are first converted to WAV via _convert_to_wav
    # (which does use ffmpeg), then loaded the same way.
    # ----------------------------------------------------------------
    if os.getenv("NEXGUARD_ENABLE_WHISPER", "0") == "1":
        try:
            model = _get_whisper_model()

            # Build audio input: prefer numpy to avoid ffmpeg dependency
            audio_input = None
            if path.suffix.lower() == ".wav":
                audio_input = _load_wav_as_numpy(path)
            else:
                tmp_wav = _convert_to_wav(path)
                if tmp_wav:
                    audio_input = _load_wav_as_numpy(tmp_wav)
                    try:
                        tmp_wav.unlink()
                    except Exception:
                        pass

            # Fall back to raw path string if numpy loading failed
            transcribe_input = audio_input if audio_input is not None else str(path)
            result = model.transcribe(transcribe_input, fp16=False, task="translate")
            return (
                result.get("text", "").strip(),
                None,
                result.get("language"),
            )
        except ImportError:
            # Whisper not installed — fall through to Google STT below
            pass
        except Exception as e:
            return "", f"Whisper transcription failed: {str(e)[:120]}", None

    # ----------------------------------------------------------------
    # Fallback: Google online STT (only reached if Whisper import fails)
    # ----------------------------------------------------------------
    if os.getenv("NEXGUARD_ENABLE_ONLINE_STT", "0") == "1":
        try:
            import speech_recognition as sr

            wav_path = (
                path if path.suffix.lower() == ".wav"
                else _convert_to_wav(path)
            )
            if not wav_path:
                return "", "Audio conversion failed. Install ffmpeg for mp3/mp4 voice scanning.", None

            recognizer = sr.Recognizer()
            with sr.AudioFile(str(wav_path)) as source:
                audio = recognizer.record(source, duration=45)
            text = recognizer.recognize_google(
                audio,
                language=os.getenv("NEXGUARD_STT_LANG", "en-US"),
            )
            if wav_path != path:
                try:
                    wav_path.unlink()
                except Exception:
                    pass
            return text, None, None
        except Exception as e:
            return "", f"Online speech-to-text failed: {str(e)[:120]}", None

    return (
        "",
        "Real transcript not enabled. Install openai-whisper and set NEXGUARD_ENABLE_WHISPER=1.",
        None,
    )


def analyze_voice(file_path):

    path = Path(file_path)

    if not path.exists():

        return {
            "verdict": "ERROR",
            "score": 0,
            "risk_score": 0,
            "text": "File missing",
            "reasons": [
                "Voice file not found"
            ]
        }

    text, stt_note, language = _speech_to_text(path)

    # ONLY transcript-based scoring (filename fallback disabled).
    combined_for_scoring = text if text.strip() else ""

    scored = _score_text(combined_for_scoring)
    verdict = scored["verdict"]
    score = scored["score"]
    intent_score = scored["intent_score"]
    reasons = list(scored["reasons"])

    has_transcript = bool(text.strip())

    # Always return a complete, non-blank response (FIX 3 / FIX 5):
    #  * transcript + no intent match -> intent_score 0 with an empty-cues note
    #  * no transcript at all         -> UNKNOWN, never SAFE (BUG 3)
    if has_transcript and not reasons:
        reasons.append("No scam-intent cues detected in the transcript.")

    if stt_note:
        reasons.append(stt_note)

    if not has_transcript:
        # BUG 3 (WORK_PLAN Task 1): nothing was analyzed, so nothing is "safe".
        verdict = "UNKNOWN"
        reasons.append(
            "No transcript available — the audio could not be analyzed. "
            "This is NOT a safe verdict."
        )

    # Fake-vs-real ratio + confidence (Task 10). The ratio is only claimed
    # when there was actually a transcript to judge.
    word_count = len(combined_for_scoring.split())
    if not has_transcript:
        scam_ratio = None
        genuine_ratio = None
        confidence = "Low"
    else:
        scam_ratio = score
        genuine_ratio = 100 - score
        if score >= 70 or len(set(scored["categories"])) >= 3:
            confidence = "High"
        elif word_count < 8:
            confidence = "Low"
        elif score == 0 and word_count >= 12:
            confidence = "High"   # long, clean transcript — confidently safe
        else:
            confidence = "Medium"

    return {

        "verdict": verdict,

        "score": score,

        "risk_score": score,

        "intent_score": intent_score,

        "matched_cues": scored["matched_cues"],

        "categories": scored["categories"],

        "language": language,

        "scam_ratio": scam_ratio,

        "genuine_ratio": genuine_ratio,

        "confidence": confidence,

        "text": (
            text.strip()
            or
            "No transcript returned. Enable STT or upload a .txt transcript for accurate voice testing."
        ),

        "reasons": reasons,

        "ai_explanation": (
            "; ".join(reasons)
            if reasons
            else
            "No scam wording detected in voice transcript."
        ),
    }