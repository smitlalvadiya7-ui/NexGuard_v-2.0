"""
NexGuard AI — AI image origin detection (AI-generated vs real photo).

Three evidence layers, honest about certainty:
  1. Metadata provenance (PROOF)   — generator chunks/tags, C2PA markers,
                                     camera EXIF. Only this layer may NAME
                                     the generator platform.
  2. Local classifier (PROBABILITY)— transformers image-classification
                                     pipeline, lazy-loaded, fail-open.
  3. Forensic cues (SUPPORTING)    — canvas-size hints; never a verdict alone.

Verdicts: AI_GENERATED (proof) / LIKELY_AI / LIKELY_REAL / UNCERTAIN.
Once the classifier answers we always lean real-vs-AI with a confidence %;
UNCERTAIN is reserved for "the model could not answer at all" and for images
that are not photographs at all (flat colour, smooth gradient, pure noise),
where the classifier's answer would mean nothing.
Free and local only — no paid APIs, no uploads anywhere.
"""

import io
import logging
import os

from PIL import Image, ImageFilter

log = logging.getLogger("nexguard.image_origin")

# Default model = the 2026-07-21 realistic-corpus benchmark winner (see
# backend/eval/image_model_result.json). The 2026-07-19 corpus was 84%
# CIFAKE 32×32 thumbnails; rebuilt at 200 realistic images (100 Hemg AI art /
# 100 COCO photos, MIN_DIM 200) and re-raced against 3 extra free models —
# umm-maybe still wins on emitted-verdict precision. "off" disables the
# probability layer entirely.
MODEL_ID = (os.getenv("NEXGUARD_IMAGE_MODEL") or "umm-maybe/AI-image-detector").strip()

# Strict-band thresholds on P(AI). These are now used ONLY by the offline
# benchmark (eval/image_model_benchmark.py) to measure per-band precision —
# the LIVE verdict no longer hides behind them. Product decision 2026-07-22:
# once the model has answered, always lean to the more likely side (real vs
# AI) with a confidence % that reflects the signal's strength, instead of
# returning UNCERTAIN for the ~67% of images that used to fall in the dead
# zone. UNCERTAIN now means only "the model could not answer at all".
CLASSIFIER_HI = 0.80
CLASSIFIER_LO = 0.15

# Marker (lowercase) -> (generator name, official link). Order matters: the
# first match wins, and more specific strings come first.
GENERATORS = [
    ("midjourney", ("Midjourney", "https://www.midjourney.com")),
    ("dall-e", ("DALL·E (OpenAI)", "https://openai.com/dall-e-3")),
    ("dall·e", ("DALL·E (OpenAI)", "https://openai.com/dall-e-3")),
    ("adobe firefly", ("Adobe Firefly", "https://www.adobe.com/products/firefly.html")),
    ("firefly", ("Adobe Firefly", "https://www.adobe.com/products/firefly.html")),
    ("stable diffusion", ("Stable Diffusion", "https://stability.ai")),
    ("comfyui", ("ComfyUI (Stable Diffusion)", "https://www.comfy.org")),
    ("imagen", ("Google Imagen", "https://deepmind.google/technologies/imagen-3/")),
    ("google gemini", ("Google Gemini", "https://gemini.google.com")),
]

_C2PA_MARKERS = (b"urn:c2pa", b"c2pa.org", b"contentauth", b"jumbf")
_C2PA_VERIFY = "https://contentcredentials.org/verify"

# Common text-to-image canvas sizes (SD/SDXL presets, DALL-E, Midjourney).
AI_CANVAS = {
    (512, 512), (768, 768), (1024, 1024), (2048, 2048),
    (1344, 768), (768, 1344), (832, 1216), (1216, 832),
    (1152, 896), (896, 1152), (1536, 1024), (1024, 1536),
    (1792, 1024), (1024, 1792),
}

_EXIF_MAKE, _EXIF_MODEL, _EXIF_SOFTWARE, _EXIF_DATETIME = 271, 272, 305, 306
_EXIF_GPS_IFD = 0x8825


def _match_generator(text):
    low = (text or "").lower()
    for marker, named in GENERATORS:
        if marker in low:
            return named
    return None


def provenance_findings(pil_image, raw_bytes):
    """PROOF-level findings from metadata. Each: {kind, generator, link, reason}.
    kind 'proof' = the file itself says it was AI-made; kind 'credentials' =
    signed Content Credentials are present (verify externally)."""
    findings = []
    try:
        info = dict(getattr(pil_image, "info", None) or {})
        text_chunks = dict(getattr(pil_image, "text", None) or {})
        info.update(text_chunks)

        # Stable Diffusion WebUI (A1111) writes the whole prompt into a
        # 'parameters' chunk; ComfyUI writes 'prompt' + 'workflow' JSON.
        if isinstance(info.get("parameters"), str) and info["parameters"].strip():
            findings.append({
                "kind": "proof",
                "generator": "Stable Diffusion (AUTOMATIC1111 WebUI)",
                "link": "https://stability.ai",
                "reason": ("The file carries a Stable Diffusion 'parameters' "
                           "chunk with the generation prompt — proof it was "
                           "AI-generated."),
            })
        elif "prompt" in info and "workflow" in info:
            findings.append({
                "kind": "proof",
                "generator": "ComfyUI (Stable Diffusion)",
                "link": "https://www.comfy.org",
                "reason": ("The file carries ComfyUI 'prompt'/'workflow' "
                           "chunks — proof it was AI-generated."),
            })

        # Software / XMP-style strings naming a known generator.
        exif = pil_image.getexif() if pil_image is not None else {}
        software = str(exif.get(_EXIF_SOFTWARE, "")) if exif else ""
        candidates = [software] + [str(v) for v in info.values()
                                   if isinstance(v, str)]
        for text in candidates:
            named = _match_generator(text)
            if named:
                name, link = named
                if not any(f.get("generator", "").startswith(name.split()[0])
                           for f in findings):
                    findings.append({
                        "kind": "proof", "generator": name, "link": link,
                        "reason": (f"The file's metadata names {name} as the "
                                   "creator — proof it was AI-generated."),
                    })
                break

        low = (raw_bytes or b"").lower()
        # IPTC digital source type for synthetic media.
        if b"trainedalgorithmicmedia" in low:
            findings.append({
                "kind": "proof", "generator": None, "link": None,
                "reason": ("The file is marked 'trainedAlgorithmicMedia' "
                           "(IPTC digital source type) — declared AI-generated."),
            })
        # C2PA / Content Credentials container markers.
        if any(m in low for m in _C2PA_MARKERS):
            findings.append({
                "kind": "credentials", "generator": None, "link": _C2PA_VERIFY,
                "reason": ("Signed Content Credentials (C2PA) are attached — "
                           "verify who made it at contentcredentials.org/verify."),
            })
    except Exception as e:                      # metadata must never crash a scan
        log.warning("provenance read failed: %s", e)
    return findings


def camera_evidence(pil_image):
    """Camera EXIF lines SUPPORTING 'real photo'. Absence proves nothing —
    WhatsApp/screenshots strip EXIF — so an empty list is just silence."""
    lines = []
    try:
        exif = pil_image.getexif() if pil_image is not None else None
        if not exif:
            return []
        make = str(exif.get(_EXIF_MAKE, "")).strip()
        model = str(exif.get(_EXIF_MODEL, "")).strip()
        taken = str(exif.get(_EXIF_DATETIME, "")).strip()
        if make or model:
            cam = " ".join(p for p in (make, model) if p)
            when = f" (taken {taken})" if taken else ""
            lines.append(f"Camera EXIF present: {cam}{when} — points to a real photo.")
        try:
            if exif.get_ifd(_EXIF_GPS_IFD):
                lines.append("GPS location data present — typical of a real camera photo.")
        except Exception:
            pass
    except Exception as e:
        log.warning("camera EXIF read failed: %s", e)
    return lines


def forensic_cues(pil_image):
    """SUPPORTING hints only — never enough for a verdict by themselves."""
    cues = []
    try:
        if pil_image is None:
            return []
        size = tuple(pil_image.size)
        if camera_evidence(pil_image):
            return []                       # a camera photo's size is not a cue
        w, h = size
        if size in AI_CANVAS:
            cues.append(f"{w}×{h} is a common AI-generator canvas size.")
        elif w % 64 == 0 and h % 64 == 0 and w <= 2048 and h <= 2048:
            cues.append(f"{w}×{h} (both sides multiples of 64) matches "
                        "typical AI-generator output sizes.")
    except Exception as e:
        log.warning("forensic cues failed: %s", e)
    return cues


# ---------------------------------------------------------------------------
# Layer 2 — local classifier (probability, never proof, never names a tool)
# ---------------------------------------------------------------------------

_pipeline = None
_AI_LABELS = ("artificial", "ai", "fake", "generated", "synthetic")
_REAL_LABELS = ("human", "real", "photo", "authentic")


def classifier_probability(path):
    """P(AI-generated) in 0..1 from the local model, or None when the layer
    is off/unavailable — every failure fails open to 'no probability'."""
    global _pipeline
    if (MODEL_ID or "").lower() in ("", "off"):
        return None
    try:
        if _pipeline is None:
            from transformers import pipeline as hf_pipeline
            _pipeline = hf_pipeline("image-classification", model=MODEL_ID)
        preds = _pipeline(path) or []
        ai, real = None, None
        for pred in preds:
            label = str(pred.get("label", "")).lower()
            score = float(pred.get("score", 0.0))
            if any(k in label for k in _AI_LABELS):
                ai = max(ai, score) if ai is not None else score
            elif any(k in label for k in _REAL_LABELS):
                real = max(real, score) if real is not None else score
        if ai is not None:
            return ai
        if real is not None:
            return 1.0 - real
        return None
    except Exception as e:
        log.warning("image classifier unavailable: %s", e)
        return None


# ---------------------------------------------------------------------------
# Verdict — plan table, honest about certainty
# ---------------------------------------------------------------------------

ACTIONS = [
    {"label": "Verify Content Credentials yourself",
     "url": "https://contentcredentials.org/verify"},
    {"label": "Reverse-search with Google Lens", "url": "https://lens.google.com"},
    {"label": "Reverse-search with TinEye", "url": "https://tineye.com"},
    {"label": "Being used in a scam? Report it via the Support page", "url": None},
]


# Thresholds for "is there a photograph here at all?", measured 2026-10-01 on
# the bundled corpora (testdata/image_origin, the test pack, screenshots):
#   real + AI photos   detail 1.6-25.4, neighbour correlation 0.73-0.994
#   plain gradient     detail <= 0.37,  correlation 1.0
#   random noise       detail 46.5,     correlation 0.004
#   solid colour       no variation at all
_FLAT_STD = 2.0        # whole-image grey-level spread below this = one flat colour
_MIN_DETAIL = 0.8      # high-frequency residual below this = smooth synthetic fill
_MIN_NEIGHBOUR_R = 0.3 # adjacent-pixel correlation below this = noise, no scene


def photographic_content(pil_image):
    """
    None when the image has photograph-like content; otherwise a reason it
    does not. The AI-vs-real classifier only means something on a picture of
    a scene: asked about a flat colour, a computer gradient or random noise it
    still returns a probability, and on 2026-09-29 that turned a plain
    gradient into "Likely a real photo". Checked on a native-resolution centre
    crop (no resampling, which would smooth noise away). Never raises.
    """
    if pil_image is None:
        return None
    try:
        import numpy as np
        grey = pil_image.convert("L")
        w, h = grey.size
        s = min(512, w, h)
        if s < 8:
            return None
        crop = grey.crop(((w - s) // 2, (h - s) // 2, (w - s) // 2 + s, (h - s) // 2 + s))
        a = np.asarray(crop, dtype=np.float32)
        if float(a.std()) < _FLAT_STD:
            return "it is a single flat colour"
        blurred = np.asarray(crop.filter(ImageFilter.BoxBlur(1)), dtype=np.float32)
        detail = float((a - blurred)[1:-1, 1:-1].std())
        if detail < _MIN_DETAIL:
            return "it is a smooth computer-drawn fill (gradient or flat shapes)"
        r = float(np.corrcoef(a[:, :-1].ravel(), a[:, 1:].ravel())[0, 1])
        if r < _MIN_NEIGHBOUR_R:
            return "it is random noise with no scene in it"
        return None
    except Exception as e:  # noqa: BLE001 — a stats failure must not block a verdict
        log.debug("photographic_content failed: %s", e)
        return None


def _result(verdict, confidence, analysis, reasons, generator=None,
            generator_link=None, ai_probability=None):
    return {"verdict": verdict, "confidence": confidence,
            "generator": generator, "generator_link": generator_link,
            "ai_probability": ai_probability, "reasons": reasons,
            "actions": list(ACTIONS), "analysis": analysis}


def analyze_image_origin(path):
    """Full 3-layer analysis of one image file. Never raises."""
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
        img = Image.open(io.BytesIO(raw))
        img.load()
    except Exception as e:
        log.info("unreadable image: %s", e)
        return _result(
            "UNCERTAIN", 0,
            "This file could not be read as an image — nothing was analyzed.",
            ["The file is not a readable image."])

    findings = provenance_findings(img, raw)
    camera = camera_evidence(img)
    cues = forensic_cues(img)
    reasons = [f["reason"] for f in findings] + camera + cues

    proof = next((f for f in findings if f["kind"] == "proof"), None)
    if proof:
        gen = proof.get("generator")
        made = f", made with {gen}" if gen else ""
        return _result(
            "AI_GENERATED", 100,
            f"AI-generated — confirmed by the file's own metadata{made}.",
            reasons, generator=gen, generator_link=proof.get("link"))

    # Metadata proof above stands on its own. Everything below is the
    # classifier's opinion, which only applies to a picture of a scene.
    not_a_photo = photographic_content(img)
    if not_a_photo:
        reasons.insert(0, f"The picture itself is not a photograph — {not_a_photo} — "
                          "so the AI-vs-real detector cannot judge it.")
        return _result(
            "UNCERTAIN", 0,
            f"Not a photograph — {not_a_photo}. The detector separates AI images "
            "from camera photos, so it has nothing meaningful to say here"
            + (" (the camera metadata alone does not prove a real photo)." if camera else "."),
            reasons, ai_probability=None)

    p = classifier_probability(path)
    ai_pct = round(p * 100) if p is not None else None

    # The probability layer is the only thing that can separate a plain real
    # photo from an AI render once metadata is silent. If it could not answer
    # (transformers/torch missing, or the model failed to download), we have
    # nothing to lean on — that is the ONLY case that stays UNCERTAIN now.
    if p is None:
        if not reasons:
            reasons = ["No provenance metadata and no camera EXIF were found, "
                       "and the local AI-image detector model is not available "
                       "on this server."]
        return _result(
            "UNCERTAIN", 0,
            "Not enough evidence either way — the local detector model is not "
            "available (install transformers + torch and restart the backend).",
            reasons, ai_probability=None)

    # Model answered → always lean to the more likely side. A near-0.5 score
    # produces a low-confidence lean ("Leaning …"), never a non-answer. The
    # confidence % already tells the user how strong the signal is.
    if p >= 0.5:
        conf = min(95, ai_pct)
        if cues:
            conf = min(95, conf + 5)
        lean = "Likely AI-generated" if conf >= 60 else "Leaning AI-generated"
        reasons.insert(0, f"The local detector model rates this {ai_pct}% "
                          "likely AI-generated.")
        return _result(
            "LIKELY_AI", conf,
            f"{lean} (confidence {conf}%). No provenance proof was found, so "
            "the exact tool cannot be named honestly.",
            reasons, ai_probability=ai_pct)

    # p < 0.5 → leans real. Camera EXIF corroborates and lifts the ceiling to
    # 95; without it we cap at 80 (the realistic-corpus precision of a
    # metadata-free "real") so we never overstate.
    reasons.insert(0, f"The local detector model rates this only {ai_pct}% "
                      "likely AI-generated.")
    if camera:
        conf = min(95, round((1 - p) * 100) + 10)
        note = ""
    else:
        raw_conf = round((1 - p) * 100)
        conf = min(80, raw_conf)
        note = (" No camera metadata was found to corroborate it, so the "
                "confidence is capped." if raw_conf > conf else
                " No camera metadata was found to corroborate it.")
    lean = "Likely a real photo" if conf >= 60 else "Leaning real photo"
    return _result(
        "LIKELY_REAL", conf,
        f"{lean} (confidence {conf}%).{note}",
        reasons, ai_probability=ai_pct)
