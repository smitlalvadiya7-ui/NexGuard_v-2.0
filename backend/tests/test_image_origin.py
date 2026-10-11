"""
AI Image Detector — engine tests. Layer 1 (metadata provenance = PROOF),
layer 3 (forensic cues = SUPPORTING) here; layer 2 (classifier) and the
verdict composition are tested further down with the pipeline monkeypatched.
All images are built in-memory with Pillow — no files, no network, no model.
"""

import io

from PIL import Image
from PIL.PngImagePlugin import PngInfo

import image_origin


# ---------------------------------------------------------------------------
# helpers — tiny real images
# ---------------------------------------------------------------------------

def photo_like(size):
    """
    Natural-image statistics without a real photo: a smooth random scene
    (strong neighbour correlation) plus mild sensor-like noise (real
    high-frequency detail). A blank white canvas is NOT a stand-in for a photo
    any more — it is exactly the input the detector must refuse to grade.
    """
    import numpy as np
    rng = np.random.default_rng(7)
    w, h = size
    small = (rng.random((max(2, h // 16), max(2, w // 16), 3)) * 255).astype("uint8")
    base = np.asarray(Image.fromarray(small).resize(size, Image.BICUBIC), dtype=np.float32)
    noise = rng.normal(0, 4, base.shape).astype(np.float32)
    return Image.fromarray(np.clip(base + noise, 0, 255).astype("uint8"))


def png_bytes(size=(100, 100), text=None, photo=False):
    img = photo_like(size) if photo else Image.new("RGB", size, "white")
    info = PngInfo()
    for k, v in (text or {}).items():
        info.add_text(k, v)
    buf = io.BytesIO()
    img.save(buf, "PNG", pnginfo=info)
    return buf.getvalue()


def jpeg_bytes(size=(4032, 3024), exif_tags=None, photo=False):
    img = photo_like(size) if photo else Image.new("RGB", size, "white")
    exif = Image.Exif()
    for tag, v in (exif_tags or {}).items():
        exif[tag] = v
    buf = io.BytesIO()
    img.save(buf, "JPEG", exif=exif.tobytes())
    return buf.getvalue()


def open_img(raw):
    return Image.open(io.BytesIO(raw))


CAMERA_EXIF = {271: "Apple", 272: "iPhone 13", 306: "2025:11:02 14:22:31"}


# ---------------------------------------------------------------------------
# Layer 1 — provenance (proof)
# ---------------------------------------------------------------------------

def test_sd_parameters_chunk_is_proof():
    raw = png_bytes(text={"parameters": "a cat, Steps: 20, Sampler: Euler"})
    found = image_origin.provenance_findings(open_img(raw), raw)
    proofs = [f for f in found if f["kind"] == "proof"]
    assert proofs and "Stable Diffusion" in proofs[0]["generator"]
    assert proofs[0]["link"]

def test_comfyui_chunks_are_proof():
    raw = png_bytes(text={"prompt": "{\"1\": {}}", "workflow": "{\"nodes\": []}"})
    found = image_origin.provenance_findings(open_img(raw), raw)
    assert any(f["kind"] == "proof" and "ComfyUI" in (f["generator"] or "")
               for f in found)

def test_midjourney_software_tag_is_proof_with_link():
    raw = jpeg_bytes(size=(1024, 1024), exif_tags={305: "Midjourney v6.1"})
    found = image_origin.provenance_findings(open_img(raw), raw)
    proofs = [f for f in found if f["kind"] == "proof"]
    assert proofs and proofs[0]["generator"] == "Midjourney"
    assert "midjourney.com" in proofs[0]["link"]

def test_trained_algorithmic_media_marker_is_generic_proof():
    raw = png_bytes() + b"<xmp>http://cv.iptc.org/trainedAlgorithmicMedia</xmp>"
    found = image_origin.provenance_findings(open_img(raw), raw)
    assert any(f["kind"] == "proof" for f in found)

def test_c2pa_markers_are_credentials_finding():
    raw = png_bytes() + b"....urn:c2pa:manifest...."
    found = image_origin.provenance_findings(open_img(raw), raw)
    creds = [f for f in found if f["kind"] == "credentials"]
    assert creds and "contentcredentials.org" in creds[0]["link"]

def test_clean_camera_photo_has_no_provenance():
    raw = jpeg_bytes(exif_tags=CAMERA_EXIF)
    assert image_origin.provenance_findings(open_img(raw), raw) == []

def test_provenance_never_raises_on_junk():
    assert image_origin.provenance_findings(None, b"not an image") == []


# ---------------------------------------------------------------------------
# Camera evidence (supports REAL, never proves anything)
# ---------------------------------------------------------------------------

def test_camera_exif_detected():
    raw = jpeg_bytes(exif_tags=CAMERA_EXIF)
    lines = image_origin.camera_evidence(open_img(raw))
    assert lines and any("Apple" in ln and "iPhone 13" in ln for ln in lines)

def test_no_exif_means_no_camera_evidence():
    raw = png_bytes()
    assert image_origin.camera_evidence(open_img(raw)) == []
    assert image_origin.camera_evidence(None) == []


# ---------------------------------------------------------------------------
# Layer 3 — forensic cues (supporting only)
# ---------------------------------------------------------------------------

def test_ai_canvas_size_is_a_cue():
    raw = png_bytes(size=(1024, 1024))
    cues = image_origin.forensic_cues(open_img(raw))
    assert any("1024" in c for c in cues)

def test_camera_photo_dimensions_are_not_a_cue():
    raw = jpeg_bytes(size=(4032, 3024), exif_tags=CAMERA_EXIF)
    assert image_origin.forensic_cues(open_img(raw)) == []

def test_cues_never_raise():
    assert image_origin.forensic_cues(None) == []


# ---------------------------------------------------------------------------
# Layer 2 + verdict — classifier monkeypatched, honest composition
# ---------------------------------------------------------------------------

def _write(tmp_path, raw, name="img.png"):
    p = tmp_path / name
    p.write_bytes(raw)
    return str(p)

def test_provenance_proof_wins_regardless_of_classifier(tmp_path, monkeypatch):
    monkeypatch.setattr(image_origin, "classifier_probability", lambda p: 0.01)
    path = _write(tmp_path, png_bytes(text={"parameters": "cat, Steps: 20"}))
    r = image_origin.analyze_image_origin(path)
    assert r["verdict"] == "AI_GENERATED"
    assert r["confidence"] == 100
    assert "Stable Diffusion" in r["generator"]
    assert r["generator_link"]

def test_high_probability_with_cue_is_likely_ai_capped_95(tmp_path, monkeypatch):
    monkeypatch.setattr(image_origin, "classifier_probability", lambda p: 0.97)
    path = _write(tmp_path, png_bytes(size=(1024, 1024), photo=True))
    r = image_origin.analyze_image_origin(path)
    assert r["verdict"] == "LIKELY_AI"
    assert r["confidence"] == 95                  # 97 capped at 95
    assert r["generator"] is None                 # classifier never names a tool
    assert r["ai_probability"] == 97
    assert any("1024" in reason for reason in r["reasons"])

def test_low_probability_with_camera_exif_is_likely_real(tmp_path, monkeypatch):
    monkeypatch.setattr(image_origin, "classifier_probability", lambda p: 0.10)
    path = _write(tmp_path, jpeg_bytes(size=(801, 600), exif_tags=CAMERA_EXIF, photo=True),
                  "photo.jpg")
    r = image_origin.analyze_image_origin(path)
    assert r["verdict"] == "LIKELY_REAL"
    assert r["confidence"] == 95                  # 90 + 10 camera, capped
    assert any("Apple" in reason for reason in r["reasons"])

def test_low_probability_without_camera_exif_is_likely_real_capped(tmp_path, monkeypatch):
    # 2026-07-21 realistic corpus: the likely_real band is 80% precise (28/35),
    # more reliable than the LIKELY_AI band (73.5%) we already emit, so a
    # strong classifier signal alone now earns LIKELY_REAL. Without camera
    # EXIF to corroborate it, the confidence is capped at the band precision.
    monkeypatch.setattr(image_origin, "classifier_probability", lambda p: 0.05)
    path = _write(tmp_path, jpeg_bytes(size=(801, 600), photo=True), "x.jpg")
    r = image_origin.analyze_image_origin(path)
    assert r["verdict"] == "LIKELY_REAL"
    assert r["confidence"] == 80                   # capped at band precision
    assert "capped" in r["analysis"]

def test_middle_probability_leans_not_uncertain(tmp_path, monkeypatch):
    # 2026-07-22 product decision: never hide behind UNCERTAIN once the model
    # has answered — a near-0.5 score is a low-confidence lean, not a non-answer.
    monkeypatch.setattr(image_origin, "classifier_probability", lambda p: 0.5)
    path = _write(tmp_path, jpeg_bytes(size=(801, 600), photo=True), "x.jpg")
    r = image_origin.analyze_image_origin(path)
    assert r["verdict"] == "LIKELY_AI"            # 0.5 rounds to the AI side
    assert r["confidence"] == 50
    assert r["ai_probability"] == 50
    assert "Leaning" in r["analysis"]             # low confidence → "Leaning"

def test_mid_real_probability_leans_real(tmp_path, monkeypatch):
    # p=0.40 → leans real at low confidence, no longer UNCERTAIN.
    monkeypatch.setattr(image_origin, "classifier_probability", lambda p: 0.40)
    path = _write(tmp_path, jpeg_bytes(size=(801, 600), photo=True), "x.jpg")
    r = image_origin.analyze_image_origin(path)
    assert r["verdict"] == "LIKELY_REAL"
    assert r["confidence"] == 60                  # (1-0.40)*100, under the 80 cap
    assert r["ai_probability"] == 40

def test_no_model_and_no_proof_is_uncertain(tmp_path, monkeypatch):
    # The ONLY surviving UNCERTAIN path: the classifier could not answer.
    monkeypatch.setattr(image_origin, "classifier_probability", lambda p: None)
    path = _write(tmp_path, jpeg_bytes(size=(801, 600), photo=True), "x.jpg")
    r = image_origin.analyze_image_origin(path)
    assert r["verdict"] == "UNCERTAIN"
    assert r["ai_probability"] is None
    assert "not available" in r["analysis"].lower()

def test_actions_always_present(tmp_path, monkeypatch):
    monkeypatch.setattr(image_origin, "classifier_probability", lambda p: None)
    path = _write(tmp_path, png_bytes())
    r = image_origin.analyze_image_origin(path)
    urls = " ".join(a["url"] for a in r["actions"] if a.get("url"))
    assert "contentcredentials.org" in urls
    assert "lens.google.com" in urls
    assert "tineye.com" in urls

def test_unreadable_file_is_honest_uncertain(tmp_path, monkeypatch):
    monkeypatch.setattr(image_origin, "classifier_probability",
                        lambda p: (_ for _ in ()).throw(AssertionError("no call")))
    path = _write(tmp_path, b"this is not an image", "junk.bin")
    r = image_origin.analyze_image_origin(path)
    assert r["verdict"] == "UNCERTAIN"
    assert "could not" in r["analysis"].lower()

def test_model_off_env_disables_classifier(tmp_path, monkeypatch):
    monkeypatch.setattr(image_origin, "MODEL_ID", "off")
    assert image_origin.classifier_probability(
        _write(tmp_path, png_bytes())) is None


# ---------------------------------------------------------------------------
# Not a photograph at all -> UNCERTAIN, whatever the classifier says.
#
# 2026-09-29 test pack: a plain computer gradient (png/bmp/tiff) came back
# LIKELY_REAL — "Likely a real photo". The detector is an AI-vs-camera-photo
# classifier; a flat colour, a smooth gradient or pure noise is neither, and
# whatever probability it returns for one is meaningless. Measured on the
# bundled corpora, real and AI photos sit at high-frequency detail 1.6-25 and
# neighbour correlation 0.73-0.99; the gradient at <= 0.37 detail, the noise
# at 0.004 correlation, the solid-colour "camera" JPEGs at zero variation.
# ---------------------------------------------------------------------------

def _gradient_png():
    img = Image.new("RGB", (512, 512))
    img.putdata([(x // 2, y // 2, 128) for y in range(512) for x in range(512)])
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def _noise_png():
    import numpy as np
    arr = (np.random.default_rng(3).random((400, 400, 3)) * 255).astype("uint8")
    buf = io.BytesIO()
    Image.fromarray(arr).save(buf, "PNG")
    return buf.getvalue()


def _no_classifier(p):
    raise AssertionError("the classifier must not be asked about a non-photo")


def test_a_plain_gradient_is_uncertain_not_real(tmp_path, monkeypatch):
    monkeypatch.setattr(image_origin, "classifier_probability", _no_classifier)
    r = image_origin.analyze_image_origin(_write(tmp_path, _gradient_png(), "g.png"))
    assert r["verdict"] == "UNCERTAIN"
    assert "photograph" in r["analysis"].lower()


def test_random_noise_is_uncertain(tmp_path, monkeypatch):
    monkeypatch.setattr(image_origin, "classifier_probability", _no_classifier)
    r = image_origin.analyze_image_origin(_write(tmp_path, _noise_png(), "n.png"))
    assert r["verdict"] == "UNCERTAIN"


def test_a_solid_colour_with_camera_exif_is_uncertain_but_keeps_the_exif_reason(tmp_path, monkeypatch):
    monkeypatch.setattr(image_origin, "classifier_probability", _no_classifier)
    path = _write(tmp_path, jpeg_bytes(size=(801, 600), exif_tags=CAMERA_EXIF), "s.jpg")
    r = image_origin.analyze_image_origin(path)
    assert r["verdict"] == "UNCERTAIN"
    assert any("Apple" in reason for reason in r["reasons"])


def test_metadata_proof_still_wins_on_a_blank_canvas(tmp_path, monkeypatch):
    monkeypatch.setattr(image_origin, "classifier_probability", _no_classifier)
    path = _write(tmp_path, png_bytes(text={"parameters": "cat, Steps: 20"}))
    assert image_origin.analyze_image_origin(path)["verdict"] == "AI_GENERATED"


def test_photographic_content_check_never_raises():
    assert image_origin.photographic_content(None) is None
