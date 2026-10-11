"""
AI-image detector model benchmark — MANUAL CLI, never run by pytest.

Compares the two candidate detectors on labeled images and picks a winner:
    Organika/sdxl-detector      (ViT fine-tuned on SDXL vs photos)
    umm-maybe/AI-image-detector (Swin fine-tuned on AI art vs photos)

Data sources (all optional, whatever exists is used, honestly reported):
  * testdata/image_origin/ai/    — user-provided known AI images
  * testdata/image_origin/real/  — user-provided known real photos
  * a public Hugging Face dataset sample (needs the `datasets` package;
    skipped with a clear message when unavailable)

Run from backend/:
    py -m eval.image_model_benchmark --sample 50
Writes eval/image_model_result.json and prints the winner. The winner id is
then hard-coded as the MODEL_ID default in backend/image_origin.py.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

_BACKEND = Path(__file__).resolve().parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from image_origin import (_AI_LABELS, _REAL_LABELS,  # noqa: E402
                          CLASSIFIER_HI, CLASSIFIER_LO)

CANDIDATES = [
    "Organika/sdxl-detector",
    "umm-maybe/AI-image-detector",
    "haywoodsloan/ai-image-detector-deploy",
    "dima806/ai_vs_real_image_detection",
    # NYUAD-ComNets/NYUAD_AI-generated_images_detector: dropped 2026-07-21 —
    # its config lacks image_processor_type and transformers 5.x refuses it.
]
TESTDATA = _BACKEND.parent / "testdata" / "image_origin"
RESULT_PATH = Path(__file__).resolve().parent / "image_model_result.json"
CORPUS_DIR = Path(__file__).resolve().parent / "_image_corpus"
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".webp", ".bmp"}

# Reject thumbnails: the 2026-07-19 corpus was 84% CIFAKE 32×32 images, which
# no ViT/Swin detector (trained on real-resolution photos/art) can judge —
# every model scored a coin flip and the winner was picked on junk. Users scan
# real-size photos, memes and screenshots, so the corpus must look like that.
MIN_DIM = 200

# (dataset id, image column, label spec) — walked in order until BOTH classes
# are filled. label spec is a column name, or ("fixed", is_ai) for datasets
# that contain only one class (e.g. Flickr = all real photos).
DATASET_CANDIDATES = [
    ("Hemg/AI-Generated-vs-Real-Images-Datasets", "image", "label"),
    # Real-photo fillers (parquet-native — script datasets like flickr30k no
    # longer load): Hemg's real side runs dry under the MIN_DIM filter.
    # COCO = diverse everyday photography; food101 = backup if COCO breaks.
    ("detection-datasets/coco", "image", ("fixed", False)),
    ("ethz/food101", "image", ("fixed", False)),
]
SCAN_CAP = 3000                 # rows to stream per dataset before giving up


def load_local():
    """[(PIL.Image, truth_is_ai, source_name)] from the user's testdata folders."""
    from PIL import Image
    items = []
    for sub, is_ai in (("ai", True), ("real", False)):
        folder = TESTDATA / sub
        if not folder.is_dir():
            continue
        for p in sorted(folder.iterdir()):
            if p.suffix.lower() in IMAGE_EXT:
                try:
                    img = Image.open(p)
                    img.load()
                    if min(img.size) < MIN_DIM:
                        continue        # thumbnails can't be judged fairly
                    items.append((img.convert("RGB"), is_ai, f"local:{p.name}"))
                except Exception as e:
                    print(f"  ! skipping unreadable {p.name}: {e}")
    return items


def _label_is_ai(names, value):
    """Map a dataset label (int or str) to True=AI using the label names.
    REAL keywords are checked FIRST: Hemg's classes are AiArtData/RealArt,
    and a naive 'art' match would tag BOTH as AI (2026-07-19 bug)."""
    name = str(names[value] if names and isinstance(value, int) else value).lower()
    if any(k in name for k in ("real", "human", "photo", "camera", "genuine")):
        return False
    if any(k in name for k in ("ai", "fake", "generated", "synthetic")):
        return True
    return None


def load_public(per_class):
    """Stream a labeled sample from public datasets until BOTH classes are
    filled (shuffled streams — class-sorted datasets would otherwise yield
    only one label, which is exactly what a fair benchmark must not do)."""
    try:
        from datasets import load_dataset
    except Exception:
        print("  ! `datasets` package not installed — public sample skipped "
              "(pip install datasets)")
        return []
    got = {True: 0, False: 0}
    items = []
    for ds_id, img_col, label_spec in DATASET_CANDIDATES:
        if all(v >= per_class for v in got.values()):
            break
        fixed = isinstance(label_spec, tuple) and label_spec[0] == "fixed"
        if fixed and got[label_spec[1]] >= per_class:
            continue                        # this class is already full
        try:
            print(f"  streaming sample from {ds_id} …")
            ds = None
            last_err = None
            for split in ("train",) if not fixed else ("validation", "val",
                                                       "test", "train"):
                try:
                    ds = load_dataset(ds_id, split=split, streaming=True)
                    break
                except Exception as e:
                    last_err = e
            if ds is None:
                raise last_err
            try:
                ds = ds.shuffle(seed=42, buffer_size=500)
            except Exception:
                pass
            names = None
            if not fixed:
                try:
                    names = ds.features[label_spec].names
                except Exception:
                    pass
            scanned = 0
            for row in ds:
                scanned += 1
                if scanned > SCAN_CAP or all(v >= per_class for v in got.values()):
                    break
                truth = (label_spec[1] if fixed
                         else _label_is_ai(names, row[label_spec]))
                if truth is None or got[truth] >= per_class:
                    continue
                try:
                    img = row[img_col]
                    if min(img.size) < MIN_DIM:
                        continue        # thumbnails can't be judged fairly
                    items.append((img.convert("RGB"), truth, ds_id))
                    got[truth] += 1
                except Exception:
                    continue
            print(f"  running total: {got[True]} AI + {got[False]} real")
        except Exception as e:
            print(f"  ! {ds_id} failed: {e}")
    if not items:
        print("  ! no public dataset reachable — continuing with local images only")
    return items


def probability_ai(pipe, img):
    """Same label mapping the engine uses (image_origin.classifier_probability)."""
    preds = pipe(img) or []
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


def freeze_corpus(items):
    """Save the sampled corpus so reruns judge the SAME images (ab_eval
    philosophy: a frozen corpus is the only fair comparison)."""
    for sub in ("ai", "real"):
        (CORPUS_DIR / sub).mkdir(parents=True, exist_ok=True)
        for old in (CORPUS_DIR / sub).glob("*.png"):
            old.unlink()                # a refresh replaces the corpus fully
    counts = {True: 0, False: 0}
    for img, truth, _src in items:
        sub = "ai" if truth else "real"
        counts[truth] += 1
        img.save(CORPUS_DIR / sub / f"{counts[truth]:04d}.png")
    print(f"  corpus frozen to {CORPUS_DIR} "
          f"({counts[True]} AI / {counts[False]} real)")


def load_frozen():
    from PIL import Image
    items = []
    for sub, is_ai in (("ai", True), ("real", False)):
        folder = CORPUS_DIR / sub
        if not folder.is_dir():
            continue
        for p in sorted(folder.glob("*.png")):
            img = Image.open(p)
            img.load()
            items.append((img.convert("RGB"), is_ai, f"frozen:{p.name}"))
    return items


def evaluate(model_id, items):
    from transformers import pipeline as hf_pipeline
    print(f"\n== {model_id} ==")
    t0 = time.time()
    try:
        pipe = hf_pipeline("image-classification", model=model_id)
    except Exception as e:
        print(f"  ! model failed to load, skipping: {e}")
        return None
    load_s = round(time.time() - t0, 1)
    tp = fp = tn = fn = unmapped = 0
    # What the ENGINE would actually tell a user (its live thresholds),
    # split by truth — a confidently WRONG verdict is the worst outcome.
    band = {"likely_ai": {"ai": 0, "real": 0},
            "likely_real": {"ai": 0, "real": 0},
            "uncertain": {"ai": 0, "real": 0}}
    t0 = time.time()
    for img, truth_ai, _src in items:
        p = probability_ai(pipe, img)
        if p is None:
            unmapped += 1
            continue
        pred_ai = p >= 0.5
        if pred_ai and truth_ai:
            tp += 1
        elif pred_ai and not truth_ai:
            fp += 1
        elif not pred_ai and not truth_ai:
            tn += 1
        else:
            fn += 1
        b = ("likely_ai" if p >= CLASSIFIER_HI else
             "likely_real" if p <= CLASSIFIER_LO else "uncertain")
        band[b]["ai" if truth_ai else "real"] += 1
    scan_s = round(time.time() - t0, 1)
    total = tp + fp + tn + fn
    acc = round(100 * (tp + tn) / total, 2) if total else 0.0
    prec = round(100 * tp / (tp + fp), 2) if (tp + fp) else 0.0
    rec = round(100 * tp / (tp + fn), 2) if (tp + fn) else 0.0
    claims = (band["likely_ai"]["ai"] + band["likely_ai"]["real"]
              + band["likely_real"]["ai"] + band["likely_real"]["real"])
    correct = band["likely_ai"]["ai"] + band["likely_real"]["real"]
    verdict_precision = round(100 * correct / claims, 2) if claims else 0.0
    coverage = round(100 * claims / total, 2) if total else 0.0
    stats = {"model": model_id, "images": total, "accuracy": acc,
             "ai_precision": prec, "ai_recall": rec,
             "tp": tp, "fp": fp, "tn": tn, "fn": fn, "unmapped": unmapped,
             "bands": band, "verdict_precision": verdict_precision,
             "verdict_coverage": coverage,
             "load_seconds": load_s, "scan_seconds": scan_s}
    print(f"  images={total} accuracy={acc}% AI-precision={prec}% "
          f"AI-recall={rec}%")
    print(f"  emitted verdicts: precision={verdict_precision}% "
          f"coverage={coverage}% bands={band} ({scan_s}s)")
    return stats


def main():
    ap = argparse.ArgumentParser(description="Benchmark AI-image detectors")
    ap.add_argument("--sample", type=int, default=50,
                    help="public images per class (default 50)")
    ap.add_argument("--models", nargs="*", default=CANDIDATES)
    ap.add_argument("--refresh", action="store_true",
                    help="re-stream a fresh public sample instead of the frozen corpus")
    args = ap.parse_args()

    print("Collecting labeled images …")
    items = load_local()
    print(f"  {len(items)} local images from {TESTDATA}")
    frozen = [] if args.refresh else load_frozen()
    if frozen:
        print(f"  {len(frozen)} frozen-corpus images from {CORPUS_DIR}")
        items += frozen
    else:
        fresh = load_public(args.sample)
        if fresh:
            freeze_corpus(fresh)
        items += fresh
    if not items:
        print("No labeled images at all — add files to "
              "testdata/image_origin/{ai,real}/ or install `datasets`.")
        return 1

    n_ai = sum(1 for _i, t, _s in items if t)
    print(f"Total: {len(items)} images ({n_ai} AI / {len(items) - n_ai} real)")

    results = [r for r in (evaluate(m, items) for m in args.models) if r]
    if not results:
        print("No model produced results — nothing to compare.")
        return 1
    # Winner: the model whose EMITTED verdicts are most often right
    # (NexGuard rule: confidently wrong is the worst outcome; UNCERTAIN is
    # honest). Ties: more coverage, then raw accuracy.
    winner = max(results, key=lambda r: (r["verdict_precision"],
                                         r["verdict_coverage"], r["accuracy"]))
    out = {"date": time.strftime("%Y-%m-%d %H:%M"), "corpus_size": len(items),
           "corpus_ai": n_ai, "models": results, "winner": winner["model"]}
    RESULT_PATH.write_text(json.dumps(out, indent=2))
    print(f"\nWINNER: {winner['model']}  (written to {RESULT_PATH.name})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
