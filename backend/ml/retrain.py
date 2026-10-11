"""
Active-learning retrain for the NexGuard phishing classifier.

Folds admin-ACCEPTED verdict feedback (from the verdict_feedback table) into the
training set, retrains + calibrates a CANDIDATE model, and prints a before/after
metrics comparison against the currently deployed model.

IMPORTANT: this NEVER deploys. It writes only:
    phishing_model.candidate.joblib
    metrics.candidate.json
An admin reviews the comparison and, if happy, manually promotes the candidate:
    copy phishing_model.candidate.joblib -> phishing_model.joblib
    copy metrics.candidate.json          -> metrics.json
and restarts the server.

Usage:
    python retrain.py [--data raw_dataset.csv] [--min-feedback 1]
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.metrics import (accuracy_score, brier_score_loss, confusion_matrix,
                             f1_score, precision_score, recall_score,
                             roc_auc_score, roc_curve)
from sklearn.model_selection import train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
# Make sibling backend modules (db_config, models) and ml modules importable
for p in (BACKEND, HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from features import FEATURE_NAMES, extract_features          # noqa: E402
import train as T                                             # reuse the proven helpers  # noqa: E402

CAND_MODEL = os.path.join(HERE, "phishing_model.candidate.joblib")
CAND_METRICS = os.path.join(HERE, "metrics.candidate.json")
LIVE_METRICS = os.path.join(HERE, "metrics.json")


def _load_accepted_feedback():
    """Return [(url, status)] for admin-accepted feedback rows."""
    try:
        # db_config binds the SQLite engine to a path relative to cwd, so anchor
        # to the backend dir to hit the SAME nexguard.db the server uses.
        os.chdir(BACKEND)
        from db_config import SessionLocal, engine, Base
        from models import VerdictFeedback
        Base.metadata.create_all(bind=engine)   # no-op if it already exists
    except Exception as e:
        print(f"Could not open the feedback DB: {e}")
        return []
    db = SessionLocal()
    try:
        rows = db.query(VerdictFeedback).filter(VerdictFeedback.status == "accepted").all()
        out = []
        for r in rows:
            status = "phishing" if (r.user_label or "").lower() == "malicious" else "legitimate"
            if r.url:
                out.append((r.url.strip(), status))
        return out
    finally:
        db.close()


def combine_with_feedback(base: "pd.DataFrame", feedback: list) -> "pd.DataFrame":
    """
    Fold accepted human feedback [(url, status)] into the base training frame.
    Active learning rule: on a duplicate URL the HUMAN label wins (keep="last").
    """
    if not feedback:
        return base.reset_index(drop=True)
    fb_df = pd.DataFrame(feedback, columns=["url", "status"])
    combined = pd.concat([base, fb_df], ignore_index=True)
    return combined.drop_duplicates(subset="url", keep="last").reset_index(drop=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.join(HERE, "raw_dataset.csv"))
    ap.add_argument("--min-feedback", type=int, default=1)
    args = ap.parse_args()

    # ---- assemble the augmented dataset -----------------------------------
    base = pd.read_csv(args.data)
    url_col = "url" if "url" in base.columns else base.columns[0]
    label_col = "status" if "status" in base.columns else base.columns[-1]
    base = base[[url_col, label_col]].rename(columns={url_col: "url", label_col: "status"})

    feedback = _load_accepted_feedback()
    print(f"Accepted feedback rows: {len(feedback)}")
    if len(feedback) < args.min_feedback:
        print(f"Not enough accepted feedback (need >= {args.min_feedback}). Nothing to do.")
        return

    combined = combine_with_feedback(base, feedback)
    print(f"Base rows: {len(base)} | combined (deduped): {len(combined)}")

    X = np.array([extract_features(u) for u in combined["url"].astype(str)])
    y = combined["status"].astype(str).str.lower().str.contains("phish").astype(int).values
    n_phish, n_legit = int(y.sum()), int((y == 0).sum())

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # ---- train + select (reuse train.py helpers) --------------------------
    candidates = T._build_candidates()
    fitted, scores = {}, {}
    for name, model in candidates.items():
        print(f"Training {name} ...")
        model.fit(X_train, y_train)
        fitted[name] = model
        scores[name] = T._evaluate(model, X_test, y_test)

    best_name = max(candidates, key=lambda n: (scores[n]["roc_auc"], scores[n]["f1"]))
    best_model = fitted[best_name]
    print(f"Chosen candidate model: {best_name}")

    # ---- calibrate --------------------------------------------------------
    proba_uncal = best_model.predict_proba(X_test)[:, 1]
    brier_before = float(brier_score_loss(y_test, proba_uncal))
    fresh = T._build_candidates()[best_name]
    calibrated = CalibratedClassifierCV(fresh, method="isotonic", cv=5)
    calibrated.fit(X_train, y_train)

    proba = calibrated.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    brier_after = float(brier_score_loss(y_test, proba))
    cand_scores = {
        "accuracy":  round(float(accuracy_score(y_test, pred)), 4),
        "precision": round(float(precision_score(y_test, pred)), 4),
        "recall":    round(float(recall_score(y_test, pred)), 4),
        "f1":        round(float(f1_score(y_test, pred)), 4),
        "roc_auc":   round(float(roc_auc_score(y_test, proba)), 4),
    }
    cm = confusion_matrix(y_test, pred)
    fpr, tpr, thr = roc_curve(y_test, proba)
    roc_fpr, roc_tpr, roc_thr = T._downsample_roc(fpr, tpr, thr)

    # ---- save candidate (NEVER the live model) ----------------------------
    joblib.dump(
        {"model": calibrated, "features": FEATURE_NAMES, "name": best_name,
         "calibrated": True, "calibration_method": "isotonic"},
        CAND_MODEL, compress=3,
    )
    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "chosen_model": best_name,
        "selection_metric": "roc_auc (tie-break: f1)",
        "is_candidate": True,
        "dataset": {
            "n_samples": int(len(y)), "n_phishing": n_phish, "n_legitimate": n_legit,
            "n_features": len(FEATURE_NAMES), "test_size": 0.2, "n_test": int(len(y_test)),
            "n_feedback_accepted": len(feedback),
        },
        "models": scores,
        "calibration": {"method": "isotonic",
                        "brier_before": round(brier_before, 5),
                        "brier_after": round(brier_after, 5),
                        "chosen_calibrated_metrics": cand_scores},
        "confusion_matrix": {"labels": ["legitimate", "phishing"], "matrix": cm.tolist(),
                             "tn": int(cm[0, 0]), "fp": int(cm[0, 1]),
                             "fn": int(cm[1, 0]), "tp": int(cm[1, 1])},
        "roc_curve": {"fpr": roc_fpr, "tpr": roc_tpr, "thresholds": roc_thr},
        "feature_importances": T._feature_importances(best_model),
    }
    with open(CAND_METRICS, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    # ---- before/after comparison vs the deployed model --------------------
    print("\n" + "=" * 64)
    print("RETRAIN COMPARISON (deployed -> candidate)")
    print("=" * 64)
    try:
        with open(LIVE_METRICS, encoding="utf-8") as f:
            live = json.load(f)
        live_chosen = live.get("chosen_model")
        live_scores = (live.get("models", {}) or {}).get(live_chosen, {})
        live_cal = (live.get("calibration", {}) or {})
    except Exception:
        live_scores, live_cal = {}, {}

    def _row(label, before, after):
        b = f"{before:.4f}" if isinstance(before, (int, float)) else "  n/a"
        a = f"{after:.4f}" if isinstance(after, (int, float)) else "  n/a"
        delta = ""
        if isinstance(before, (int, float)) and isinstance(after, (int, float)):
            delta = f"  ({'+' if after >= before else ''}{after - before:.4f})"
        print(f"  {label:14} {b:>8} -> {a:>8}{delta}")

    for m in ("accuracy", "precision", "recall", "f1", "roc_auc"):
        _row(m, live_scores.get(m), cand_scores.get(m))
    _row("brier", live_cal.get("brier_after"), round(brier_after, 5))

    improved = cand_scores.get("roc_auc", 0) >= (live_scores.get("roc_auc") or 0)
    print("=" * 64)
    print(f"Candidate ROC-AUC {'improved or matched' if improved else 'REGRESSED'} vs deployed.")
    print(f"\nSaved candidate model   -> {CAND_MODEL}")
    print(f"Saved candidate metrics -> {CAND_METRICS}")
    print("\nNOT deployed. Judge the candidate on the REAL pipeline first (M3):")
    print("  cd backend")
    print("  python -m eval.ab_eval build eval/_corpus.json")
    print("  python -m eval.ab_eval scan  eval/_corpus.json eval/_deployed.json")
    print(f"  NEXGUARD_MODEL_PATH={CAND_MODEL}")
    print("      python -m eval.ab_eval scan eval/_corpus.json eval/_candidate.json")
    print("  python -m eval.ab_eval diff  eval/_deployed.json eval/_candidate.json")
    print("Run the two scans SERIALLY (parallel runs exhaust the reputation")
    print("quotas and fake a recall collapse). To promote (admin decision), copy")
    print("the candidate files over phishing_model.joblib / metrics.json and")
    print("restart the server.")


if __name__ == "__main__":
    main()
