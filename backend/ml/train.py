"""
Train & evaluate the NexGuard phishing URL classifier.

Usage:
    python train.py --data raw_dataset.csv

Loads a CSV with a 'url' column and a 'status' column (legitimate/phishing),
extracts the same 24 offline lexical features used at prediction time, then
trains and compares THREE candidates on a held-out test set:

    1. RandomForest               (the existing baseline)
    2. XGBoost                    (gradient-boosted trees)
    3. SoftVotingEnsemble         (soft-voting average of RF + XGBoost)

The candidate with the best ROC-AUC (tie-broken by F1) is kept and written to
`phishing_model.joblib`.  A full `metrics.json` is also written containing every
candidate's accuracy / precision / recall / F1 / ROC-AUC, plus the chosen
model's confusion matrix, ROC-curve points and feature importances, the dataset
size and the chosen model type.
"""
import argparse
import json
import os
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import (accuracy_score, brier_score_loss, confusion_matrix,
                             f1_score, precision_score, recall_score,
                             roc_auc_score, roc_curve)
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from features import FEATURE_NAMES, extract_features

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(HERE, "phishing_model.joblib")
METRICS_PATH = os.path.join(HERE, "metrics.json")

# Keep ROC-curve output compact (full curves can have thousands of points).
_MAX_ROC_POINTS = 200


def load_dataset(path):
    df = pd.read_csv(path)
    url_col = "url" if "url" in df.columns else df.columns[0]
    label_col = "status" if "status" in df.columns else df.columns[-1]
    X = np.array([extract_features(u) for u in df[url_col].astype(str)])
    y = (df[label_col].astype(str).str.lower().str.contains("phish")).astype(int).values
    return X, y


def _build_candidates():
    """Construct the three candidate estimators (fresh, unfitted)."""
    rf = RandomForestClassifier(
        n_estimators=200, max_depth=16, min_samples_leaf=4,
        n_jobs=-1, random_state=42,
    )
    xgb = XGBClassifier(
        n_estimators=400, max_depth=6, learning_rate=0.1,
        subsample=0.9, colsample_bytree=0.9,
        eval_metric="logloss", tree_method="hist",
        n_jobs=-1, random_state=42,
    )
    # Soft voting averages the two models' predicted probabilities.
    ensemble = VotingClassifier(
        estimators=[("rf", rf), ("xgb", xgb)],
        voting="soft", n_jobs=-1,
    )
    return {"RandomForest": rf, "XGBoost": xgb, "SoftVotingEnsemble": ensemble}


def _evaluate(model, X_test, y_test):
    """Return the standard metric set for a fitted model on the test set."""
    pred = model.predict(X_test)
    proba = model.predict_proba(X_test)[:, 1]
    return {
        "accuracy":  round(float(accuracy_score(y_test, pred)), 4),
        "precision": round(float(precision_score(y_test, pred)), 4),
        "recall":    round(float(recall_score(y_test, pred)), 4),
        "f1":        round(float(f1_score(y_test, pred)), 4),
        "roc_auc":   round(float(roc_auc_score(y_test, proba)), 4),
    }


def _feature_importances(model):
    """Importances for the chosen model. Averages RF+XGB for the ensemble."""
    if hasattr(model, "feature_importances_"):
        imp = np.asarray(model.feature_importances_, dtype=float)
    elif isinstance(model, VotingClassifier):
        mats = [np.asarray(est.feature_importances_, dtype=float)
                for est in model.named_estimators_.values()
                if hasattr(est, "feature_importances_")]
        if not mats:
            return []
        # Normalise each to sum 1 before averaging (RF and XGB use different scales).
        mats = [m / m.sum() if m.sum() else m for m in mats]
        imp = np.mean(mats, axis=0)
    else:
        return []
    pairs = sorted(zip(FEATURE_NAMES, imp), key=lambda t: t[1], reverse=True)
    return [{"feature": n, "importance": round(float(v), 5)} for n, v in pairs]


def _downsample_roc(fpr, tpr, thr):
    """Evenly subsample ROC points so metrics.json stays small."""
    n = len(fpr)
    if n <= _MAX_ROC_POINTS:
        idx = range(n)
    else:
        idx = np.unique(np.linspace(0, n - 1, _MAX_ROC_POINTS).astype(int))
    return (
        [round(float(fpr[i]), 5) for i in idx],
        [round(float(tpr[i]), 5) for i in idx],
        # thresholds[0] is +inf in sklearn; clamp for valid JSON.
        [round(float(min(thr[i], 1.0)), 5) for i in idx],
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.join(HERE, "raw_dataset.csv"))
    args = ap.parse_args()

    print(f"Loading {args.data} ...")
    X, y = load_dataset(args.data)
    n_phish, n_legit = int(y.sum()), int((y == 0).sum())
    print(f"Samples: {len(y)} | phishing: {n_phish} | legitimate: {n_legit}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    candidates = _build_candidates()
    fitted, scores = {}, {}
    for name, model in candidates.items():
        print(f"\nTraining {name} ...")
        model.fit(X_train, y_train)
        fitted[name] = model
        scores[name] = _evaluate(model, X_test, y_test)

    # ---- comparison table -------------------------------------------------
    cols = ["accuracy", "precision", "recall", "f1", "roc_auc"]
    print("\n" + "=" * 74)
    print(f"{'Model':22}" + "".join(f"{c:>11}" for c in cols))
    print("-" * 74)
    for name in candidates:
        print(f"{name:22}" + "".join(f"{scores[name][c]:>11.4f}" for c in cols))
    print("=" * 74)

    # ---- pick the best (ROC-AUC, tie-broken by F1) ------------------------
    best_name = max(candidates, key=lambda n: (scores[n]["roc_auc"], scores[n]["f1"]))
    best_model = fitted[best_name]
    print(f"\nChosen model: {best_name} "
          f"(roc_auc={scores[best_name]['roc_auc']:.4f}, f1={scores[best_name]['f1']:.4f})")

    # ---- probability calibration -----------------------------------------
    # Wrap a FRESH clone of the chosen estimator in CalibratedClassifierCV so the
    # probabilities we ship are well-calibrated (predicted prob ~= empirical risk).
    # Isotonic is safe at this sample size; cv=5 refits internally (no separate
    # holdout needed). The DEPLOYED model is the calibrated one; predict.py just
    # calls predict_proba and needs no change.
    proba_uncal = best_model.predict_proba(X_test)[:, 1]
    brier_before = float(brier_score_loss(y_test, proba_uncal))
    rel_true_b, rel_pred_b = calibration_curve(y_test, proba_uncal, n_bins=10, strategy="quantile")

    fresh = _build_candidates()[best_name]
    print(f"\nCalibrating {best_name} (isotonic, cv=5) ...")
    calibrated = CalibratedClassifierCV(fresh, method="isotonic", cv=5)
    calibrated.fit(X_train, y_train)

    proba = calibrated.predict_proba(X_test)[:, 1]   # calibrated proba drives cm/roc
    pred = (proba >= 0.5).astype(int)
    brier_after = float(brier_score_loss(y_test, proba))
    rel_true_a, rel_pred_a = calibration_curve(y_test, proba, n_bins=10, strategy="quantile")
    calibrated_scores = {
        "accuracy":  round(float(accuracy_score(y_test, pred)), 4),
        "precision": round(float(precision_score(y_test, pred)), 4),
        "recall":    round(float(recall_score(y_test, pred)), 4),
        "f1":        round(float(f1_score(y_test, pred)), 4),
        "roc_auc":   round(float(roc_auc_score(y_test, proba)), 4),
    }

    cm = confusion_matrix(y_test, pred)
    fpr, tpr, thr = roc_curve(y_test, proba)
    roc_fpr, roc_tpr, roc_thr = _downsample_roc(fpr, tpr, thr)
    # Importances come from the uncalibrated base model (the calibrated wrapper
    # doesn't expose feature_importances_).
    importances = _feature_importances(best_model)

    print(f"Brier score  before={brier_before:.4f}  after={brier_after:.4f}  "
          f"({'improved' if brier_after <= brier_before else 'worse'})")
    print("\nConfusion matrix (rows=true, cols=pred) [legit, phish]:")
    print(cm)
    if importances:
        print("\nTop 10 features:")
        for item in importances[:10]:
            print(f"  {item['feature']:28} {item['importance']:.5f}")

    # ---- persist model + metrics -----------------------------------------
    joblib.dump(
        {"model": calibrated, "features": FEATURE_NAMES, "name": best_name,
         "calibrated": True, "calibration_method": "isotonic"},
        MODEL_PATH, compress=3,
    )
    print(f"\nSaved calibrated model -> {MODEL_PATH}")

    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "chosen_model": best_name,
        "selection_metric": "roc_auc (tie-break: f1)",
        "dataset": {
            "n_samples": int(len(y)),
            "n_phishing": n_phish,
            "n_legitimate": n_legit,
            "n_features": len(FEATURE_NAMES),
            "test_size": 0.2,
            "n_test": int(len(y_test)),
        },
        "models": scores,
        "calibration": {
            "method": "isotonic",
            "brier_before": round(brier_before, 5),
            "brier_after": round(brier_after, 5),
            "chosen_calibrated_metrics": calibrated_scores,
            "reliability_before": {
                "prob_pred": [round(float(v), 5) for v in rel_pred_b],
                "prob_true": [round(float(v), 5) for v in rel_true_b],
            },
            "reliability_after": {
                "prob_pred": [round(float(v), 5) for v in rel_pred_a],
                "prob_true": [round(float(v), 5) for v in rel_true_a],
            },
        },
        "confusion_matrix": {
            "labels": ["legitimate", "phishing"],
            "matrix": cm.tolist(),
            "tn": int(cm[0, 0]), "fp": int(cm[0, 1]),
            "fn": int(cm[1, 0]), "tp": int(cm[1, 1]),
        },
        "roc_curve": {"fpr": roc_fpr, "tpr": roc_tpr, "thresholds": roc_thr},
        "feature_importances": importances,
    }
    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"Saved metrics -> {METRICS_PATH}")


if __name__ == "__main__":
    main()
