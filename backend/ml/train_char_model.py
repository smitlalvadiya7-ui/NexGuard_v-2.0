"""
Challenger URL model (NEXT_PHASE_PLAN M4): character-level TF-IDF +
logistic regression vs the deployed tree ensemble.

Honest comparison, same rules as everything else here:
  * trained and tested on the SAME dataset and the SAME 80/20 split
    parameters (random_state=42, stratified) as train.py / retrain.py, so
    the numbers are comparable with the deployed metrics;
  * the challenger only "wins" if it beats the deployed model's ROC-AUC
    AND does not regress F1 — ties keep the deployed model;
  * a winning challenger is saved as a CANDIDATE
    (phishing_model.char_candidate.joblib, input_mode="raw_url") — never
    deployed. Judge it on the REAL pipeline first:
        NEXGUARD_MODEL_PATH=<candidate> python -m eval.ab_eval scan ...
    (predict.py feeds raw_url bundles the URL string directly);
  * either way the outcome is recorded in ml/char_model_result.json.

Run (from backend/):  py -m ml.train_char_model
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

DATASET = os.path.join(HERE, "raw_dataset.csv")
LIVE_MODEL = os.path.join(HERE, "phishing_model.joblib")
LIVE_METRICS = os.path.join(HERE, "metrics.json")
PREV_MODEL = os.path.join(HERE, "phishing_model.prev.joblib")
PREV_METRICS = os.path.join(HERE, "metrics.prev.json")
RESULT_PATH = os.path.join(HERE, "char_model_result.json")
CAND_PATH = os.path.join(HERE, "phishing_model.char_candidate.joblib")

CHAR_MODEL_NAME = "char_tfidf_logreg"
_TOP_IMPORTANCES = 25


def decide(deployed_scores, challenger_scores):
    """(challenger_wins, reason). Fails safe: missing numbers keep deployed."""
    dep_auc = (deployed_scores or {}).get("roc_auc")
    dep_f1 = (deployed_scores or {}).get("f1")
    ch_auc = (challenger_scores or {}).get("roc_auc")
    ch_f1 = (challenger_scores or {}).get("f1")
    if None in (dep_auc, dep_f1, ch_auc, ch_f1):
        return False, "scores missing on one side — keeping the deployed model"
    if ch_auc <= dep_auc:
        return False, (f"challenger ROC-AUC {ch_auc:.4f} does not beat "
                       f"deployed {dep_auc:.4f}")
    if ch_f1 < dep_f1:
        return False, (f"challenger F1 regressed ({dep_f1:.4f} -> {ch_f1:.4f}) "
                       f"despite the ROC-AUC gain")
    return True, (f"challenger wins: ROC-AUC {dep_auc:.4f} -> {ch_auc:.4f}, "
                  f"F1 {dep_f1:.4f} -> {ch_f1:.4f}")


def char_metrics_dict(pipe, X_test, y_test, n_samples, n_phishing, prev_models):
    """
    Build a metrics.json-shaped dict for the char champion so /model-metrics
    and the Model page stay truthful after promotion: the char model's own
    confusion matrix, ROC curve and top-|coefficient| n-gram "importances",
    with the previous candidates' scores kept for the comparison table.
    No "calibration" block — the logistic pipeline ships uncalibrated, and
    scheduled_retrain.final_scores() then reads models[chosen_model].
    """
    import numpy as np
    from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                                 precision_score, recall_score, roc_auc_score,
                                 roc_curve)

    from ml.train import _downsample_roc

    proba = pipe.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    scores = {
        "accuracy":  round(float(accuracy_score(y_test, pred)), 4),
        "precision": round(float(precision_score(y_test, pred)), 4),
        "recall":    round(float(recall_score(y_test, pred)), 4),
        "f1":        round(float(f1_score(y_test, pred)), 4),
        "roc_auc":   round(float(roc_auc_score(y_test, proba)), 4),
    }
    cm = confusion_matrix(y_test, pred)
    fpr, tpr, thr = roc_curve(y_test, proba)
    roc_fpr, roc_tpr, roc_thr = _downsample_roc(fpr, tpr, thr)

    tfidf = pipe.named_steps["tfidf"]
    coef = np.abs(np.asarray(pipe.named_steps["clf"].coef_, dtype=float)).reshape(-1)
    total = coef.sum() or 1.0
    names = tfidf.get_feature_names_out()
    top_idx = np.argsort(coef)[::-1][:_TOP_IMPORTANCES]
    importances = [{"feature": f"ng_{str(names[i]).strip()}",
                    "importance": round(float(coef[i] / total), 5)}
                   for i in top_idx if str(names[i]).strip()]

    models = dict(prev_models or {})
    models[CHAR_MODEL_NAME] = scores
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "chosen_model": CHAR_MODEL_NAME,
        "selection_metric": ("real-pipeline A/B on a frozen corpus "
                             "(eval/ab_eval) + offline roc_auc/f1"),
        "dataset": {
            "n_samples": int(n_samples),
            "n_phishing": int(n_phishing),
            "n_legitimate": int(n_samples) - int(n_phishing),
            "n_features": len(tfidf.vocabulary_),
            "test_size": 0.2,
            "n_test": int(len(y_test)),
        },
        "models": models,
        "confusion_matrix": {
            "labels": ["legitimate", "phishing"],
            "matrix": cm.tolist(),
            "tn": int(cm[0, 0]), "fp": int(cm[0, 1]),
            "fn": int(cm[1, 0]), "tp": int(cm[1, 1]),
        },
        "roc_curve": {"fpr": roc_fpr, "tpr": roc_tpr, "thresholds": roc_thr},
        "feature_importances": importances,
    }


def promote_char(metrics: dict):
    """Char candidate becomes the deployed model; the old model + metrics are
    kept as .prev for one-copy rollback (same names scheduled_retrain uses)."""
    import shutil
    if os.path.exists(LIVE_MODEL):
        shutil.copy2(LIVE_MODEL, PREV_MODEL)
    if os.path.exists(LIVE_METRICS):
        shutil.copy2(LIVE_METRICS, PREV_METRICS)
    shutil.copy2(CAND_PATH, LIVE_MODEL)
    with open(LIVE_METRICS, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)


def run_promotion(data_path: str = DATASET) -> None:
    """
    Promote the saved char candidate after it has won the SERIAL real-pipeline
    A/B (eval/ab_eval). Rebuilds the same 80/20 split to compute the champion's
    honest metrics.json, then swaps the deployed model with a .prev backup.
    """
    import joblib
    import pandas as pd
    from sklearn.model_selection import train_test_split

    bundle = joblib.load(CAND_PATH)
    if bundle.get("input_mode") != "raw_url":
        raise SystemExit(f"{CAND_PATH} is not a raw_url char bundle — refusing")

    df = pd.read_csv(data_path)
    urls = df["url"].astype(str).tolist()
    y = df["status"].astype(str).str.lower().str.contains("phish").astype(int).values
    _, X_test, _, y_test = train_test_split(
        urls, y, test_size=0.2, random_state=42, stratify=y)

    try:
        with open(LIVE_METRICS, encoding="utf-8") as f:
            prev_models = json.load(f).get("models") or {}
    except Exception:
        prev_models = {}

    metrics = char_metrics_dict(bundle["model"], X_test, y_test,
                                n_samples=len(y), n_phishing=int(y.sum()),
                                prev_models=prev_models)
    promote_char(metrics)
    scores = metrics["models"][CHAR_MODEL_NAME]
    print(f"PROMOTED {CHAR_MODEL_NAME} -> {LIVE_MODEL}")
    print(f"  offline held-out: {scores}")
    print(f"  previous model kept as {PREV_MODEL} (rollback: copy it back)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=DATASET)
    ap.add_argument("--max-features", type=int, default=200_000)
    ap.add_argument("--promote", action="store_true",
                    help="promote the saved char candidate (run AFTER it wins "
                         "the serial real-pipeline A/B via eval/ab_eval)")
    args = ap.parse_args()

    if args.promote:
        run_promotion(args.data)
        return

    import joblib
    import pandas as pd
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import (accuracy_score, f1_score, precision_score,
                                 recall_score, roc_auc_score)
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import Pipeline

    from ml.scheduled_retrain import final_scores

    df = pd.read_csv(args.data)
    urls = df["url"].astype(str).tolist()
    y = df["status"].astype(str).str.lower().str.contains("phish").astype(int).values
    print(f"Dataset: {len(urls)} URLs ({int(y.sum())} phishing)")

    # Same split parameters as train.py / retrain.py — comparable numbers.
    X_train, X_test, y_train, y_test = train_test_split(
        urls, y, test_size=0.2, random_state=42, stratify=y)

    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5),
                                  max_features=args.max_features,
                                  sublinear_tf=True, min_df=2)),
        ("clf", LogisticRegression(max_iter=2000, C=10.0, solver="liblinear")),
    ])
    print("Training char-level TF-IDF + logistic regression ...")
    pipe.fit(X_train, y_train)

    proba = pipe.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    challenger = {
        "accuracy":  round(float(accuracy_score(y_test, pred)), 4),
        "precision": round(float(precision_score(y_test, pred)), 4),
        "recall":    round(float(recall_score(y_test, pred)), 4),
        "f1":        round(float(f1_score(y_test, pred)), 4),
        "roc_auc":   round(float(roc_auc_score(y_test, proba)), 4),
    }

    try:
        with open(LIVE_METRICS, encoding="utf-8") as f:
            deployed = final_scores(json.load(f))
    except Exception:
        deployed = {}

    print("\nmetric        deployed -> challenger")
    for m in ("accuracy", "precision", "recall", "f1", "roc_auc"):
        d = deployed.get(m)
        d = f"{d:.4f}" if isinstance(d, (int, float)) else "   n/a"
        print(f"  {m:11} {d:>8} -> {challenger[m]:.4f}")

    win, reason = decide(deployed, challenger)
    print(f"\nDecision: {'CHALLENGER WINS' if win else 'DEPLOYED KEEPS'} — {reason}")

    result = {
        "run_at": datetime.now(timezone.utc).isoformat(),
        "challenger": "char_tfidf_logreg (char_wb 2-5grams, "
                      f"max_features={args.max_features})",
        "n_samples": len(urls),
        "deployed_scores": deployed,
        "challenger_scores": challenger,
        "challenger_wins": win,
        "reason": reason,
    }
    with open(RESULT_PATH, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"Result recorded -> {RESULT_PATH}")

    if win:
        joblib.dump({"model": pipe, "features": [], "name": "char_tfidf_logreg",
                     "calibrated": False, "input_mode": "raw_url"},
                    CAND_PATH, compress=3)
        print(f"Candidate saved -> {CAND_PATH}  (NOT deployed)")
        print("Judge it on the REAL pipeline before any promotion:")
        print(f"  NEXGUARD_MODEL_PATH={CAND_PATH}")
        print("      python -m eval.ab_eval scan eval/_corpus.json eval/_char.json")
    else:
        print("The deployed tree ensemble stays — recorded honestly.")


if __name__ == "__main__":
    main()
