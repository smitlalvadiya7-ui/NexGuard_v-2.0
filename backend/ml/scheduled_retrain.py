"""
Scheduled retrain with a safety gate (NEXT_PHASE_PLAN M5).

Weekly job: retrain a candidate model on the base dataset + accepted user
feedback (ml/retrain.py), then promote it over the deployed model ONLY if
the safety gate passes:

  * candidate ROC-AUC  >= deployed ROC-AUC          (no regression)
  * candidate precision >= deployed precision - slack (default 0.005)
  * candidate precision >= --min-precision floor, if given

If the gate fails, the deployed model stays and the reason is recorded.
Every run appends a line to ml/retrain_log.json so decisions are auditable.
The previous deployed model is kept as phishing_model.prev.joblib — restore
it by copying back if a promotion ever misbehaves.

The gate compares OFFLINE metrics (same test split for both sides). For big
model changes, judging on the REAL pipeline stays best practice:
`python -m eval.ab_eval` serially before/after — see ml/retrain.py's output.
The server loads the model at startup — restart it after a promotion.

Run once (from backend/):    py -m ml.scheduled_retrain [--dry-run]
Register weekly (Windows, run from backend/ as your user):

  schtasks /Create /SC WEEKLY /D SUN /ST 03:00 /TN "NexGuard weekly retrain" ^
    /TR "cmd /c cd /d %CD% && py -m ml.scheduled_retrain >> ml\\retrain_task.log 2>&1"

Remove with:  schtasks /Delete /TN "NexGuard weekly retrain" /F
"""

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, BACKEND)

CAND_MODEL = os.path.join(HERE, "phishing_model.candidate.joblib")
CAND_METRICS = os.path.join(HERE, "metrics.candidate.json")
LIVE_MODEL = os.path.join(HERE, "phishing_model.joblib")
LIVE_METRICS = os.path.join(HERE, "metrics.json")
PREV_MODEL = os.path.join(HERE, "phishing_model.prev.joblib")
PREV_METRICS = os.path.join(HERE, "metrics.prev.json")
RUN_LOG = os.path.join(HERE, "retrain_log.json")

PRECISION_SLACK = 0.005


def final_scores(metrics) -> dict:
    """The model's final offline scores from a metrics dict: calibrated
    numbers when present, else the chosen model's selection scores."""
    if not isinstance(metrics, dict):
        return {}
    cal = (metrics.get("calibration") or {}).get("chosen_calibrated_metrics")
    if isinstance(cal, dict) and cal:
        return cal
    chosen = metrics.get("chosen_model")
    scores = (metrics.get("models") or {}).get(chosen)
    return scores if isinstance(scores, dict) else {}


def should_promote(deployed_metrics, candidate_metrics,
                   precision_slack=PRECISION_SLACK, min_precision=None):
    """Safety gate. Returns (ok, reason). Fails safe on missing numbers —
    an unjudgeable candidate is never promoted."""
    dep = final_scores(deployed_metrics)
    cand = final_scores(candidate_metrics)
    dep_auc, cand_auc = dep.get("roc_auc"), cand.get("roc_auc")
    dep_p, cand_p = dep.get("precision"), cand.get("precision")
    if None in (dep_auc, cand_auc, dep_p, cand_p):
        return False, "metrics missing on one side — cannot judge, keeping deployed"
    if cand_auc < dep_auc:
        return False, f"ROC-AUC regressed ({dep_auc:.4f} -> {cand_auc:.4f})"
    if cand_p < dep_p - precision_slack:
        return False, (f"precision dropped beyond slack "
                       f"({dep_p:.4f} -> {cand_p:.4f}, slack {precision_slack})")
    if min_precision is not None and cand_p < min_precision:
        return False, f"precision {cand_p:.4f} below the floor {min_precision}"
    return True, (f"no regression: ROC-AUC {dep_auc:.4f} -> {cand_auc:.4f}, "
                  f"precision {dep_p:.4f} -> {cand_p:.4f}")


def promote():
    """Candidate becomes the deployed model; the old one is kept as .prev."""
    if os.path.exists(LIVE_MODEL):
        shutil.copy2(LIVE_MODEL, PREV_MODEL)
    if os.path.exists(LIVE_METRICS):
        shutil.copy2(LIVE_METRICS, PREV_METRICS)
    shutil.copy2(CAND_MODEL, LIVE_MODEL)
    shutil.copy2(CAND_METRICS, LIVE_METRICS)


def _log_run(entry):
    try:
        log = []
        if os.path.exists(RUN_LOG):
            with open(RUN_LOG, encoding="utf-8") as f:
                log = json.load(f)
        log.append(entry)
        with open(RUN_LOG, "w", encoding="utf-8") as f:
            json.dump(log[-100:], f, indent=2)
    except Exception as e:
        print(f"(could not write {RUN_LOG}: {e})")


def _load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="retrain + judge, but never touch the deployed model")
    ap.add_argument("--min-feedback", type=int, default=1,
                    help="skip when fewer accepted-feedback rows than this")
    ap.add_argument("--min-precision", type=float, default=None,
                    help="hard offline-precision floor for promotion")
    args = ap.parse_args()

    started = datetime.now(timezone.utc).isoformat()
    entry = {"started_at": started, "dry_run": args.dry_run}

    # 1. Retrain a candidate (writes candidate files; exits politely when
    #    there is not enough accepted feedback to learn from).
    import retrain as retrain_mod
    sys.argv = ["retrain", "--min-feedback", str(args.min_feedback)]
    before = os.path.getmtime(CAND_METRICS) if os.path.exists(CAND_METRICS) else 0
    retrain_mod.main()
    after = os.path.getmtime(CAND_METRICS) if os.path.exists(CAND_METRICS) else 0
    if after <= before:
        entry["decision"] = "skipped"
        entry["reason"] = "no new candidate produced (not enough accepted feedback)"
        print(f"\n[scheduled_retrain] {entry['reason']}")
        _log_run(entry)
        return

    # 2. Judge candidate vs deployed with the safety gate.
    ok, reason = should_promote(_load(LIVE_METRICS), _load(CAND_METRICS),
                                min_precision=args.min_precision)
    entry["reason"] = reason

    # 3. Promote only on a pass (and never in dry-run).
    if not ok:
        entry["decision"] = "kept_deployed"
        print(f"\n[scheduled_retrain] NOT promoted: {reason}")
    elif args.dry_run:
        entry["decision"] = "would_promote"
        print(f"\n[scheduled_retrain] DRY RUN — would promote: {reason}")
    else:
        promote()
        entry["decision"] = "promoted"
        print(f"\n[scheduled_retrain] PROMOTED: {reason}")
        print("Restart the backend server to load the new model.")
    _log_run(entry)


if __name__ == "__main__":
    main()
