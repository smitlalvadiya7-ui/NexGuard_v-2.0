"""
M5 — scheduled retrain with a safety gate. The weekly job retrains a
candidate (ml/retrain.py) and promotes it over the deployed model ONLY when
the gate passes: no ROC-AUC regression, precision within slack, and an
optional hard precision floor. These tests pin the gate and the promote
file-swap; the actual training run is exercised by the retrain module.
"""

import json

import pytest

pytest.importorskip("pandas")
import ml.scheduled_retrain as sr  # noqa: E402


def _metrics(auc, precision):
    return {
        "chosen_model": "xgboost",
        "models": {"xgboost": {"roc_auc": auc, "precision": precision}},
        "calibration": {
            "chosen_calibrated_metrics": {"roc_auc": auc, "precision": precision},
        },
    }


# ---------------------------------------------------------------------------
# final_scores — reads the calibrated final numbers, falls back safely
# ---------------------------------------------------------------------------

def test_final_scores_prefers_calibrated():
    m = _metrics(0.99, 0.95)
    m["models"]["xgboost"] = {"roc_auc": 0.90, "precision": 0.80}   # uncalibrated
    assert sr.final_scores(m)["roc_auc"] == 0.99

def test_final_scores_falls_back_to_selection_scores():
    m = _metrics(0.99, 0.95)
    del m["calibration"]
    assert sr.final_scores(m)["roc_auc"] == 0.99

def test_final_scores_handles_junk():
    assert sr.final_scores(None) == {}
    assert sr.final_scores({}) == {}


# ---------------------------------------------------------------------------
# should_promote — the safety gate
# ---------------------------------------------------------------------------

def test_promotes_a_clear_improvement():
    ok, reason = sr.should_promote(_metrics(0.97, 0.92), _metrics(0.98, 0.94))
    assert ok, reason

def test_blocks_auc_regression():
    ok, reason = sr.should_promote(_metrics(0.98, 0.92), _metrics(0.97, 0.94))
    assert not ok
    assert "roc" in reason.lower()

def test_blocks_precision_drop_beyond_slack():
    ok, reason = sr.should_promote(_metrics(0.97, 0.95), _metrics(0.98, 0.90))
    assert not ok
    assert "precision" in reason.lower()

def test_allows_precision_within_slack():
    ok, _ = sr.should_promote(_metrics(0.97, 0.940), _metrics(0.97, 0.936))
    assert ok

def test_min_precision_floor():
    ok, reason = sr.should_promote(
        _metrics(0.90, 0.80), _metrics(0.95, 0.85), min_precision=0.90)
    assert not ok
    assert "floor" in reason.lower()

def test_fails_safe_on_missing_metrics():
    ok, _ = sr.should_promote({}, _metrics(0.99, 0.99))
    assert not ok
    ok, _ = sr.should_promote(_metrics(0.9, 0.9), {})
    assert not ok


# ---------------------------------------------------------------------------
# promote — file swap with backup of the previous deployed model
# ---------------------------------------------------------------------------

def test_promote_swaps_files_and_keeps_backup(tmp_path, monkeypatch):
    cand_model = tmp_path / "phishing_model.candidate.joblib"
    cand_metrics = tmp_path / "metrics.candidate.json"
    live_model = tmp_path / "phishing_model.joblib"
    live_metrics = tmp_path / "metrics.json"
    cand_model.write_bytes(b"NEW-MODEL")
    cand_metrics.write_text(json.dumps({"v": "new"}))
    live_model.write_bytes(b"OLD-MODEL")
    live_metrics.write_text(json.dumps({"v": "old"}))

    monkeypatch.setattr(sr, "CAND_MODEL", str(cand_model))
    monkeypatch.setattr(sr, "CAND_METRICS", str(cand_metrics))
    monkeypatch.setattr(sr, "LIVE_MODEL", str(live_model))
    monkeypatch.setattr(sr, "LIVE_METRICS", str(live_metrics))
    monkeypatch.setattr(sr, "PREV_MODEL", str(tmp_path / "phishing_model.prev.joblib"))
    monkeypatch.setattr(sr, "PREV_METRICS", str(tmp_path / "metrics.prev.json"))

    sr.promote()

    assert live_model.read_bytes() == b"NEW-MODEL"
    assert json.loads(live_metrics.read_text())["v"] == "new"
    assert (tmp_path / "phishing_model.prev.joblib").read_bytes() == b"OLD-MODEL"
    assert json.loads((tmp_path / "metrics.prev.json").read_text())["v"] == "old"
