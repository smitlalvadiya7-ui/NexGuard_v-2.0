"""
M4 — challenger URL model (char-level TF-IDF + logistic regression) vs the
deployed tree ensemble. These tests pin the honest comparison decision and
the predict-path support for raw-URL models (input_mode="raw_url"), so a
winning challenger could drive the REAL pipeline via NEXGUARD_MODEL_PATH.
"""

import importlib

import pytest

pytest.importorskip("sklearn")
import ml.train_char_model as tcm  # noqa: E402


# ---------------------------------------------------------------------------
# decide — the challenger must beat the deployed model, not just tie it
# ---------------------------------------------------------------------------

def test_challenger_wins_on_clear_improvement():
    win, reason = tcm.decide(
        {"roc_auc": 0.97, "f1": 0.93}, {"roc_auc": 0.985, "f1": 0.95})
    assert win, reason

def test_deployed_keeps_on_auc_tie_or_loss():
    win, _ = tcm.decide({"roc_auc": 0.98, "f1": 0.93}, {"roc_auc": 0.98, "f1": 0.99})
    assert not win
    win, _ = tcm.decide({"roc_auc": 0.98, "f1": 0.93}, {"roc_auc": 0.90, "f1": 0.99})
    assert not win

def test_deployed_keeps_when_f1_regresses():
    win, reason = tcm.decide(
        {"roc_auc": 0.97, "f1": 0.95}, {"roc_auc": 0.99, "f1": 0.90})
    assert not win
    assert "f1" in reason.lower()

def test_decide_fails_safe_on_missing_numbers():
    win, _ = tcm.decide({}, {"roc_auc": 0.99, "f1": 0.99})
    assert not win


# ---------------------------------------------------------------------------
# predict.py — raw-URL bundles drive the same predict function
# ---------------------------------------------------------------------------

def _tiny_char_bundle(tmp_path):
    import joblib
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 3))),
        ("clf", LogisticRegression()),
    ])
    pipe.fit(
        ["https://github.com", "https://google.com",
         "http://paypal-verify.top/login", "http://secure-bank.xyz/otp"],
        [0, 0, 1, 1],
    )
    path = tmp_path / "char_model.joblib"
    joblib.dump({"model": pipe, "features": [], "name": "char_tfidf_logreg",
                 "input_mode": "raw_url"}, path)
    return path


def test_predict_supports_raw_url_bundles(tmp_path, monkeypatch):
    path = _tiny_char_bundle(tmp_path)
    monkeypatch.setenv("NEXGUARD_MODEL_PATH", str(path))
    import ml.predict as predict
    reloaded = importlib.reload(predict)
    try:
        p = reloaded.ml_phishing_probability("http://paypal-verify.top/login")
        assert p is not None and 0.0 <= p <= 1.0
    finally:
        monkeypatch.delenv("NEXGUARD_MODEL_PATH")
        importlib.reload(predict)   # restore the deployed model


def test_model_info_reports_vocab_size_for_raw_url_bundles(tmp_path, monkeypatch):
    # the startup log must not read "0 features" for the char champion
    import joblib
    path = _tiny_char_bundle(tmp_path)
    monkeypatch.setenv("NEXGUARD_MODEL_PATH", str(path))
    import ml.predict as predict
    reloaded = importlib.reload(predict)
    try:
        vocab = joblib.load(path)["model"].named_steps["tfidf"].vocabulary_
        assert reloaded.model_info()["n_features"] == len(vocab) > 0
    finally:
        monkeypatch.delenv("NEXGUARD_MODEL_PATH")
        importlib.reload(predict)


# ---------------------------------------------------------------------------
# explain.py — raw-URL bundles get honest per-substring explanations, so
# promoting the char challenger never blanks the "Why this verdict" section
# ---------------------------------------------------------------------------

def _reload_ml(monkeypatch, model_path):
    monkeypatch.setenv("NEXGUARD_MODEL_PATH", str(model_path))
    import ml.predict as predict
    import ml.explain as explain
    importlib.reload(predict)
    return importlib.reload(explain), predict


def _restore_ml(monkeypatch):
    monkeypatch.delenv("NEXGUARD_MODEL_PATH", raising=False)
    import ml.predict as predict
    import ml.explain as explain
    importlib.reload(predict)
    importlib.reload(explain)


def test_explain_supports_raw_url_bundles(tmp_path, monkeypatch):
    path = _tiny_char_bundle(tmp_path)
    explain, _ = _reload_ml(monkeypatch, path)
    try:
        url = "http://paypal-verify.top/login"
        out = explain.explain_url(url, top_n=5)
        assert out is not None
        assert out["method"] == "linear"
        assert 0.0 <= out["ml_probability"] <= 1.0
        top = out["top_features"]
        assert 0 < len(top) <= 5
        for item in top:
            # each factor is a real substring of THIS url, shown honestly
            assert item["feature"].startswith("ng_")
            assert isinstance(item["value"], str) and item["value"]
            assert item["value"].lower() in url.lower()
            # plain python float, never np.float64 (clean JSON + clean repr)
            assert type(item["contribution"]) is float
        # risk-pushing factors come FIRST (the UI shows positives only) and
        # descend; safe-ward factors may only trail to fill leftover slots
        contribs = [i["contribution"] for i in top]
        positives = [c for c in contribs if c > 0]
        assert positives, "a phishy URL must surface positive factors"
        assert contribs[:len(positives)] == sorted(positives, reverse=True)
    finally:
        _restore_ml(monkeypatch)


def test_explain_select_top_puts_risk_factors_before_safe_factors():
    # abs-sorting alone would lead with the -0.30/-0.20 safe-ward grams and
    # the UI (positives-only) would show almost nothing — risk factors first
    import ml.explain as explain
    items = [
        {"feature": "ng_a", "value": "a", "contribution": -0.30},
        {"feature": "ng_b", "value": "b", "contribution": 0.05},
        {"feature": "ng_c", "value": "c", "contribution": -0.20},
        {"feature": "ng_d", "value": "d", "contribution": 0.12},
        {"feature": "ng_e", "value": "e", "contribution": 0.0},
    ]
    top = explain._select_top(items, 3)
    assert [i["feature"] for i in top] == ["ng_d", "ng_b", "ng_a"]
    # with enough positives, safe-ward factors don't take slots at all
    top2 = explain._select_top(items, 2)
    assert [i["feature"] for i in top2] == ["ng_d", "ng_b"]


def test_explain_merges_subsumed_grams_of_the_same_direction():
    # ".xyz/", "xyz/", "yz/" are one piece of evidence, not three factors;
    # an opposite-direction subgram stays separate (never netted away)
    import ml.explain as explain
    merged = explain._merge_subsumed({
        ".xyz/": 0.02, "xyz/": 0.03, "yz/": 0.01, "pay": 0.02, "ay": -0.01,
    })
    assert merged[".xyz/"] == pytest.approx(0.06)
    assert "xyz/" not in merged and "yz/" not in merged
    assert merged["pay"] == pytest.approx(0.02)
    assert merged["ay"] == pytest.approx(-0.01)


def test_explain_raw_url_positive_mass_matches_probability(tmp_path, monkeypatch):
    path = _tiny_char_bundle(tmp_path)
    explain, _ = _reload_ml(monkeypatch, path)
    try:
        out = explain.explain_url("http://secure-bank.xyz/otp", top_n=50)
        pos = sum(f["contribution"] for f in out["top_features"]
                  if f["contribution"] > 0)
        # same convention as the tree path: positive mass scales to ~prob
        assert pos == pytest.approx(out["ml_probability"], abs=0.05)
    finally:
        _restore_ml(monkeypatch)


# ---------------------------------------------------------------------------
# promotion — honest metrics.json for the char champion + .prev rollback copy
# ---------------------------------------------------------------------------

def _fitted_tiny_pipe():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    X = ["https://github.com", "https://google.com", "https://wikipedia.org",
         "http://paypal-verify.top/login", "http://secure-bank.xyz/otp",
         "http://apple-id-check.top/verify"]
    y = [0, 0, 0, 1, 1, 1]
    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 3))),
        ("clf", LogisticRegression()),
    ])
    pipe.fit(X, y)
    return pipe, X, y


def test_char_metrics_dict_matches_metrics_json_schema():
    pipe, X, y = _fitted_tiny_pipe()
    prev_models = {"XGBoost": {"accuracy": 0.95, "precision": 0.955,
                               "recall": 0.945, "f1": 0.95, "roc_auc": 0.988}}
    m = tcm.char_metrics_dict(pipe, X, y, n_samples=100, n_phishing=50,
                              prev_models=prev_models)
    assert m["chosen_model"] == "char_tfidf_logreg"
    scores = m["models"]["char_tfidf_logreg"]
    for k in ("accuracy", "precision", "recall", "f1", "roc_auc"):
        assert 0.0 <= scores[k] <= 1.0
    assert m["models"]["XGBoost"] == prev_models["XGBoost"]
    ds = m["dataset"]
    assert ds["n_samples"] == 100 and ds["n_phishing"] == 50
    assert ds["n_legitimate"] == 50 and ds["n_test"] == len(X)
    assert ds["n_features"] == len(pipe.named_steps["tfidf"].vocabulary_)
    cm = m["confusion_matrix"]
    assert cm["tn"] + cm["fp"] + cm["fn"] + cm["tp"] == len(X)
    roc = m["roc_curve"]
    assert len(roc["fpr"]) == len(roc["tpr"]) == len(roc["thresholds"]) > 0
    imps = m["feature_importances"]
    assert imps and all(d["feature"].startswith("ng_") for d in imps)
    vals = [d["importance"] for d in imps]
    assert vals == sorted(vals, reverse=True)


def test_scheduled_retrain_gate_reads_char_metrics():
    # after promotion the M5 gate must still be able to judge future
    # candidates against the char champion
    from ml.scheduled_retrain import final_scores
    pipe, X, y = _fitted_tiny_pipe()
    m = tcm.char_metrics_dict(pipe, X, y, n_samples=100, n_phishing=50,
                              prev_models={})
    scores = final_scores(m)
    assert scores == m["models"]["char_tfidf_logreg"]


def test_promote_char_backs_up_previous_model_and_metrics(tmp_path, monkeypatch):
    cand = tmp_path / "cand.joblib"; cand.write_bytes(b"CANDIDATE")
    live = tmp_path / "live.joblib"; live.write_bytes(b"OLD-MODEL")
    live_metrics = tmp_path / "metrics.json"
    live_metrics.write_text('{"chosen_model": "XGBoost"}', encoding="utf-8")
    prev = tmp_path / "prev.joblib"
    prev_metrics = tmp_path / "metrics.prev.json"
    monkeypatch.setattr(tcm, "CAND_PATH", str(cand))
    monkeypatch.setattr(tcm, "LIVE_MODEL", str(live))
    monkeypatch.setattr(tcm, "LIVE_METRICS", str(live_metrics))
    monkeypatch.setattr(tcm, "PREV_MODEL", str(prev))
    monkeypatch.setattr(tcm, "PREV_METRICS", str(prev_metrics))

    tcm.promote_char({"chosen_model": "char_tfidf_logreg"})

    assert live.read_bytes() == b"CANDIDATE"
    assert prev.read_bytes() == b"OLD-MODEL"
    assert prev_metrics.read_text(encoding="utf-8") == '{"chosen_model": "XGBoost"}'
    import json as _json
    assert _json.loads(live_metrics.read_text(encoding="utf-8"))["chosen_model"] == "char_tfidf_logreg"


def test_explain_raw_url_dedupes_grams(tmp_path, monkeypatch):
    path = _tiny_char_bundle(tmp_path)
    explain, _ = _reload_ml(monkeypatch, path)
    try:
        out = explain.explain_url("http://paypal-verify.top/login", top_n=10)
        values = [f["value"] for f in out["top_features"]]
        assert len(values) == len(set(values))
    finally:
        _restore_ml(monkeypatch)
