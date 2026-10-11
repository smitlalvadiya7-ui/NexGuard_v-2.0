"""
M3 — active-learning loop. The report → admin-review → retrain flow existed;
these tests pin the three pieces that close it honestly:

  * combine_with_feedback — accepted human labels join the training frame and
    WIN over the base label on a duplicate URL;
  * load_training_urls — the benchmark's training-URL exclusion also covers
    accepted-feedback URLs (they are trained on, so they may never be
    benchmarked), and fails safe when the DB is unreachable;
  * NEXGUARD_MODEL_PATH — a candidate model can drive the real pipeline in a
    separate process without touching the deployed model file.
"""

import importlib
import os

import pytest

pd = pytest.importorskip("pandas")

import ml.retrain as retrain  # noqa: E402
rw = pytest.importorskip("eval.realworld_eval")


# ---------------------------------------------------------------------------
# combine_with_feedback
# ---------------------------------------------------------------------------

BASE = pd.DataFrame(
    [("http://old-phish.top/login", "phishing"),
     ("https://my-site.io/page", "phishing")],       # a false positive…
    columns=["url", "status"],
)


def test_feedback_rows_are_appended():
    fb = [("https://new-report.example/", "legitimate")]
    combined = retrain.combine_with_feedback(BASE, fb)
    assert len(combined) == 3
    assert ("https://new-report.example/", "legitimate") in \
        list(combined.itertuples(index=False, name=None))


def test_human_label_wins_on_duplicate_url():
    # …the admin accepted the user's "this is safe" report: the human label
    # must replace the base row, not sit next to it.
    fb = [("https://my-site.io/page", "legitimate")]
    combined = retrain.combine_with_feedback(BASE, fb)
    rows = list(combined.itertuples(index=False, name=None))
    assert len(combined) == 2
    assert ("https://my-site.io/page", "legitimate") in rows
    assert ("https://my-site.io/page", "phishing") not in rows


def test_empty_feedback_is_identity():
    combined = retrain.combine_with_feedback(BASE, [])
    assert list(combined.itertuples(index=False, name=None)) == \
        list(BASE.itertuples(index=False, name=None))


# ---------------------------------------------------------------------------
# load_training_urls — accepted feedback joins the benchmark exclusion
# ---------------------------------------------------------------------------

def test_training_urls_include_accepted_feedback(tmp_path, monkeypatch):
    csv = tmp_path / "ds.csv"
    csv.write_text("url,status\nhttp://a.top/x,phishing\n", encoding="utf-8")
    monkeypatch.setattr(rw, "accepted_feedback_urls",
                        lambda: {"https://accepted-report.example/"})
    urls = rw.load_training_urls(csv)
    assert urls == {"http://a.top/x", "https://accepted-report.example/"}


def test_training_urls_fail_safe_without_db(tmp_path, monkeypatch):
    csv = tmp_path / "ds.csv"
    csv.write_text("url,status\nhttp://a.top/x,phishing\n", encoding="utf-8")

    def boom():
        raise RuntimeError("no db")
    monkeypatch.setattr(rw, "accepted_feedback_urls", boom)
    assert rw.load_training_urls(csv) == {"http://a.top/x"}


def test_accepted_feedback_urls_fail_safe():
    # Whatever the DB situation in this environment, the helper never raises.
    urls = rw.accepted_feedback_urls()
    assert isinstance(urls, set)


# ---------------------------------------------------------------------------
# NEXGUARD_MODEL_PATH — candidate model without touching the deployed file
# ---------------------------------------------------------------------------

def test_model_path_env_override(monkeypatch):
    import ml.predict as predict
    monkeypatch.setenv("NEXGUARD_MODEL_PATH", r"C:\somewhere\candidate.joblib")
    reloaded = importlib.reload(predict)
    try:
        assert reloaded.MODEL_PATH == r"C:\somewhere\candidate.joblib"
    finally:
        monkeypatch.delenv("NEXGUARD_MODEL_PATH")
        importlib.reload(predict)   # restore the deployed-model default


def test_model_path_defaults_to_deployed(monkeypatch):
    import ml.predict as predict
    monkeypatch.delenv("NEXGUARD_MODEL_PATH", raising=False)
    reloaded = importlib.reload(predict)
    assert reloaded.MODEL_PATH == os.path.join(
        os.path.dirname(reloaded.__file__), "phishing_model.joblib")
