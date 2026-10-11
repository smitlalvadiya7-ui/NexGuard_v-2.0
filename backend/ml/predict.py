"""
Load the trained phishing model once and expose a simple predict function.
Fails gracefully (returns None) if the model file is missing, so the app
keeps working on heuristics alone.
"""
import json
import logging
import os

HERE = os.path.dirname(os.path.abspath(__file__))
# NEXGUARD_MODEL_PATH (M3): lets a SEPARATE process (candidate A/B via
# eval/ab_eval) drive the real pipeline with a candidate model without ever
# touching the deployed file. Read once at import — the server never hot-swaps.
MODEL_PATH = os.getenv("NEXGUARD_MODEL_PATH") or os.path.join(HERE, "phishing_model.joblib")
METRICS_PATH = os.path.join(HERE, "metrics.json")

logger = logging.getLogger("nexguard.ml")

_BUNDLE = None
_LOAD_TRIED = False
_LOAD_ERROR = None


def _load():
    global _BUNDLE, _LOAD_TRIED, _LOAD_ERROR
    if _LOAD_TRIED:
        return _BUNDLE
    _LOAD_TRIED = True
    try:
        import joblib  # noqa: F401  (also surfaces a missing-dependency error)
        import sklearn  # noqa: F401
        import xgboost  # noqa: F401
    except Exception as e:
        _LOAD_ERROR = f"ML dependency import failed: {e}"
        _BUNDLE = None
        return _BUNDLE
    try:
        import joblib
        _BUNDLE = joblib.load(MODEL_PATH)
    except Exception as e:
        _LOAD_ERROR = f"could not load {MODEL_PATH}: {e}"
        _BUNDLE = None
    return _BUNDLE


def ml_phishing_probability(url: str):
    """Return phishing probability in [0,1], or None if the model is unavailable."""
    bundle = _load()
    if not bundle:
        return None
    try:
        from features import extract_features
    except ImportError:
        from .features import extract_features
    try:
        # M4: char-level challenger bundles consume the raw URL string;
        # tree-ensemble bundles consume the engineered feature vector.
        if bundle.get("input_mode") == "raw_url":
            vec = [url]
        else:
            vec = [extract_features(url)]
        proba = bundle["model"].predict_proba(vec)[0][1]
        return float(proba)
    except Exception:
        return None


# Calibration sanity samples: a clean major domain must read low, known
# phishing must read high. Printed at startup so miscalibration is obvious.
_SANITY_SAMPLES = [
    ("https://github.com", "low"),
    ("https://www.google.com", "low"),
    ("http://paypal-secure-login-verify.xyz/account", "high"),
    ("http://testsafebrowsing.appspot.com/s/phishing.html", "high"),
]


def startup_check():
    """
    Load the model at startup. If it is unavailable, log a clear WARNING (never
    run silently on heuristics only). If it loaded, log the model identity and
    print sample phishing probabilities for calibration. Returns model_info().
    """
    bundle = _load()
    if not bundle:
        logger.warning(
            "ML phishing model UNAVAILABLE (%s). Scans will run on heuristics + "
            "reputation ONLY. Ensure joblib/scikit-learn/xgboost are installed and "
            "ml/phishing_model.joblib exists.",
            _LOAD_ERROR or "unknown reason",
        )
        return {"available": False, "error": _LOAD_ERROR}

    info = model_info()
    logger.info(
        "ML phishing model loaded: %s (%s features, dataset=%s).",
        info.get("model"), info.get("n_features"), info.get("dataset_size"),
    )
    lines = []
    for url, expect in _SANITY_SAMPLES:
        p = ml_phishing_probability(url)
        shown = f"{p:.3f}" if p is not None else "  n/a"
        lines.append(f"      {shown}  (expect {expect:>4})  {url}")
    logger.info("ML calibration sample probabilities:\n%s", "\n".join(lines))
    return info


def model_info():
    bundle = _load()
    if not bundle:
        return {"available": False}
    n_features = len(bundle.get("features", []))
    if bundle.get("input_mode") == "raw_url":
        # char-level bundles have no engineered feature list — the honest
        # count is the fitted TF-IDF vocabulary size
        try:
            n_features = len(bundle["model"].named_steps["tfidf"].vocabulary_)
        except Exception:
            pass
    info = {
        "available": True,
        "model": bundle.get("name", "unknown"),
        "n_features": n_features,
        "calibrated": bool(bundle.get("calibrated", False)),
        "calibration_method": bundle.get("calibration_method"),
    }
    # Surface the held-out scores for the chosen model, if metrics.json exists.
    try:
        with open(METRICS_PATH, encoding="utf-8") as f:
            metrics = json.load(f)
        chosen = metrics.get("chosen_model")
        info["metrics"] = (metrics.get("models", {}) or {}).get(chosen)
        info["dataset_size"] = (metrics.get("dataset", {}) or {}).get("n_samples")
        cal = metrics.get("calibration") or {}
        if cal:
            info["brier_before"] = cal.get("brier_before")
            info["brier_after"] = cal.get("brier_after")
    except Exception:
        pass
    return info
