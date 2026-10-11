"""
Per-URL explainability for the NexGuard phishing classifier.

For a single URL this computes how much each lexical feature pushed THIS URL's
phishing probability up or down, and returns a compact top-N "why" list:

    [{"feature": "suspicious_tld", "value": ".xyz", "contribution": 0.18}, ...]

sorted by absolute impact (most influential first).

Two strategies, chosen automatically:

  1. SHAP (preferred) — TreeExplainer over the trained tree model(s).  For the
     soft-voting ensemble the per-feature SHAP values of every tree sub-model
     are averaged.  SHAP values are signed and additive (positive = pushed the
     URL toward "phishing"), which is exactly what we want.

  2. Fallback — global `feature_importances_` combined with THIS URL's feature
     values (activation-weighted, signed by a small risk-direction map and
     scaled to the model's phishing probability).  Used whenever SHAP is not
     installed or fails for the loaded model.

Everything is import-guarded and fails closed (returns None) so a missing model
or missing SHAP never breaks a scan.
"""
import json
import os
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
METRICS_PATH = os.path.join(HERE, "metrics.json")

# Direction each feature pushes the verdict when its value is "elevated".
# +1 => higher value looks more like phishing, -1 => looks safer.
# Used only by the fallback path (SHAP derives direction from the model).
_RISK_SIGN = {
    "length_url": +1, "length_hostname": +1, "has_ip": +1, "nb_dots": +1,
    "nb_hyphens": +1, "nb_at": +1, "nb_qm": +1, "nb_and": +1, "nb_eq": +1,
    "nb_underscore": +1, "nb_slash": +1, "nb_digits": +1, "ratio_digits_url": +1,
    "ratio_digits_host": +1, "nb_subdomains": +1, "prefix_suffix": +1,
    "has_https": -1, "is_shortener": +1, "suspicious_tld": +1,
    "domain_entropy": +1, "nb_phish_hints": +1, "brand_in_subdomain_or_path": +1,
    "longest_word_host": +1, "tld_in_path": +1,
}

# Rough scale used to squash unbounded count/length features into ~[0,1] for the
# fallback activation. Binary/ratio features fall through to the default.
_SCALE = {
    "length_url": 75, "length_hostname": 30, "nb_dots": 4, "nb_hyphens": 3,
    "nb_qm": 2, "nb_and": 3, "nb_eq": 3, "nb_underscore": 3, "nb_slash": 5,
    "nb_digits": 8, "nb_subdomains": 3, "domain_entropy": 4,
    "nb_phish_hints": 3, "longest_word_host": 20, "nb_at": 1,
}


def _imports():
    """Return (extract_features, FEATURE_NAMES, SUSPICIOUS_TLDS, SHORTENERS)."""
    try:
        from features import extract_features, FEATURE_NAMES, SUSPICIOUS_TLDS, SHORTENERS
    except ImportError:
        from .features import extract_features, FEATURE_NAMES, SUSPICIOUS_TLDS, SHORTENERS
    return extract_features, FEATURE_NAMES, SUSPICIOUS_TLDS, SHORTENERS


def _host(url: str) -> str:
    url = (url or "").strip()
    if url and not url.startswith(("http://", "https://")) and "." in url:
        url = "http://" + url
    h = (urlparse(url).netloc or "").split("@")[-1].split(":")[0].lower()
    return h[4:] if h.startswith("www.") else h


def _format_value(name, numeric, url, suspicious_tlds, shorteners):
    """Human-readable display of the feature's value for THIS URL."""
    host = _host(url)
    if name == "suspicious_tld":
        for t in suspicious_tlds:
            if host.endswith(t):
                return t
        return "none"
    if name == "has_https":
        return "https" if numeric else "http (no TLS)"
    if name == "is_shortener":
        return host if numeric else "no"
    if name in ("has_ip", "prefix_suffix", "brand_in_subdomain_or_path", "tld_in_path"):
        return "yes" if numeric else "no"
    if name in ("ratio_digits_url", "ratio_digits_host", "domain_entropy"):
        return round(float(numeric), 3)
    # plain counts / lengths
    try:
        return int(numeric)
    except Exception:
        return numeric


# ---------------------------------------------------------------------------
# SHAP path
# ---------------------------------------------------------------------------

def _positive_class_shap(sv, n_features):
    """Normalise the many possible SHAP output shapes to a 1-D (n_features,) array."""
    import numpy as np
    # list/tuple -> one array per class; take the phishing class (last)
    if isinstance(sv, (list, tuple)):
        sv = sv[-1]
    arr = np.asarray(sv, dtype=float)
    # squeeze a leading sample axis of length 1
    if arr.ndim == 3:            # (samples, features, classes)
        arr = arr[0, :, -1]
    elif arr.ndim == 2:
        if arr.shape == (1, n_features):      # (samples, features)
            arr = arr[0]
        elif arr.shape[0] == n_features:      # (features, classes)
            arr = arr[:, -1]
        else:
            arr = arr[0]
    return np.asarray(arr, dtype=float).reshape(-1)[:n_features]


def _shap_contributions(model, vec, n_features):
    """Average per-feature SHAP values across every tree sub-model. None on failure."""
    import numpy as np
    import shap

    estimators = list(model.named_estimators_.values()) if hasattr(model, "named_estimators_") else [model]
    total = np.zeros(n_features, dtype=float)
    used = 0
    for est in estimators:
        try:
            explainer = shap.TreeExplainer(est)
            sv = explainer.shap_values(vec, check_additivity=False)
            total += _positive_class_shap(sv, n_features)
            used += 1
        except Exception:
            continue
    if not used:
        return None
    return total / used


# ---------------------------------------------------------------------------
# Fallback path: feature_importances_ x activation, signed
# ---------------------------------------------------------------------------

def _load_importances(model, feature_names):
    """Importances aligned to feature_names. Prefers the model, then metrics.json."""
    try:
        import numpy as np
        if hasattr(model, "feature_importances_"):
            return list(np.asarray(model.feature_importances_, dtype=float))
        if hasattr(model, "named_estimators_"):
            mats = [np.asarray(e.feature_importances_, dtype=float)
                    for e in model.named_estimators_.values()
                    if hasattr(e, "feature_importances_")]
            if mats:
                mats = [m / m.sum() if m.sum() else m for m in mats]
                return list(np.mean(mats, axis=0))
    except Exception:
        pass
    # metrics.json fallback
    try:
        with open(METRICS_PATH, encoding="utf-8") as f:
            imp = {d["feature"]: d["importance"] for d in json.load(f).get("feature_importances", [])}
        return [float(imp.get(n, 0.0)) for n in feature_names]
    except Exception:
        return [0.0] * len(feature_names)


def _activation(name, numeric):
    """Squash THIS URL's feature value to ~[0,1] for the fallback weighting."""
    v = float(numeric or 0)
    if name in ("ratio_digits_url", "ratio_digits_host"):
        return max(0.0, min(1.0, v))
    scale = _SCALE.get(name)
    if scale:
        return v / (v + scale)          # diminishing returns, in (0,1)
    return 1.0 if v else 0.0            # binary flags


def _fallback_contributions(model, feature_names, vector, prob):
    """importance x activation, signed by _RISK_SIGN, scaled toward `prob`."""
    importances = _load_importances(model, feature_names)
    raw = []
    for name, imp, val in zip(feature_names, importances, vector):
        act = _activation(name, val)
        raw.append(_RISK_SIGN.get(name, 1) * float(imp) * act)
    pos = sum(r for r in raw if r > 0)
    # Scale positive mass to the model's phishing probability so numbers read
    # like probability contributions (e.g. +0.18). Negatives scale to match.
    factor = (prob / pos) if (pos and prob) else 1.0
    return [round(r * factor, 4) for r in raw]


# ---------------------------------------------------------------------------
# Raw-URL (char-level) path: TF-IDF value x logistic coefficient per n-gram
# ---------------------------------------------------------------------------

_RAW_NAMES_CACHE = {}


def _raw_feature_names(tfidf):
    key = id(tfidf)
    names = _RAW_NAMES_CACHE.get(key)
    if names is None:
        names = tfidf.get_feature_names_out()
        _RAW_NAMES_CACHE.clear()          # only ever one deployed model
        _RAW_NAMES_CACHE[key] = names
    return names


def _merge_subsumed(per_text):
    """Fold a gram into an already-kept longer gram that contains it when both
    push the same direction — overlapping char n-grams of one substring are one
    piece of evidence. Opposite-direction subgrams stay separate (never netted
    away against evidence they don't share)."""
    merged = {}
    for text in sorted(per_text, key=lambda t: (-len(t), t)):
        c = per_text[text]
        host = next((t for t in merged
                     if text in t and (c > 0) == (merged[t] > 0)), None)
        if host is not None:
            merged[host] += c
        else:
            merged[text] = c
    return merged


def _select_top(items, top_n):
    """Risk-pushing (positive) factors first, strongest first — the web UI
    shows positives only, so they must not lose slots to safe-ward grams.
    Safe-ward factors fill any leftover slots for the PDF report's benefit."""
    pos = sorted((i for i in items if i["contribution"] > 0),
                 key=lambda d: d["contribution"], reverse=True)
    neg = sorted((i for i in items if i["contribution"] < 0),
                 key=lambda d: d["contribution"])
    return (pos + neg)[:top_n]


def _explain_raw_url(bundle, url, prob, top_n):
    """
    For input_mode="raw_url" bundles (char TF-IDF + logistic regression) the
    honest per-URL attribution is: contribution of each character n-gram
    present in THIS url = its TF-IDF weight x the model's coefficient
    (signed, additive in log-odds). Overlapping grams that clean to the same
    visible text are summed, and the positive mass is scaled to the phishing
    probability — the same display convention as the tree path.
    """
    pipe = bundle["model"]
    tfidf = pipe.named_steps["tfidf"]
    clf = pipe.named_steps["clf"]
    import numpy as np
    coef = np.asarray(clf.coef_, dtype=float).reshape(-1)
    vec = tfidf.transform([url]).tocsr()
    names = _raw_feature_names(tfidf)

    per_text = {}
    for i, v in zip(vec.indices, vec.data):
        text = str(names[i]).strip()
        if not text:
            continue
        per_text[text] = per_text.get(text, 0.0) + float(v) * coef[i]

    per_text = _merge_subsumed(per_text)
    pos = sum(c for c in per_text.values() if c > 0)
    factor = (prob / pos) if (pos and prob) else 1.0
    items = [{"feature": f"ng_{text}", "value": text,
              "contribution": float(round(c * factor, 4))}
             for text, c in per_text.items()]
    top = _select_top(items, top_n)

    return {
        "method": "linear",
        "ml_probability": round(float(prob), 4),
        "top_features": top,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def explain_url(url: str, top_n: int = 5):
    """
    Explain a single URL's phishing probability.

    Returns
    -------
    dict | None
        {
          "method": "shap" | "importance",
          "ml_probability": float,
          "top_features": [
             {"feature": str, "value": <display>, "contribution": float}, ...
          ]
        }
        None if the model is unavailable.
    """
    try:
        from predict import _load, ml_phishing_probability
    except ImportError:
        from .predict import _load, ml_phishing_probability

    bundle = _load()
    if not bundle:
        return None

    if bundle.get("input_mode") == "raw_url":
        prob = ml_phishing_probability(url)
        if prob is None:
            return None
        try:
            return _explain_raw_url(bundle, url, prob, top_n)
        except Exception:
            return None

    extract_features, FEATURE_NAMES, SUSPICIOUS_TLDS, SHORTENERS = _imports()
    feature_names = bundle.get("features", FEATURE_NAMES)
    n = len(feature_names)

    try:
        vector = extract_features(url)
    except Exception:
        return None

    prob = ml_phishing_probability(url)
    if prob is None:
        return None

    method = "importance"
    contributions = None
    try:
        import numpy as np  # noqa: F401
        vec = [list(map(float, vector))]
        contributions = _shap_contributions(bundle["model"], vec, n)
        if contributions is not None:
            method = "shap"
    except Exception:
        contributions = None

    if contributions is None:
        contributions = _fallback_contributions(bundle["model"], feature_names, vector, prob)

    # Normalise to probability space so contributions read like the verdict
    # probability (e.g. +0.18). SHAP from XGBoost is in log-odds and RF in
    # probability units; scaling the positive mass to `prob` makes either
    # method comparable and intuitive while preserving rank and sign.
    contributions = list(contributions)
    pos = sum(float(c) for c in contributions if c > 0)
    if pos and prob:
        contributions = [round(float(c) * (prob / pos), 4) for c in contributions]

    items = []
    for name, val, contrib in zip(feature_names, vector, contributions):
        items.append({
            "feature": name,
            "value": _format_value(name, val, url, SUSPICIOUS_TLDS, SHORTENERS),
            "contribution": round(float(contrib), 4),
        })
    # Most influential first; drop exact-zero contributions from the tail.
    items.sort(key=lambda d: abs(d["contribution"]), reverse=True)
    top = [it for it in items if it["contribution"] != 0][:top_n]
    if not top:                      # everything zero — still show the top names
        top = items[:top_n]

    return {
        "method": method,
        "ml_probability": round(float(prob), 4),
        "top_features": top,
    }
