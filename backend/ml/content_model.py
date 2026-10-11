"""
Content-signal phishing model (NEXT_PHASE_PLAN M2).

A second, page-level model beside the lexical URL model: it turns the
STRUCTURED page features that apis/page_content.py extracts from fetched HTML
(credential forms, cross-domain form posts, brand/title mismatch, obfuscation
signals, external-resource fan-out …) into a calibrated phishing probability
for the fusion blend — so the ML "sees the page", not just the URL string.

v1 is a hand-calibrated logistic model (an expert prior over the known
phishing-kit footprint), validated against the REAL-WORLD eval
(python -m eval.realworld_eval) rather than the small offline URL dataset —
per the plan's rule that every ML change is judged on live results. The
verdict-feedback loop (M3) will accumulate labeled page-feature rows so a
trained replacement can drop in later without changing this interface.

Fusion contract (mirrors reputation's "only an active hit votes"):
  * page not fetched / no dict  -> None  (no opinion, channel absent)
  * bland page (p < CONTENT_ACTIVE_PROB) -> probability is REPORTED but the
    aggregator keeps the channel neutral — static parsing cannot execute
    JavaScript, so "nothing visible" must never exonerate URL evidence
    (kits serve empty shells to scanners).

Leaf module: stdlib-only, fail-safe.
"""
import math

# Below this probability the content channel casts NO vote in the blend.
CONTENT_ACTIVE_PROB = 0.5

# Logistic coefficients (log-odds). Bias anchors a clean page at ~0.03;
# weights are the kit footprint: cross-domain credential POST and brand
# impersonation dominate, structural oddities corroborate.
_BIAS = -3.6
_WEIGHTS = {
    "has_password_field": 1.1,
    "has_login_form": 0.7,
    "external_form_action": 2.2,
    "brand_mismatch": 1.6,
    "title_brand_mismatch": 0.9,
    "favicon_brand_mismatch": 0.7,
    "js_redirect": 0.5,
    "login_keywords_near_form": 1.0,
}
# Interactions — the classic kit combinations say more than their parts.
_W_PASSWORD_AND_BRAND = 1.2      # password form on a page claiming another brand
_W_PASSWORD_AND_EXTERNAL = 1.0   # password form posting cross-domain
# Weak, capped corroborators.
_W_PER_SIGNAL = 0.25             # each distinct suspicious_signals entry
_MAX_SIGNALS = 6
_W_RESOURCE_FANOUT = 0.8         # external sub-resource fan-out, saturates at 10
_RESOURCE_SATURATION = 10


def _sigmoid(z: float) -> float:
    return 1.0 / (1.0 + math.exp(-z))


def content_phishing_probability(content) -> float | None:
    """
    Phishing probability in [0,1] from a page_content feature dict, or None
    when there is no fetched page to judge. Never raises; malformed fields
    count as absent.
    """
    if not isinstance(content, dict) or not content.get("fetched"):
        return None
    try:
        z = _BIAS
        for name, w in _WEIGHTS.items():
            if content.get(name):
                z += w

        if content.get("has_password_field"):
            if content.get("brand_mismatch") or content.get("title_brand_mismatch"):
                z += _W_PASSWORD_AND_BRAND
            if content.get("external_form_action"):
                z += _W_PASSWORD_AND_EXTERNAL

        signals = content.get("suspicious_signals") or []
        if isinstance(signals, (list, tuple)):
            z += _W_PER_SIGNAL * min(len(signals), _MAX_SIGNALS)

        try:
            fanout = int(content.get("external_resource_count") or 0)
        except (TypeError, ValueError):
            fanout = 0
        z += _W_RESOURCE_FANOUT * min(max(fanout, 0), _RESOURCE_SATURATION) / _RESOURCE_SATURATION

        return round(_sigmoid(z), 4)
    except Exception:
        return None
