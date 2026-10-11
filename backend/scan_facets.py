"""
Scan facets (WORK_PLAN Task 4): derive threat type / targeted brand / origin
country ONCE at save time from the scan engine's STRUCTURED output — flags,
reputation sources, sender_origin, voice intent categories, resolved geo —
instead of shallow keyword matches over summary text at dashboard time.

Leaf module: stdlib-only, safe for any module to import.
"""
import re

# voice intent category -> dashboard threat-type label. None = a manipulation
# TACTIC (pressure, secrecy), not a threat type of its own.
VOICE_CATEGORY_LABELS = {
    "code_request":     "OTP harvesting",
    "code_mention":     "OTP harvesting",
    "credential":       "Credential harvesting",
    "money":            "Money request",
    "impersonation":    "Caller impersonation",
    "remote_access":    "Remote-access scam",
    "authority_threat": "Authority-threat scam",
    "social_media":     "Social-media scam",
    "delivery":         "Delivery/customs scam",
    "job_offer":        "Job-offer scam",
    "investment":       "Investment scam",
    "lottery":          "Lottery/prize scam",
    "urgency":          None,
    "secrecy":          None,
}

_TYPO_BRAND_RE = re.compile(r"Typosquatting: impersonates '([^']+)'")


def derive_scan_facets(module: str, result: dict) -> dict:
    """Returns {"threat_types": [..], "brand": str, "country": str}.
    Facets are recorded only for flagged scans — a SAFE scan contributes
    nothing to the threat panels."""
    verdict = (result.get("verdict") or "").upper()
    if verdict not in ("SUSPICIOUS", "MALICIOUS"):
        return {"threat_types": [], "brand": "", "country": ""}

    types: list = []
    brand = ""

    flags = [str(f) for f in (result.get("flags") or result.get("reasons") or [])]
    for f in flags:
        if f.startswith("Typosquatting"):
            types.append("Typosquatting")
            if not brand:
                m = _TYPO_BRAND_RE.match(f)
                brand = m.group(1) if m else ""
        if (f.startswith("Credential harvesting")
                or "posts credentials to a different domain" in f):
            types.append("Credential harvesting")
        if f.startswith("Possible impersonation:"):
            types.append("Brand impersonation")
            if not brand:
                brand = f.split(":", 1)[1].strip()
        if f.startswith(("Malicious attachment", "Suspicious attachment")):
            types.append("Malicious attachment")

    for s in (result.get("sources") or []):
        if (s.get("status") or "") != "flag":
            continue
        name = (s.get("name") or "").lower()
        if "urlhaus" in name:
            types.append("Malware")
        elif "virustotal" in name:
            types.append("Flagged by AV engines")
        else:
            types.append("Phishing (blocklisted)")

    ml = result.get("ml_probability")
    if ml is not None and ml >= 0.85:
        types.append("Phishing pattern (ML)")

    origin = result.get("sender_origin") or {}
    if origin.get("status") == "mismatch":
        types.append("Sender impersonation")
        brand = brand or (origin.get("claimed_brand") or "")
    elif origin.get("status") == "spoof_suspected":
        types.append("Spoofed sender")

    for cat in (result.get("categories") or []):
        label = VOICE_CATEGORY_LABELS.get(cat)
        if label:
            types.append(label)

    if not types:
        types.append("Suspicious content")

    seen, deduped = set(), []
    for t in types:
        if t not in seen:
            deduped.append(t)
            seen.add(t)

    ip_location = result.get("ip_location")
    country = (
        result.get("ip_country")
        or (ip_location.get("country") if isinstance(ip_location, dict) else None)
        or ""
    )

    return {
        "threat_types": deduped,
        "brand": brand.title() if brand else "",
        "country": str(country),
    }


# Country centroids for the threat-origins panel — geo is aggregated from the
# country stored per scan (no live lookups at dashboard time). Rough national
# centroids; a country not listed still shows in the list, just without a
# map point.
COUNTRY_CENTROIDS = {
    "United States": (39.8, -98.6), "Russia": (61.5, 105.3), "China": (35.9, 104.2),
    "India": (20.6, 79.0), "Brazil": (-14.2, -51.9), "Germany": (51.2, 10.4),
    "Netherlands": (52.1, 5.3), "France": (46.2, 2.2), "United Kingdom": (55.4, -3.4),
    "Canada": (56.1, -106.3), "Japan": (36.2, 138.3), "South Korea": (35.9, 127.8),
    "Singapore": (1.35, 103.8), "Hong Kong": (22.3, 114.2), "Vietnam": (14.1, 108.3),
    "Indonesia": (-0.8, 113.9), "Thailand": (15.9, 101.0), "Malaysia": (4.2, 102.0),
    "Philippines": (12.9, 121.8), "Pakistan": (30.4, 69.3), "Bangladesh": (23.7, 90.4),
    "Nigeria": (9.1, 8.7), "South Africa": (-30.6, 22.9), "Egypt": (26.8, 30.8),
    "Turkey": (39.0, 35.2), "Iran": (32.4, 53.7), "Ukraine": (48.4, 31.2),
    "Poland": (51.9, 19.1), "Romania": (45.9, 25.0), "Bulgaria": (42.7, 25.5),
    "Czechia": (49.8, 15.5), "Lithuania": (55.2, 23.9), "Moldova": (47.4, 28.4),
    "Spain": (40.5, -3.7), "Italy": (41.9, 12.6), "Portugal": (39.4, -8.2),
    "Mexico": (23.6, -102.6), "Argentina": (-38.4, -63.6), "Colombia": (4.6, -74.1),
    "Australia": (-25.3, 133.8), "New Zealand": (-40.9, 174.9),
    "United Arab Emirates": (23.4, 53.8), "Saudi Arabia": (23.9, 45.1),
    "Israel": (31.0, 34.9), "Switzerland": (46.8, 8.2), "Sweden": (60.1, 18.6),
    "Norway": (60.5, 8.5), "Finland": (61.9, 25.7), "Ireland": (53.4, -8.2),
    "Seychelles": (-4.7, 55.5), "Panama": (8.5, -80.8), "Belize": (17.2, -88.5),
}


def country_centroid(country: str):
    """(lat, lng) for a known country name, else None."""
    return COUNTRY_CENTROIDS.get((country or "").strip())
