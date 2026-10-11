"""
Scan facets (WORK_PLAN Task 4): threat type / targeted brand / origin country
are derived ONCE at save time from the scan engine's STRUCTURED output
(flags, sources, sender_origin, voice categories, geo) — not from shallow
keyword matches over summary text at dashboard time.
"""

from scan_facets import country_centroid, derive_scan_facets


def test_url_scan_facets_from_structured_signals():
    result = {
        "verdict": "MALICIOUS",
        "ml_probability": 0.97,
        "flags": [
            "Typosquatting: impersonates 'paypal' via edit_distance (85% confidence)",
            "Credential harvesting: password form posts cross-domain while impersonating a brand",
        ],
        "sources": [
            {"name": "Safe Browsing", "status": "flag", "detail": "SOCIAL_ENGINEERING"},
            {"name": "VirusTotal", "status": "clean", "detail": "0 engines"},
        ],
        "ip_country": "Russia",
    }
    f = derive_scan_facets("URL Scanner", result)
    assert "Typosquatting" in f["threat_types"]
    assert "Credential harvesting" in f["threat_types"]
    assert "Phishing (blocklisted)" in f["threat_types"]
    assert "Phishing pattern (ML)" in f["threat_types"]
    assert f["brand"] == "Paypal"
    assert f["country"] == "Russia"


def test_safe_scan_has_no_threat_facets():
    f = derive_scan_facets("URL Scanner", {
        "verdict": "SAFE",
        "flags": ["Suspicious keyword: login"],
        "ip_country": "United States",
    })
    assert f["threat_types"] == []
    assert f["brand"] == ""
    assert f["country"] == ""   # only flagged scans feed the origins panel


def test_malware_blocklist_source_maps_to_malware():
    f = derive_scan_facets("URL Scanner", {
        "verdict": "MALICIOUS",
        "flags": [],
        "sources": [{"name": "URLHaus", "status": "flag", "detail": "listed"}],
    })
    assert "Malware" in f["threat_types"]


def test_email_sender_origin_mismatch_facets():
    f = derive_scan_facets("Email Analyzer", {
        "verdict": "MALICIOUS",
        "reasons": ["Claims to be 'icici' but was sent from 'icici-verify.top'..."],
        "sender_origin": {"status": "mismatch", "claimed_brand": "icici"},
    })
    assert "Sender impersonation" in f["threat_types"]
    assert f["brand"] == "Icici"


def test_voice_categories_map_to_labels():
    f = derive_scan_facets("Voice Analyzer", {
        "verdict": "SUSPICIOUS",
        "reasons": [],
        "categories": ["delivery", "urgency", "lottery"],
    })
    assert "Delivery/customs scam" in f["threat_types"]
    assert "Lottery/prize scam" in f["threat_types"]
    # pressure alone is a tactic, not a threat type
    assert all("urgency" not in t.lower() for t in f["threat_types"])


def test_threat_without_structured_signals_gets_generic_label():
    f = derive_scan_facets("Screenshot OCR", {"verdict": "SUSPICIOUS", "reasons": ["odd"]})
    assert f["threat_types"] == ["Suspicious content"]


def test_country_centroids():
    lat, lng = country_centroid("Russia")
    assert isinstance(lat, float) and isinstance(lng, float)
    assert country_centroid("Nowhereland") is None
