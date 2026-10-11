"""
Dashboard analytics aggregation (WORK_PLAN Task 4): stacked scan activity,
facet-driven type/brand panels with legacy keyword fallback, and DB-cached
threat origins (no live geo lookups at dashboard time).

Skipped in the slim CI env (fastapi + app deps not installed there).
"""

from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

main = pytest.importorskip("main")


def _row(verdict, days_ago=0, threat_types="", brand="", geo_country="",
         summary="", target=""):
    return SimpleNamespace(
        verdict=verdict,
        created_at=datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days_ago),
        threat_types=threat_types,
        brand=brand,
        geo_country=geo_country,
        summary=summary,
        target=target,
    )


def _day_keys(days=7):
    today = datetime.now(timezone.utc).replace(tzinfo=None).date()
    return [today - timedelta(days=i) for i in range(days - 1, -1, -1)]


def test_scan_activity_is_stacked_per_day_for_all_verdicts():
    rows = [
        _row("SAFE"), _row("SAFE"), _row("SUSPICIOUS"), _row("MALICIOUS"),
        _row("SAFE", days_ago=1),
    ]
    agg = main._aggregate_analytics(rows, _day_keys())
    today_bucket = agg["scan_activity"][-1]
    yesterday_bucket = agg["scan_activity"][-2]
    assert today_bucket["safe"] == 2
    assert today_bucket["suspicious"] == 1
    assert today_bucket["malicious"] == 1
    assert yesterday_bucket["safe"] == 1
    # safe-only days still show activity — useful even when nothing is flagged
    assert len(agg["scan_activity"]) == 7


def test_threat_types_and_brands_come_from_stored_facets():
    rows = [
        _row("MALICIOUS", threat_types="Typosquatting,Phishing (blocklisted)", brand="Paypal"),
        _row("SUSPICIOUS", threat_types="Sender impersonation", brand="Icici"),
        _row("SAFE", threat_types="", brand=""),  # safe rows contribute nothing
    ]
    agg = main._aggregate_analytics(rows, _day_keys())
    types = {t["type"]: t["count"] for t in agg["top_threat_types"]}
    brands = {b["brand"]: b["count"] for b in agg["top_targeted_brands"]}
    assert types["Typosquatting"] == 1
    assert types["Sender impersonation"] == 1
    assert brands == {"Paypal": 1, "Icici": 1}


def test_legacy_rows_fall_back_to_keyword_rules():
    rows = [_row("MALICIOUS", summary="Phishing detected on this page",
                 target="http://paypal-login.evil")]
    agg = main._aggregate_analytics(rows, _day_keys())
    assert len(agg["top_threat_types"]) >= 1   # keyword fallback still fills the panel


def test_threat_geo_comes_from_stored_countries_only():
    rows = [
        _row("MALICIOUS", threat_types="Malware", geo_country="Russia"),
        _row("MALICIOUS", threat_types="Malware", geo_country="Russia"),
        _row("SUSPICIOUS", threat_types="Suspicious content", geo_country="Atlantis"),
        _row("MALICIOUS", threat_types="Malware", geo_country=""),  # unresolved: skipped
    ]
    agg = main._aggregate_analytics(rows, _day_keys())
    geo = {g["country"]: g for g in agg["threat_geo"]}
    assert geo["Russia"]["count"] == 2
    assert geo["Russia"]["lat"] is not None          # known centroid
    assert geo["Atlantis"]["lat"] is None            # listed, but no map point
    assert "" not in geo                             # honest: no fake rows


def test_no_threats_means_empty_panels_not_fake_data():
    rows = [_row("SAFE"), _row("SAFE")]
    agg = main._aggregate_analytics(rows, _day_keys())
    assert agg["top_threat_types"] == []
    assert agg["top_targeted_brands"] == []
    assert agg["threat_geo"] == []
