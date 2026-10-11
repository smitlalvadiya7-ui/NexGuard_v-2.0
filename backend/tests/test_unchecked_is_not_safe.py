"""
A URL that was never checked must not be reported as SAFE.

The report that forced this, 2026-07-30. A 200-URL batch of KNOWN-malicious
domains produced:

    Malicious   65
    Suspicious  10
    Safe       125

and page 1 of the PDF lists `https://vivek.howtowpguide.info  SAFE  0%`. Scanned
on its own, minutes later, the same domain came back MALICIOUS 100 with both
VirusTotal and Safe Browsing flagging it.

Nothing was wrong with the verdict logic. VirusTotal's free tier allows 4
requests per minute; the batch runs 8 concurrent scans, so it fired roughly 240
VT requests in the first minute, collected HTTP 429s, tripped the circuit
breaker, and every scan after that ran with no reputation source at all.

The dangerous part is not the missed detection — it is the word SAFE. "0%" on a
row that was never checked is worse than an error, because a user acts on it.
This is a scanner telling somebody a phishing page is fine.

So: when a scan had no reputation coverage and found nothing locally, the verdict
is UNKNOWN, not SAFE. "We could not check this" is the honest answer, and the
one a user can act on correctly.
"""

import asyncio

import pytest

import aggregator as agg


UNAVAILABLE = {"status": "unavailable", "detail": "unavailable"}
CLEAN = {"status": "clean", "detail": "not listed"}


def scan_with(monkeypatch, *, vt, gsb, urlhaus, feeds, content=None, url=None):
    """Drive the real full_scan with reputation sources in a chosen state."""
    monkeypatch.setattr(agg, "_resolve_chain",
                        lambda u, **kw: {"chain": [u], "final": u, "loop": False,
                                         "truncated": False, "html": None,
                                         "blocked_scheme": False})
    monkeypatch.setattr(agg, "_resolve_ip", lambda d: "203.0.113.10")
    monkeypatch.setattr(agg, "check_virustotal",
                        lambda u: {**vt, "raw_positives": vt.get("raw_positives", 0)})

    async def _a(value):
        return dict(value)

    monkeypatch.setattr(agg, "check_safe_browsing", lambda u: _a(gsb))
    monkeypatch.setattr(agg, "check_web_risk", lambda u: _a(gsb))
    monkeypatch.setattr(agg, "check_urlhaus", lambda u: _a(urlhaus))
    monkeypatch.setattr(agg, "check_phish_feeds", lambda u: _a(feeds))
    monkeypatch.setattr(agg, "check_geo", lambda d: _a(agg._FB_GEO))
    monkeypatch.setattr(agg, "check_ssl_cert", lambda d: _a(agg._FB_SSL))
    monkeypatch.setattr(agg, "check_urlscan", lambda u: _a(agg._FB_URLSCAN))
    monkeypatch.setattr(agg, "check_whois", lambda d: _a(agg._FB_WHOIS))
    monkeypatch.setattr(agg, "analyze_page_content",
                        lambda u, html=None: content or dict(agg._FB_CONTENT))
    monkeypatch.setattr(agg, "_explain_url", lambda u, top_n=5: None)
    monkeypatch.setattr(agg, "cache_get", lambda k: None)
    monkeypatch.setattr(agg, "cache_put", lambda k, v, ttl=None: None)
    return asyncio.run(agg.full_scan(url or "https://ordinary-looking.example/"))


# ---------------------------------------------------------------------------
# The verdict
# ---------------------------------------------------------------------------

class TestUncheckedVerdict:
    def test_no_reputation_coverage_gives_unknown_not_safe(self, monkeypatch):
        """The exact row from the report: nothing checked it, so it is not SAFE."""
        r = scan_with(monkeypatch, vt=UNAVAILABLE, gsb=UNAVAILABLE,
                      urlhaus=UNAVAILABLE, feeds={**UNAVAILABLE, "match": None})
        assert r["verdict"] == "UNKNOWN", (
            f"a URL nothing could check must not read as SAFE; got {r['verdict']}")

    def test_checked_and_clean_is_still_safe(self, monkeypatch):
        """The control. A URL three sources actually cleared IS safe."""
        r = scan_with(monkeypatch, vt=CLEAN, gsb=CLEAN, urlhaus=CLEAN,
                      feeds={**CLEAN, "match": None})
        assert r["verdict"] == "SAFE"

    def test_one_source_answering_is_enough_for_safe(self, monkeypatch):
        """Not every source has to answer — one real check is a real check."""
        r = scan_with(monkeypatch, vt=UNAVAILABLE, gsb=CLEAN,
                      urlhaus=UNAVAILABLE, feeds={**UNAVAILABLE, "match": None})
        assert r["verdict"] == "SAFE"

    def test_a_threat_verdict_is_never_downgraded(self, monkeypatch):
        """If something DID flag it, missing sources are irrelevant."""
        r = scan_with(monkeypatch, vt={"status": "flag", "detail": "9/90",
                                      "raw_positives": 9},
                      gsb=UNAVAILABLE, urlhaus=UNAVAILABLE,
                      feeds={**UNAVAILABLE, "match": None})
        assert r["verdict"] == "MALICIOUS"

    def test_local_evidence_still_convicts_without_reputation(self, monkeypatch):
        """UNKNOWN is for 'no evidence either way', not 'no reputation'. Real
        local evidence must still be able to flag a page."""
        kit = dict(agg._FB_CONTENT)
        kit.update(fetched=True, has_password_field=True, has_login_form=True,
                   external_form_action=True, brand_mismatch=True, content_risk=85)
        r = scan_with(monkeypatch, vt=UNAVAILABLE, gsb=UNAVAILABLE,
                      urlhaus=UNAVAILABLE, feeds={**UNAVAILABLE, "match": None},
                      content=kit)
        assert r["verdict"] == "MALICIOUS"


# ---------------------------------------------------------------------------
# What the user is told
# ---------------------------------------------------------------------------

class TestDisclosure:
    def test_unknown_says_why(self, monkeypatch):
        r = scan_with(monkeypatch, vt=UNAVAILABLE, gsb=UNAVAILABLE,
                      urlhaus=UNAVAILABLE, feeds={**UNAVAILABLE, "match": None})
        blob = " ".join(r["flags"]).lower()
        assert "could not be checked" in blob or "incomplete" in blob

    def test_unknown_is_not_scored_as_a_threat(self, monkeypatch):
        """UNKNOWN means 'no information', so it must not carry an alarming
        score that a UI would colour red."""
        r = scan_with(monkeypatch, vt=UNAVAILABLE, gsb=UNAVAILABLE,
                      urlhaus=UNAVAILABLE, feeds={**UNAVAILABLE, "match": None})
        assert r["risk_score"] < agg.SUSPICIOUS_MIN

    def test_intel_fields_still_describe_the_gap(self, monkeypatch):
        r = scan_with(monkeypatch, vt=UNAVAILABLE, gsb=UNAVAILABLE,
                      urlhaus=UNAVAILABLE, feeds={**UNAVAILABLE, "match": None})
        assert r["intel_complete"] is False
        assert r["intel_unavailable"]


# ---------------------------------------------------------------------------
# Callers that classify verdicts
# ---------------------------------------------------------------------------

class TestThreatClassification:
    @pytest.mark.parametrize("verdict,is_threat", [
        ("MALICIOUS", True),
        ("SUSPICIOUS", True),
        ("SAFE", False),
        ("UNKNOWN", False),
    ])
    def test_unknown_is_not_a_threat_for_the_benchmark(self, verdict, is_threat):
        """
        UNKNOWN must not be counted as a catch. Doing so would inflate recall by
        rewarding the scanner for failing to check — the exact opposite of the
        honesty this whole audit is about.
        """
        from eval.realworld_eval import _is_threat
        assert _is_threat(verdict) is is_threat


# ---------------------------------------------------------------------------
# A narrow source answering "clean" is not coverage either
#
# The first version of the UNKNOWN rule accepted ANY source that answered. The
# local community blocklist always answers — it is an in-memory lookup over ~1.1
# million entries — so it returned "clean" and suppressed UNKNOWN for every URL,
# even while VirusTotal had been rate-limited into silence.
#
# Replaying the user's 200-domain batch with that version: 168 still reported
# SAFE and UNKNOWN fired 0 times. Measured coverage of the narrow sources over
# the same corpora: community blocklist flagged 1 of 60, URLHaus 0 of 180.
#
# So blindness is judged on PRIMARY coverage — VirusTotal and Google (Safe
# Browsing or Web Risk). Those are the sources whose absence actually changes
# the answer.
# ---------------------------------------------------------------------------

class TestOnlyPrimaryCoverageClears:
    def test_a_clean_local_feed_does_not_make_it_safe(self, monkeypatch):
        """The exact defect: the feed answers, so the batch looked 'checked'."""
        r = scan_with(monkeypatch, vt=UNAVAILABLE, gsb=UNAVAILABLE,
                      urlhaus=UNAVAILABLE, feeds={**CLEAN, "match": None})
        assert r["verdict"] == "UNKNOWN", (
            "the community blocklist flagged 1 of 60 known-malicious domains; "
            "its 'clean' cannot stand in for a reputation check")

    def test_clean_urlhaus_does_not_make_it_safe(self, monkeypatch):
        r = scan_with(monkeypatch, vt=UNAVAILABLE, gsb=UNAVAILABLE,
                      urlhaus=CLEAN, feeds={**UNAVAILABLE, "match": None})
        assert r["verdict"] == "UNKNOWN"

    def test_virustotal_answering_clears_it(self, monkeypatch):
        r = scan_with(monkeypatch, vt=CLEAN, gsb=UNAVAILABLE,
                      urlhaus=UNAVAILABLE, feeds={**UNAVAILABLE, "match": None})
        assert r["verdict"] == "SAFE"

    def test_google_answering_clears_it(self, monkeypatch):
        r = scan_with(monkeypatch, vt=UNAVAILABLE, gsb=CLEAN,
                      urlhaus=UNAVAILABLE, feeds={**UNAVAILABLE, "match": None})
        assert r["verdict"] == "SAFE"

    def test_a_narrow_source_FLAGGING_still_convicts(self, monkeypatch):
        """Narrow coverage is not weak evidence — a hit is a hit. Only its
        'clean' is uninformative."""
        r = scan_with(monkeypatch, vt=UNAVAILABLE, gsb=UNAVAILABLE,
                      urlhaus=UNAVAILABLE,
                      feeds={"status": "flag", "detail": "listed", "match": "url"})
        assert r["verdict"] in ("SUSPICIOUS", "MALICIOUS")
