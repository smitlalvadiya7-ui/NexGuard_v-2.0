"""
Unit tests for the pure scoring functions in aggregator.py.

These functions take plain dicts/ints and do no I/O, so they are tested
directly — no mocks, no network. They encode the verdict policy:

    >=70 MALICIOUS | 40-69 SUSPICIOUS | <40 SAFE

and the escalation floors documented on _escalate (STRONG reputation -> 90,
two+ confirmed sources -> 100,
WEAK single-engine VT -> 60, corroborated high ML -> 78, uncorroborated -> 69,
high-confidence typosquat -> 70).
"""

import pytest

from aggregator import (
    VT_MIN_ENGINES_FOR_MALICIOUS,
    WEAK_REP_SUSPICIOUS_FLOOR,
    _confidence,
    _domain_from_url,
    _escalate,
    _host_matches,
    _is_reputable_host,
    _is_shared_hosting_tenant,
    _reputation_all_unavailable,
    _reputation_score,
    _verdict,
    _weighted_score,
)


# ---------------------------------------------------------------------------
# Result-dict factories matching the shapes the live API wrappers return.
# ---------------------------------------------------------------------------

def vt(status="clean", positives=0):
    return {"status": status, "detail": "", "raw_positives": positives}


def src(status="clean"):
    return {"status": status, "detail": ""}


def feed(match=None):
    """Community-blocklist result. `match` is "url" for an exact-URL listing
    (a confirmed hit) or "domain" for a bare-host listing (a weaker one)."""
    return {"status": "flag" if match else "clean", "detail": "", "match": match}


# ---------------------------------------------------------------------------
# _reputation_all_unavailable — degraded-scan cache guard
# ---------------------------------------------------------------------------
# A scan whose reputation sources ALL came back "unavailable" (transient outage,
# rate-limit, or cold start) must NOT be frozen into the 1-hour full-scan cache.
# Otherwise the outage keeps being served long after the sources recover, and
# the user sees "all APIs unavailable" even though the APIs work now.

class TestReputationAllUnavailable:
    def _unavail(self):
        return {"status": "clean", "detail": "unavailable"}

    def test_all_unavailable_is_true(self):
        u = self._unavail()
        assert _reputation_all_unavailable(u, u, u) is True

    def test_one_live_source_is_false(self):
        u = self._unavail()
        live = {"status": "flag", "detail": "MALWARE"}
        assert _reputation_all_unavailable(u, live, u) is False

    def test_all_clean_but_definitive_is_false(self):
        # Genuinely clean (source answered "not listed") is definitive — cacheable.
        clean = {"status": "clean", "detail": "not listed"}
        assert _reputation_all_unavailable(clean, clean, clean) is False

    def test_empty_is_false(self):
        assert _reputation_all_unavailable() is False


# ---------------------------------------------------------------------------
# _verdict — band boundaries
# ---------------------------------------------------------------------------

class TestVerdict:
    @pytest.mark.parametrize("score,expected", [
        (0, "SAFE"),
        (39, "SAFE"),
        (40, "SUSPICIOUS"),
        (69, "SUSPICIOUS"),
        (70, "MALICIOUS"),
        (100, "MALICIOUS"),
    ])
    def test_bands(self, score, expected):
        assert _verdict(score) == expected


# ---------------------------------------------------------------------------
# _weighted_score — blend + renormalisation of absent sources
# ---------------------------------------------------------------------------

class TestWeightedScore:
    def test_heuristic_only(self):
        # ML unavailable and reputation inactive -> heuristic passes through.
        assert _weighted_score(40, None, 0, False) == 40

    def test_inactive_reputation_never_drags_score_down(self):
        # rep_score is ignored entirely when rep_active is False.
        assert _weighted_score(80, None, 0, False) == 80

    def test_full_blend(self):
        # ML 0.35 + heuristic 0.25 + reputation 0.40 (weights sum to 1).
        got = _weighted_score(40, 0.60, 80, True)
        assert got == round(0.25 * 40 + 0.35 * 60 + 0.40 * 80)

    def test_ml_plus_heuristic_renormalised(self):
        # Without reputation, ML/heuristic weights renormalise to 35/60, 25/60.
        got = _weighted_score(30, 0.90, 0, False)
        assert got == round((0.25 * 30 + 0.35 * 90) / 0.60)

    def test_clamped_to_0_100(self):
        assert _weighted_score(0, 0.0, 0, False) == 0
        assert _weighted_score(100, 1.0, 100, True) == 100


# ---------------------------------------------------------------------------
# _reputation_score — per-source weights and the `active` flag
# ---------------------------------------------------------------------------

class TestReputationScore:
    def test_all_clean_is_inactive(self):
        score, n, active = _reputation_score(vt(), src(), src())
        assert (score, n, active) == (0, 0, False)

    def test_unavailable_sources_are_neutral(self):
        score, n, active = _reputation_score(
            vt("unavailable"), src("unavailable"), src("unavailable"), feed()
        )
        assert (score, n, active) == (0, 0, False)

    def test_vt_warn_is_an_active_hit(self):
        score, n, active = _reputation_score(vt("warn", 1), src(), src())
        assert (score, n, active) == (20, 1, True)

    def test_vt_flag_weight(self):
        score, n, active = _reputation_score(vt("flag", 5), src(), src())
        assert (score, n, active) == (40, 1, True)

    def test_gsb_and_urlhaus_weights(self):
        assert _reputation_score(vt(), src("flag"), src())[0] == 35
        assert _reputation_score(vt(), src(), src("flag"))[0] == 25

    def test_score_caps_at_100(self):
        score, n, active = _reputation_score(
            vt("flag", 10), src("flag"), src("flag"), feed("url")
        )
        assert (score, n, active) == (100, 4, True)

    def test_feed_url_match_weighs_like_safe_browsing(self):
        # An exact-URL listing on OpenPhish / Phishing.Database is a confirmed hit.
        score, n, active = _reputation_score(vt(), src(), src(), feed("url"))
        assert (score, n, active) == (35, 1, True)

    def test_feed_domain_match_scores_below_a_url_match(self):
        # A bare-host listing is a weaker claim than the exact URL: the feeds
        # list shared platforms and once-compromised legitimate sites, so a
        # host hit must not carry a confirmed-listing weight.
        score, n, active = _reputation_score(vt(), src(), src(), feed("domain"))
        assert (score, n, active) == (20, 1, True)

    def test_feed_clean_and_omitted_are_neutral(self):
        assert _reputation_score(vt(), src(), src(), feed()) == (0, 0, False)
        # Omitted feeds (default None) stay neutral too.
        assert _reputation_score(vt(), src(), src()) == (0, 0, False)


# ---------------------------------------------------------------------------
# _escalate — STRONG/WEAK reputation, ML, and typosquat floors
# ---------------------------------------------------------------------------

class TestEscalate:
    def test_strong_reputation_floors_at_malicious(self):
        score = _escalate(10, True, False, None, 0, 0)
        assert score >= 80
        assert _verdict(score) == "MALICIOUS"

    def test_one_confirmed_source_shows_90(self):
        # User report 2026-07-19: confirmed-risky links stopped at 80 —
        # a confirmed blocklist hit now reads 90, not a hesitant 80.
        assert _escalate(10, 1, False, None, 0, 0) == 90

    def test_two_confirmed_sources_show_full_100(self):
        # Two independent confirmed authorities agreeing = as sure as the
        # engine ever gets — the risk score reads the full 100.
        assert _escalate(10, 2, False, None, 0, 0) == 100
        assert _escalate(10, 4, False, None, 0, 0) == 100

    def test_probability_only_paths_still_never_reach_100(self):
        # ML/heuristics alone stay capped — the FP calibration is untouched.
        assert _escalate(10, 0, False, 0.99, 3, 90) < 80

    def test_weak_reputation_floors_at_suspicious_not_malicious(self):
        # A single-engine VT detection alone must NOT reach MALICIOUS.
        score = _escalate(10, False, True, None, 0, 0)
        assert score == WEAK_REP_SUSPICIOUS_FLOOR
        assert _verdict(score) == "SUSPICIOUS"

    def test_floors_never_lower_a_higher_score(self):
        assert _escalate(95, True, False, None, 0, 0) == 95
        assert _escalate(95, False, True, None, 0, 0) == 95

    def test_high_ml_alone_caps_at_suspicious(self):
        score = _escalate(10, False, False, 0.99, 0, 0)
        assert score == 69
        assert _verdict(score) == "SUSPICIOUS"

    def test_high_ml_with_strong_heuristics_is_malicious(self):
        score = _escalate(10, False, False, 0.90, 1, 0)
        assert score == 78
        assert _verdict(score) == "MALICIOUS"

    def test_ml_below_threshold_does_not_floor(self):
        assert _escalate(10, False, False, 0.84, 3, 0) == 10

    def test_ml_none_does_not_floor(self):
        # The lexical ML is dropped (None) on capped/uncorroborated hosts.
        assert _escalate(10, False, False, None, 3, 0) == 10

    def test_high_confidence_typosquat_floors_at_70(self):
        assert _escalate(10, False, False, None, 0, 80) == 70

    def test_medium_confidence_typosquat_floors_at_55(self):
        assert _escalate(10, False, False, None, 0, 66) == 55

    def test_low_confidence_typosquat_does_not_floor(self):
        assert _escalate(10, False, False, None, 0, 65) == 10

    def test_vt_min_engines_default(self):
        # The STRONG/WEAK split keys off this constant; default is 2 so a
        # 2-engine VT detection escalates to MALICIOUS but 1 engine does not.
        assert VT_MIN_ENGINES_FOR_MALICIOUS == 2


# ---------------------------------------------------------------------------
# STRONG vs WEAK classification (mirrors the full_scan logic)
# ---------------------------------------------------------------------------

def classify_rep(vt_res, gsb_res, uh_res, feed_res=None, hop_blocklisted=False):
    """Reproduces the rep_strong/rep_weak derivation in full_scan."""
    feed_res = feed_res if feed_res is not None else feed()
    _, _, rep_active = _reputation_score(vt_res, gsb_res, uh_res, feed_res)
    if hop_blocklisted:
        rep_active = True
    vt_positives = int(vt_res.get("raw_positives", 0) or 0)
    rep_strong = bool(
        hop_blocklisted
        or vt_positives >= VT_MIN_ENGINES_FOR_MALICIOUS
        or gsb_res.get("status") == "flag"
        or uh_res.get("status") == "flag"
        or (feed_res.get("status") == "flag" and feed_res.get("match") != "domain")
    )
    return rep_strong, rep_active and not rep_strong


class TestStrongWeakClassification:
    def test_single_engine_vt_is_weak(self):
        strong, weak = classify_rep(vt("warn", 1), src(), src())
        assert (strong, weak) == (False, True)

    def test_two_engine_vt_is_strong(self):
        strong, weak = classify_rep(vt("warn", 2), src(), src())
        assert (strong, weak) == (True, False)

    def test_confirmed_blocklists_are_strong(self):
        assert classify_rep(vt(), src("flag"), src()) == (True, False)
        assert classify_rep(vt(), src(), src("flag")) == (True, False)
        assert classify_rep(vt(), src(), src(), feed("url")) == (True, False)

    def test_domain_only_feed_hit_is_weak_not_strong(self):
        # A bare-host listing is active reputation, but not a conviction.
        assert classify_rep(vt(), src(), src(), feed("domain")) == (False, True)

    def test_blocklisted_redirect_hop_is_strong(self):
        strong, weak = classify_rep(vt(), src(), src(), hop_blocklisted=True)
        assert (strong, weak) == (True, False)

    def test_all_clean_is_neither(self):
        strong, weak = classify_rep(vt(), src(), src())
        assert (strong, weak) == (False, False)

    def test_single_engine_vt_end_to_end_verdict_is_suspicious(self):
        # Full path: blend then escalate — a lone AV engine yields SUSPICIOUS.
        vt_res = vt("warn", 1)
        rep_score, _, rep_active = _reputation_score(vt_res, src(), src())
        strong, weak = classify_rep(vt_res, src(), src())
        blended = _weighted_score(10, None, rep_score, rep_active)
        final = _escalate(blended, strong, weak, None, 0, 0)
        assert _verdict(final) == "SUSPICIOUS"

    def test_domain_only_feed_hit_end_to_end_verdict_is_suspicious(self):
        feed_res = feed("domain")
        rep_score, _, rep_active = _reputation_score(vt(), src(), src(), feed_res)
        strong, weak = classify_rep(vt(), src(), src(), feed_res)
        blended = _weighted_score(10, None, rep_score, rep_active)
        final = _escalate(blended, strong, weak, None, 0, 0)
        assert _verdict(final) == "SUSPICIOUS"


# ---------------------------------------------------------------------------
# _confidence — agreement across the signals that actually voted
# ---------------------------------------------------------------------------

class TestConfidence:
    def test_feed_hit_votes_with_the_threat_verdict(self):
        # The community blocklist is a reputation source: when it actively
        # flags, it must count as agreement, or a feed-only conviction reads
        # back as low confidence.
        quiet = _confidence(0, 0.1, vt(), src(), src(), feed(), "MALICIOUS")
        flagged = _confidence(0, 0.1, vt(), src(), src(), feed("url"), "MALICIOUS")
        assert flagged > quiet

    def test_clean_feed_casts_no_vote(self):
        # Absence from a blocklist is neutral, never evidence of safety.
        with_feed = _confidence(0, 0.1, vt(), src(), src(), feed(), "SAFE")
        without_feed = _confidence(0, 0.1, vt(), src(), src(), None, "SAFE")
        assert with_feed == without_feed == 100


# ---------------------------------------------------------------------------
# _host_matches / _is_shared_hosting_tenant / _is_reputable_host
# ---------------------------------------------------------------------------

class TestHostMatches:
    def test_exact_and_subdomain(self):
        assert _host_matches("google.com", {"google.com"})
        assert _host_matches("maps.google.com", {"google.com"})

    def test_lookalike_suffix_does_not_match(self):
        # evilgoogle.com is NOT a subdomain of google.com.
        assert not _host_matches("evilgoogle.com", {"google.com"})

    def test_case_and_trailing_dot_normalised(self):
        assert _host_matches("WWW.Google.COM.", {"google.com"})

    def test_empty_domain(self):
        assert not _host_matches("", {"google.com"})


class TestSharedHostingTenant:
    def test_tenant_subdomain_is_tenant(self):
        assert _is_shared_hosting_tenant("alice.github.io")
        assert _is_shared_hosting_tenant("proj.vercel.app")
        assert _is_shared_hosting_tenant("bucket.s3.amazonaws.com")

    def test_platform_apex_is_not_tenant(self):
        assert not _is_shared_hosting_tenant("github.io")
        assert not _is_shared_hosting_tenant("vercel.app")

    def test_unrelated_domain_is_not_tenant(self):
        assert not _is_shared_hosting_tenant("example.com")

    def test_gcs_apex_and_subdomain_are_tenant_content(self):
        # Path-style buckets serve customer content from the APEX itself,
        # so unlike github.io the apex is tenant-class too.
        assert _is_shared_hosting_tenant("storage.googleapis.com")
        assert _is_shared_hosting_tenant("bucket.storage.googleapis.com")
        assert _is_shared_hosting_tenant("firebasestorage.googleapis.com")

    def test_psl_private_platform_tenants(self):
        # Live FNs 2026-07-14: kits on gitbook.io / square.site tenants.
        # square.site + blogspot.com come from the PSL PRIVATE section;
        # gitbook.io is NOT on the PSL and is manually listed.
        assert _is_shared_hosting_tenant("metmskaiilizwalet.gitbook.io")
        assert _is_shared_hosting_tenant("trejar-suite.square.site")
        assert _is_shared_hosting_tenant("someone.blogspot.com")

    def test_psl_private_platform_apex_is_not_tenant(self):
        assert not _is_shared_hosting_tenant("gitbook.io")
        assert not _is_shared_hosting_tenant("square.site")

    def test_provider_subdomains_never_become_psl_tenants(self):
        # googleapis.com is ALSO on the private PSL — the provider allowlist
        # must win, or every provider subdomain turns into an untrusted tenant.
        assert not _is_shared_hosting_tenant("fonts.googleapis.com")
        assert not _is_shared_hosting_tenant("maps.googleapis.com")


class TestIsReputableHost:
    WHO_NONE = {"age": None}

    def test_provider_apex_and_subdomain(self):
        assert _is_reputable_host("googleapis.com", False, self.WHO_NONE)
        assert _is_reputable_host("fonts.googleapis.com", False, self.WHO_NONE)

    def test_gcs_object_stores_override_provider_allowlist(self):
        # storage.googleapis.com is tenant content (like S3) even though
        # *.googleapis.com matches the provider allowlist.
        assert not _is_reputable_host("storage.googleapis.com", True, {"age": "10 yr"})
        assert not _is_reputable_host("bucket.storage.googleapis.com", True, {"age": "10 yr"})
        assert not _is_reputable_host("firebasestorage.googleapis.com", True, self.WHO_NONE)

    def test_lookalike_of_provider_is_not_reputable(self):
        assert not _is_reputable_host("evilgoogle.com", False, self.WHO_NONE)

    def test_shared_hosting_apex_reputable_tenant_not(self):
        assert _is_reputable_host("github.io", False, self.WHO_NONE)
        assert not _is_reputable_host("alice.github.io", False, self.WHO_NONE)

    def test_tenant_age_cannot_whitewash(self):
        # Platform apex age says nothing about the tenant page.
        assert not _is_reputable_host("alice.github.io", True, {"age": "10 yr"})

    def test_psl_tenant_age_cannot_whitewash(self):
        # Live FN mechanism 2026-07-14: gitbook.io / square.site tenants were
        # 'reputable' because RDAP returned the PLATFORM registration age.
        assert not _is_reputable_host("metmskaiilizwalet.gitbook.io", True, {"age": "12 yr"})
        assert not _is_reputable_host("trejar-suite.square.site", True, {"age": "9 yr"})

    def test_psl_platform_apex_is_reputable(self):
        assert _is_reputable_host("gitbook.io", True, {"age": "12 yr"})
        assert _is_reputable_host("square.site", True, {"age": "9 yr"})

    def test_github_com_reputable(self):
        assert _is_reputable_host("github.com", False, self.WHO_NONE)

    # These pin the AGE branch, so the fixture domain must be neutral —
    # example.com sits in the Tranco top-1000 snapshot and is now reputable
    # through the famous-domain branch regardless of age/SSL.
    def test_old_https_domain_is_reputable(self):
        assert _is_reputable_host("quiet-corner-antiques.com", True, {"age": "5 yr"})

    def test_old_domain_without_ssl_is_not(self):
        assert not _is_reputable_host("quiet-corner-antiques.com", False, {"age": "5 yr"})

    def test_rdap_unavailable_is_neutral(self):
        # age=None (RDAP timeout / rate-limit) grants nothing.
        assert not _is_reputable_host("quiet-corner-antiques.com", True, self.WHO_NONE)
        assert not _is_reputable_host("quiet-corner-antiques.com", True, {"age": ""})

    def test_young_domain_is_not_reputable(self):
        assert not _is_reputable_host("quiet-corner-antiques.com", True, {"age": "8 days"})

    def test_famous_domain_reputable_even_when_rdap_rate_limited(self):
        # Eval FPs 2026-07-16: under RDAP 429s, age went neutral and top
        # sites lost their reputable status. The Tranco snapshot holds it.
        assert _is_reputable_host("bbc.com", True, self.WHO_NONE)
        assert _is_reputable_host("mail.ru", True, self.WHO_NONE)
        # …but a tenant page on a popular platform is still NOT reputable.
        assert not _is_reputable_host("alice.blogspot.com", True, self.WHO_NONE)

    def test_empty_domain(self):
        assert not _is_reputable_host("", True, {"age": "5 yr"})


# ---------------------------------------------------------------------------
# _domain_from_url
# ---------------------------------------------------------------------------

class TestDomainFromUrl:
    @pytest.mark.parametrize("url,expected", [
        ("https://example.com/path", "example.com"),
        ("https://www.example.com", "example.com"),
        ("https://example.com:8443/x", "example.com"),
        ("https://user@example.com/", "example.com"),
        ("example.com/path", "example.com/path"),  # schemeless: netloc empty, path used
        ("https://EXAMPLE.COM", "example.com"),
    ])
    def test_extraction(self, url, expected):
        assert _domain_from_url(url) == expected
