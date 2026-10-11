"""
Regression tests for the six defects confirmed by the 2026-07-27 detection audit
(docs/Detection_Accuracy_Audit/). Each class pins one root cause with the
evidence that found it, so a future refactor cannot silently reintroduce it.

Audit findings covered here:
  2  email_analyzer.py:595   scam-intent cap makes link-less scams unreachable
  3  aggregator.py:376       reputability depends on a rate-limited RDAP lookup
  4  apis/page_content.py    a search form counts as credential harvesting
  5  apis/typosquat.py:283   brand checks disabled for whole tenant platforms
  6  typosquat.BRANDS        brand + shortener coverage too small

Finding 1 (circular benchmark) is covered by test_realworld_eval_selection.py.
"""

import pytest

from ai_engine import SHORTENERS
from aggregator import (_cap_weak_heuristic_only, _is_reputable_host,
                        _shared_hosting_class)
from apis.page_content import _score_content_signals
from apis.typosquat import BRANDS, check_typosquatting
from email_analyzer import analyze_email, score_scam_intent

NO_AUTH = {"spf": "none", "dkim": "none", "dmarc": "none"}


# ---------------------------------------------------------------------------
# Finding 4 — a cross-origin form is only credential harvesting when it
# actually carries a credential field.
# ---------------------------------------------------------------------------
class TestExternalFormActionNeedsCredentialField:
    """
    Live FP (audit 2026-07-27): schneier.com scored content_risk 60 and was
    accused of "posting credentials to a different domain" because its
    DuckDuckGo *search* box posts cross-origin. has_password_field and
    has_login_form were both False.
    """

    def test_search_form_alone_is_not_credential_harvesting(self):
        res = _score_content_signals(
            has_password_field=False,
            has_login_form=False,
            external_form_action=True,
            brand_mismatch=False,
            title_brand_mismatch=False,
            favicon_brand_mismatch=False,
            js_redirect=False,
            login_keywords_near_form=False,
            external_resource_count=13,
            signals=[],
        )
        assert res["external_form_action"] is False, (
            "a cross-origin form with no credential field must not be reported "
            "as external_form_action"
        )

    def test_search_form_does_not_emit_a_credentials_signal(self):
        res = _score_content_signals(
            has_password_field=False,
            has_login_form=False,
            external_form_action=True,
            brand_mismatch=False,
            title_brand_mismatch=False,
            favicon_brand_mismatch=False,
            js_redirect=False,
            login_keywords_near_form=False,
            external_resource_count=13,
            signals=["Form submits credentials to external domain 'duckduckgo.com'"],
        )
        assert not any("credentials" in s.lower() for s in res["suspicious_signals"]), (
            "must not claim credentials are submitted when no credential field exists"
        )

    def test_cross_origin_password_post_is_still_credential_harvesting(self):
        """The real signal must survive the fix."""
        res = _score_content_signals(
            has_password_field=True,
            has_login_form=True,
            external_form_action=True,
            brand_mismatch=True,
            title_brand_mismatch=False,
            favicon_brand_mismatch=False,
            js_redirect=False,
            login_keywords_near_form=True,
            external_resource_count=4,
            signals=["Form submits credentials to external domain 'evil.tld'"],
        )
        assert res["external_form_action"] is True
        assert res["content_risk"] >= 70


# ---------------------------------------------------------------------------
# Finding 3 — a throttled RDAP lookup must not strip a site of reputability.
# ---------------------------------------------------------------------------
class TestReputabilitySurvivesThrottledRdap:
    """
    Controlled test (audit 2026-07-27): schneier.com, findagrave.com and
    sport.pl each flipped SAFE -> SUSPICIOUS when the only change was RDAP
    answering HTTP 429 instead of an age. On one cloud egress IP, throttled is
    the steady state, so the throttled path must not be the risky one.
    """

    HEALTHY = {"age": "24 yr", "status": "ok"}
    THROTTLED = {"age": None, "status": "unavailable", "detail": "RDAP HTTP 429"}

    def test_valid_https_host_stays_reputable_when_rdap_is_unavailable(self):
        assert _is_reputable_host("www.schneier.com", True, self.HEALTHY) is True
        assert _is_reputable_host("www.schneier.com", True, self.THROTTLED) is True, (
            "an unavailable RDAP lookup must be NEUTRAL, not evidence against the host"
        )

    def test_shared_hosting_tenant_is_never_whitewashed_by_unknown_age(self):
        """A tenant page must stay judgeable — the platform's age says nothing."""
        assert _shared_hosting_class("evil-kit.gitbook.io") == "tenant"
        assert _is_reputable_host("evil-kit.gitbook.io", True, self.THROTTLED) is False

    def test_plain_http_host_gains_nothing_from_unknown_age(self):
        assert _is_reputable_host("random-new-domain.xyz", False, self.THROTTLED) is False

    def test_rdap_reporting_a_young_domain_still_denies_reputability(self):
        young = {"age": "9 days", "status": "ok"}
        assert _is_reputable_host("brand-new-site.xyz", True, young) is False

    def test_established_domain_still_has_its_page_inspected(self):
        """
        The established-snapshot branch exists to suppress FALSE POSITIVES, not
        to skip work. full_scan reuses _is_reputable_host with an empty who_res
        to decide whether to skip the page fetch (`fast_reputable`), and letting
        the snapshot drive that had two costs, both measured:

          * 9 legitimate .ru/.xyz domains jumped from ~20 to exactly 40
            (SUSPICIOUS) because the skipped content check had been the signal
            DILUTING their suspicious-TLD flag;
          * a COMPROMISED established site — smithandsmith.co.za/mezzlesolicitors
            in the audit corpus — would never have its kit page inspected, which
            is the single hardest miss shape to catch.

        So the fetch-skip must NOT consider the snapshot.
        """
        assert _is_reputable_host("www.schneier.com", True, {}) is True
        assert _is_reputable_host(
            "www.schneier.com", True, {}, include_established=False) is False

    def test_fetch_skip_still_applies_to_providers_and_top_domains(self):
        """Narrowing must not cost the latency win on genuinely trusted hosts."""
        assert _is_reputable_host(
            "github.com", True, {}, include_established=False) is True
        assert _is_reputable_host(
            "fonts.googleapis.com", True, {}, include_established=False) is True


class TestReputabilityNeverRaisesAScore:
    """
    Measured regression while fixing finding 3 (2026-07-27): adding the
    established-domain snapshot made 9 legitimate domains — beget.ru, nic.xyz,
    smotrim.ru, yandex-team.ru, stocrm.ru, xbox-dns.ru, joinserver.xyz,
    vseinstrumenti.ru, bysex.click — jump from ~20 to EXACTLY 40 (SUSPICIOUS).

    Mechanism: becoming `reputable` made them weak_signal_capped, which DROPS
    the lexical ML from the blend. _weighted_score then renormalises over the
    single remaining part, so the heuristic's 25% weight carried 100% of the
    verdict and the score became h_score exactly — and h_score is 40 for a
    lone "Suspicious domain extension" flag on a national TLD like .ru.

    The invariant: recognising a host as reputable must never RAISE its score.
    When a reputable, reputation-clean host has nothing but a weak heuristic —
    no active reputation hit, no content vote, no strong flag — that is the
    definition of "not enough to flag", so it must stay below SUSPICIOUS.
    """

    def test_weak_heuristic_alone_does_not_convict_a_reputable_host(self):
        # h_score 40 from a lone suspicious-TLD flag, nothing else fired.
        assert _cap_weak_heuristic_only(
            40, weak_signal_capped=True, rep_active=False,
            content_voted=False, strong_flags=0) == 39

    def test_cap_does_not_apply_when_content_voted(self):
        """A compromised established site whose PAGE looks like a kit must convict."""
        assert _cap_weak_heuristic_only(
            65, weak_signal_capped=True, rep_active=False,
            content_voted=True, strong_flags=0) == 65

    def test_cap_does_not_apply_with_a_strong_flag(self):
        assert _cap_weak_heuristic_only(
            70, weak_signal_capped=True, rep_active=False,
            content_voted=False, strong_flags=1) == 70

    def test_cap_does_not_apply_on_an_active_reputation_hit(self):
        assert _cap_weak_heuristic_only(
            90, weak_signal_capped=True, rep_active=True,
            content_voted=False, strong_flags=0) == 90

    def test_cap_does_not_apply_to_a_non_reputable_host(self):
        """A fresh unknown domain keeps its weak-signal score."""
        assert _cap_weak_heuristic_only(
            40, weak_signal_capped=False, rep_active=False,
            content_voted=False, strong_flags=0) == 40

    def test_cap_never_raises_a_quiet_score(self):
        assert _cap_weak_heuristic_only(
            12, weak_signal_capped=True, rep_active=False,
            content_voted=False, strong_flags=0) == 12

    def test_cap_tracks_the_suspicious_threshold(self):
        """
        The cap must stay tied to the band boundary, not a hardcoded 39.
        Measured 2026-07-27: 15 legitimate domains park exactly ON the cap, so
        if the SUSPICIOUS threshold is ever lowered without the cap following,
        all 15 convert to false positives at once (FP 1 -> 16, FPR 0.46% ->
        7.41%). Tying them together makes that impossible.
        """
        from aggregator import SUSPICIOUS_MIN, _verdict
        capped = _cap_weak_heuristic_only(
            100, weak_signal_capped=True, rep_active=False,
            content_voted=False, strong_flags=0)
        assert capped == SUSPICIOUS_MIN - 1
        assert _verdict(capped) == "SAFE", (
            "a capped weak-signal score must land in the SAFE band whatever "
            "the threshold is set to"
        )


# ---------------------------------------------------------------------------
# Finding 5 — the established-registrable exemption must not cover tenants.
# ---------------------------------------------------------------------------
class TestTenantsAreNotExemptedByTheirPlatform:
    """
    Audit 2026-07-27: robinhood-logint.gitbook.io and
    helptrezor-suite.wasmer.app both scored 0. _split_registrable collapses a
    tenant host to the platform root whenever the platform is missing from the
    PSL private section; the root is Tranco-established, so typosquat.py
    returned early and skipped every brand check. The same label on pages.dev
    (which IS in PSL private) flagged at 72.
    """

    @pytest.mark.parametrize("host", [
        "paypal-logint.gitbook.io",
        "microsoft-verify.gitbook.io",
        "paypal-suite.wasmer.app",
    ])
    def test_brand_label_on_a_tenant_platform_is_flagged(self, host):
        res = check_typosquatting(host)
        assert res["is_typosquat"] is True, (
            f"{host} embeds a known brand in a tenant label and must flag "
            "regardless of the platform's own Tranco rank"
        )

    def test_platform_apex_itself_is_not_a_typosquat(self):
        """gitbook.io IS GitBook — the exemption must still protect the apex."""
        assert check_typosquatting("gitbook.io")["is_typosquat"] is False
        assert check_typosquatting("wasmer.app")["is_typosquat"] is False

    def test_established_non_tenant_domain_keeps_its_exemption(self):
        """Finding must not regress BUG-4: dhl.de IS DHL."""
        assert check_typosquatting("dhl.de")["is_typosquat"] is False


# ---------------------------------------------------------------------------
# Finding 6 — brand and shortener coverage.
# ---------------------------------------------------------------------------
class TestBrandAndShortenerCoverage:
    """
    Audit misses that scored 0: raiffiesen.social (one letter off a real bank),
    swisscomlei.com, and goo.su/lVUOJ (an unlisted shortener).
    """

    @pytest.mark.parametrize("brand", [
        "raiffeisen", "swisscom", "robinhood", "trezor", "garena",
        # India-facing coverage: the brands this product actually defends.
        "sbi", "hdfc", "icici", "axisbank", "kotak", "paytm", "phonepe",
        "aadhaar", "incometax",
    ])
    def test_brand_is_covered(self, brand):
        assert brand in BRANDS, f"{brand!r} is impersonated in the wild and must be listed"

    def test_bank_typosquat_from_the_audit_is_caught(self):
        assert check_typosquatting("raiffiesen.social")["is_typosquat"] is True

    @pytest.mark.parametrize("shortener", [
        "goo.su", "shorturl.at", "rb.gy", "t.ly", "s.id", "bitly.com",
    ])
    def test_shortener_is_covered(self, shortener):
        assert shortener in SHORTENERS, f"{shortener!r} must be recognised as a shortener"

    def test_official_brand_domains_are_never_typosquats(self):
        """Every added brand must carry its real domains, or it self-flags."""
        for brand, officials in BRANDS.items():
            for official in officials:
                res = check_typosquatting(official)
                assert res["is_typosquat"] is False, (
                    f"{official} is an official domain of {brand!r} but flagged as a typosquat"
                )


# ---------------------------------------------------------------------------
# Finding 2 — a maxed scam intent with a real ask must be able to convict.
# ---------------------------------------------------------------------------
class TestLinkLessScamCanReachMalicious:
    """
    Audit 2026-07-27: three unrelated maximum-intent scams all scored EXACTLY
    57 (SUSPICIOUS), because the intent contribution is capped at 45 while
    MALICIOUS needs 70. That is the whole family of scams which carry no link
    on purpose — lottery, digital arrest, advance-fee, fake job.

    The escalation must require a STRUCTURAL ask (money or credentials), not
    mere urgency vocabulary, so ordinary pushy marketing email stays SAFE.
    """

    LOTTERY = (
        "Subject: Congratulations! You have won 25 Lakh in the KBC lucky draw\n"
        "From: KBC Lottery Team <winner@kbc-lucky-draw.info>\n"
        "Body: Congratulations!!! Your mobile number has won the KBC lucky draw "
        "prize money of 25 Lakh rupees. To claim your prize, you must pay a small "
        "refundable processing fee of 5000 rupees. Send the processing fee via gift "
        "card or bank transfer and reply with your bank account number to receive "
        "your winnings immediately. Act now - this offer expires today!"
    )

    DIGITAL_ARREST = (
        "Subject: URGENT: Arrest warrant issued against your Aadhaar\n"
        "From: CBI Cyber Crime Cell <cbi-cybercell@india-gov-verify.info>\n"
        "Body: A parcel containing narcotics linked to your Aadhaar number has been "
        "seized. An arrest warrant has been issued. You are under digital arrest and "
        "must not inform your family. Transfer the security deposit of 250000 rupees "
        "to the RBI verification account and reply with your bank account number, "
        "debit card number, CVV and the OTP sent to your phone. Act now."
    )

    # Pushy but harmless: urgency words, NO money or credential ask.
    MARKETING = (
        "Subject: Last chance - our biggest sale expires today!\n"
        "From: Shop Newsletter <news@example-shop.com>\n"
        "Body: Act now! Our biggest sale of the year expires today. Limited stock "
        "remaining, so do not miss out. Browse the collection immediately and enjoy "
        "up to 70% off everything in store. Offer ends at midnight."
    )

    def test_lottery_scam_is_malicious(self):
        res = analyze_email(self.LOTTERY, auth_results=NO_AUTH)
        assert res["risk_score"] >= 70, f"scored {res['risk_score']}, expected MALICIOUS band"
        assert res["verdict"] == "MALICIOUS"

    def test_digital_arrest_scam_is_malicious(self):
        res = analyze_email(self.DIGITAL_ARREST, auth_results=NO_AUTH)
        assert res["risk_score"] >= 70, f"scored {res['risk_score']}, expected MALICIOUS band"
        assert res["verdict"] == "MALICIOUS"

    def test_urgent_marketing_without_an_ask_stays_below_malicious(self):
        intent = score_scam_intent(self.MARKETING)
        assert not intent["money_request"]
        assert not intent["credential_request"]
        res = analyze_email(self.MARKETING, auth_results=NO_AUTH)
        assert res["risk_score"] < 70, (
            f"scored {res['risk_score']} — urgency wording alone must never convict"
        )

    def test_genuine_authenticated_mail_is_unaffected(self):
        good = (
            "Subject: Your monthly account statement is ready\n"
            "From: Example Bank <statements@example-bank.com>\n"
            "Body: Your monthly statement is now available in the app. "
            "We will never ask you for your PIN or OTP."
        )
        res = analyze_email(good, auth_results={"spf": "pass", "dkim": "pass", "dmarc": "pass"})
        assert res["verdict"] == "SAFE"
