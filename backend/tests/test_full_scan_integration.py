"""
Integration tests for the FULL full_scan() blend — the real pipeline from URL
to verdict, with only the network sources monkeypatched to deterministic
fixtures. Unlike test_aggregator.py (pure functions in isolation), these catch
cross-channel bugs in the blend itself.

Regression anchor: octocat.github.io/phishing-awareness-login-guide scored
MALICIOUS 70 at the live /scan surface — the tenant corroboration gate dropped
the lexical ML but NOT the keyword heuristic ('login' 10 + 'phishing' 60 = 70),
so the renormalised blend became a pure h_score passthrough. On shared-hosting
tenants, security vocabulary alone must never exceed SUSPICIOUS.

The local heuristic engine, typosquat detector, and (when installed) the ML
model run REAL — fixtures only replace network I/O — and every assertion holds
both with the ML stack present and in the slim CI env (ml_prob = None), because
the lexical ML is dropped on uncorroborated tenants in either case.
"""

import asyncio

import pytest

import aggregator as agg


# ---------------------------------------------------------------------------
# Network fixtures (shapes mirror aggregator's own _FB_* fallbacks)
# ---------------------------------------------------------------------------

def vt(status="clean", positives=0):
    return {"status": status, "detail": f"{positives} engines", "raw_positives": positives}


def src(status="clean", detail=""):
    return {"status": status, "detail": detail}


def feed(match=None, detail=""):
    """Community-blocklist result: match is "url" (confirmed exact listing),
    "domain" (weaker bare-host listing) or None (clean)."""
    return {"status": "flag" if match else "clean", "detail": detail, "match": match}


def chain_of(url):
    return {"chain": [url], "final": url, "loop": False, "truncated": False,
            "html": None, "blocked_scheme": False}


def content(**overrides):
    c = dict(agg._FB_CONTENT)
    c.update(overrides)
    return c


CREDENTIAL_HARVEST_KIT = content(
    fetched=True,
    has_password_field=True,
    has_login_form=True,
    external_form_action=True,
    brand_mismatch=True,
    login_keywords_near_form=True,
    suspicious_signals=["Password form posts to a different domain"],
    content_risk=85,
)


@pytest.fixture
def patched_sources(monkeypatch):
    """
    Patch every network call full_scan makes; local analysis (heuristics,
    typosquat, ML) stays real. Returns a dict the test mutates to inject
    per-case reputation / content results.
    """
    state = {
        "vt": vt(),
        "gsb": src(),
        "uh": src(),
        "feeds": feed(),
        "content": content(),
        "whois": dict(agg._FB_WHOIS),
    }

    async def _async(key):
        return state[key]

    monkeypatch.setattr(agg, "_resolve_chain", lambda url, **kw: chain_of(url))
    monkeypatch.setattr(agg, "_resolve_ip", lambda d: "203.0.113.10")
    monkeypatch.setattr(agg, "check_virustotal", lambda u: state["vt"])
    # Google's threat corpus reaches the blend through whichever API this build
    # is licensed for — Safe Browsing v4 non-commercially, Web Risk in a paid
    # build (see aggregator._google_reputation). Both are stubbed from the same
    # state key so these tests assert "a Google reputation hit escalates",
    # which is the behaviour, rather than which vendor endpoint carried it.
    monkeypatch.setattr(agg, "check_safe_browsing", lambda u: _async("gsb"))
    monkeypatch.setattr(agg, "check_web_risk", lambda u: _async("gsb"))
    monkeypatch.setattr(agg, "check_urlhaus", lambda u: _async("uh"))
    monkeypatch.setattr(agg, "check_phish_feeds", lambda u: _async("feeds"))
    monkeypatch.setattr(agg, "analyze_page_content",
                        lambda u, html=None: state["content"])
    monkeypatch.setattr(agg, "check_whois", lambda d: _async("whois"))

    async def _geo(d):
        return dict(agg._FB_GEO)

    async def _sslcert(d):
        return dict(agg._FB_SSL)

    async def _urlscan(u):
        return dict(agg._FB_URLSCAN)

    monkeypatch.setattr(agg, "check_geo", _geo)
    monkeypatch.setattr(agg, "check_ssl_cert", _sslcert)
    monkeypatch.setattr(agg, "check_urlscan", _urlscan)
    monkeypatch.setattr(agg, "_explain_url", lambda u, top_n=5: None)
    # No cross-test cache contamination; hop-blocklist lookups also see None.
    monkeypatch.setattr(agg, "cache_get", lambda k: None)
    monkeypatch.setattr(agg, "cache_put", lambda k, v, ttl=None: None)
    return state


def scan(url):
    return asyncio.run(agg.full_scan(url))


# ---------------------------------------------------------------------------
# The verified false positive: keyword channel on an uncorroborated tenant
# ---------------------------------------------------------------------------

class TestTenantKeywordChannel:
    def test_security_vocabulary_alone_is_not_malicious(self, patched_sources):
        r = scan("https://octocat.github.io/phishing-awareness-login-guide")
        assert r["verdict"] in ("SAFE", "SUSPICIOUS")
        assert r["risk_score"] < 70

    def test_tenant_apex_paths_stay_safe(self, patched_sources):
        for url in ("https://octocat.github.io/",
                    "https://octocat.github.io/hello-world"):
            r = scan(url)
            assert r["verdict"] == "SAFE", url
            assert r["risk_score"] < 40, url

    def test_keyword_flags_still_listed_for_transparency(self, patched_sources):
        r = scan("https://octocat.github.io/phishing-awareness-login-guide")
        assert any(f.startswith("Suspicious keyword:") for f in r["flags"])


# ---------------------------------------------------------------------------
# Real tenant phishing kits must still escalate (the gate must not overreach)
# ---------------------------------------------------------------------------

class TestTenantKitsStillEscalate:
    def test_credential_harvest_kit_is_malicious(self, patched_sources):
        patched_sources["content"] = CREDENTIAL_HARVEST_KIT
        r = scan("https://login-verify.github.io/secure-account")
        assert r["verdict"] == "MALICIOUS"
        assert r["risk_score"] >= 78

    def test_blocklisted_tenant_is_malicious(self, patched_sources):
        patched_sources["gsb"] = src("flag", "SOCIAL_ENGINEERING")
        r = scan("https://octocat.github.io/phishing-awareness-login-guide")
        assert r["verdict"] == "MALICIOUS"
        assert r["risk_score"] >= 80

    def test_two_engine_vt_tenant_is_malicious(self, patched_sources):
        patched_sources["vt"] = vt("warn", 2)
        r = scan("https://octocat.github.io/some-page")
        assert r["verdict"] == "MALICIOUS"
        assert r["risk_score"] >= 80

    def test_single_engine_vt_tenant_is_suspicious_not_malicious(self, patched_sources):
        patched_sources["vt"] = vt("warn", 1)
        r = scan("https://octocat.github.io/some-page")
        assert r["verdict"] == "SUSPICIOUS"
        assert 60 <= r["risk_score"] < 70


# ---------------------------------------------------------------------------
# Provider allowlist (FIX 1) at the full-blend level
# ---------------------------------------------------------------------------

class TestPayloadSchemes:
    """javascript:/data: 'URLs' are payloads, not destinations — previously
    reported SAFE at 100 confidence at the live /scan surface."""

    @pytest.mark.parametrize("url", [
        "javascript:alert(1)",
        "JAVASCRIPT:alert(document.cookie)",
        "data:text/html;base64,PGgxPmhpPC9oMT4=",
        "vbscript:msgbox(1)",
        "%6Aavascript:alert(1)",      # percent-encoded scheme
        "java\tscript:alert(1)",      # whitespace-obfuscated scheme
    ])
    def test_payload_scheme_is_suspicious(self, patched_sources, url):
        r = scan(url)
        assert r["verdict"] == "SUSPICIOUS"
        assert r["risk_score"] >= 60
        assert r["domain"] == ""          # no fake 'alert(1)' domain
        assert any("scheme" in f for f in r["flags"])

    def test_normal_https_url_unaffected(self, patched_sources):
        r = scan("https://an-ordinary-site.com/page")
        assert r["verdict"] == "SAFE"

    def test_schemeless_hostname_starting_with_data_unaffected(self, patched_sources):
        # data.example.com must not be mistaken for a data: URI.
        r = scan("data.example.com/reports")
        assert r["verdict"] == "SAFE"


class TestProviderAllowlistBlend:
    def test_scary_path_on_provider_host_capped_at_suspicious(self, patched_sources):
        # fonts.googleapis.com is genuine provider infra (NOT a tenant store).
        r = scan("https://fonts.googleapis.com/secure-login-verify/"
                 "phishing-account-update.html")
        assert r["verdict"] != "MALICIOUS"
        assert r["risk_score"] <= 69

    def test_provider_host_with_strong_reputation_is_malicious(self, patched_sources):
        # An ACTIVE confirmed reputation hit must override the reputable cap.
        patched_sources["gsb"] = src("flag", "SOCIAL_ENGINEERING")
        r = scan("https://fonts.googleapis.com/some-path")
        assert r["verdict"] == "MALICIOUS"
        assert r["risk_score"] >= 80


class TestReputableKeywordChannel:
    """Aged reputable domains hosting security vocabulary (verified live FPs
    2026-07-14: kaspersky.com/resource-center/threats/phishing and
    ncsc.gov.uk/guidance/phishing scored SUSPICIOUS 60 on the 'phishing'
    keyword alone). The tenant corroboration rule must apply to ALL
    weak-signal-capped reputable hosts: uncorroborated keyword hits back out
    of the heuristic score; corroborated ones still count."""

    AGED_WHOIS = {"registrar": "Example Registrar", "created": "2005-04-02",
                  "age": "21 yr", "country": "US", "age_days": 7700}

    def test_security_article_on_aged_domain_is_safe(self, patched_sources):
        patched_sources["whois"] = dict(self.AGED_WHOIS)
        r = scan("https://security-vendor-example.com/resource-center/threats/phishing")
        assert r["verdict"] == "SAFE", (r["risk_score"], r["flags"])
        assert r["risk_score"] < 40

    def test_keyword_flags_still_listed_for_transparency(self, patched_sources):
        patched_sources["whois"] = dict(self.AGED_WHOIS)
        r = scan("https://security-vendor-example.com/resource-center/threats/phishing")
        assert any(f.startswith("Suspicious keyword:") for f in r["flags"])

    def test_corroborated_keywords_still_count(self, patched_sources):
        # 'Login combined with financial terms' is real corroboration — the
        # keyword channel must keep escalating a corroborated aged domain.
        patched_sources["whois"] = dict(self.AGED_WHOIS)
        r = scan("https://old-shop-example.com/login-bank-verify-account")
        assert r["verdict"] == "SUSPICIOUS", (r["risk_score"], r["flags"])
        assert 40 <= r["risk_score"] <= 69

    def test_credential_harvest_on_aged_domain_still_malicious(self, patched_sources):
        # Compromised aged site hosting a real kit — age must not whitewash it.
        patched_sources["whois"] = dict(self.AGED_WHOIS)
        patched_sources["content"] = CREDENTIAL_HARVEST_KIT
        r = scan("https://compromised-old-site.com/secure/login.html")
        assert r["verdict"] == "MALICIOUS"
        assert r["risk_score"] >= 78

    def test_reputation_hit_on_aged_domain_still_malicious(self, patched_sources):
        patched_sources["whois"] = dict(self.AGED_WHOIS)
        patched_sources["gsb"] = src("flag", "SOCIAL_ENGINEERING")
        r = scan("https://old-domain-example.com/newsletter")
        assert r["verdict"] == "MALICIOUS"
        assert r["risk_score"] >= 80


class TestProviderSelfImpersonationBlend:
    """A provider's own domains must not be flagged as impersonating their own
    brand. Verified live FPs (2026-07-14 eval): googletagmanager.com scanned
    SUSPICIOUS 69 — brand_embedded typosquat of 'google' (72%) + 'Possible
    impersonation: google' — with every reputation source clean."""

    @pytest.mark.parametrize("url", [
        "https://googletagmanager.com",
        "https://googlevideo.com",
        "https://microsoftonline.com",
        "https://apple-dns.net",
        "https://cloud.microsoft",
        "https://googledomains.com",
    ])
    def test_provider_apex_scans_safe(self, patched_sources, url):
        r = scan(url)
        assert r["verdict"] == "SAFE", (url, r["risk_score"], r["flags"])
        assert not any(
            "impersonat" in f.lower() or f.startswith("Typosquatting") for f in r["flags"]
        ), r["flags"]

    def test_provider_with_reputation_hit_still_malicious(self, patched_sources):
        # The exemption must not blanket-protect a provider domain that has an
        # ACTIVE reputation hit (e.g. a compromised/abused provider endpoint).
        patched_sources["gsb"] = src("flag", "SOCIAL_ENGINEERING")
        r = scan("https://googletagmanager.com/gtm.js")
        assert r["verdict"] == "MALICIOUS"
        assert r["risk_score"] >= 80

    def test_provider_redirecting_to_brand_tld_is_safe(self, patched_sources, monkeypatch):
        # Live FP 2026-07-14 (final eval run): googledomains.com 301s to
        # domains.google; the FINAL domain is scored, and the closed .google
        # brand TLD was not provider-class, so it self-impersonated at 69.
        monkeypatch.setattr(agg, "_resolve_chain", lambda url, **kw: {
            "chain": ["https://googledomains.com", "https://domains.google/"],
            "final": "https://domains.google/", "loop": False,
            "truncated": False, "html": None, "blocked_scheme": False,
        })
        r = scan("https://googledomains.com")
        assert r["verdict"] == "SAFE", (r["risk_score"], r["flags"])

    def test_google_gle_redirector_link_is_safe(self, patched_sources):
        # Live FP 2026-07-16 (BUG 1, WORK_PLAN Task 3): genuine Google mail
        # links through c.gle with long random tokens — lexically "phishy"
        # (ML 86–94%), which pushed a REAL Google email to MALICIOUS 80.
        # .gle is Google's closed Spec-13 brand TLD (c.gle / forms.gle /
        # goo.gle): provider-class, so lexical-only signals must not escalate.
        r = scan(
            "https://c.gle/AOExmq19VZiar9bZdhTgSTKMO_MCzQRgSYgVlo8tYfR5SeES"
            "_BByllpr7-TDa-IQmzCGmWNLzAX3_bq_4wmRmiRIpN_Fg93iwgecKQw1HeCs"
        )
        assert r["verdict"] == "SAFE", (r["risk_score"], r["flags"])

    def test_gle_with_reputation_hit_still_malicious(self, patched_sources):
        # The .gle exemption is lexical-only relief — an active blocklist hit
        # (e.g. an abused open redirect) must still escalate.
        patched_sources["gsb"] = src("flag", "SOCIAL_ENGINEERING")
        r = scan("https://c.gle/some-abused-redirect")
        assert r["verdict"] == "MALICIOUS"
        assert r["risk_score"] >= 80

    def test_famous_domains_scan_safe_even_without_whois_age(self, patched_sources):
        # Eval FPs 2026-07-16 (600-domain run under RDAP rate-limiting):
        # bbc.com convicted as a 'typosquat of hsbc' (55), shopify.com as
        # 'spotify' (55), amazon-adsystem.com via embedded-brand + lexical ML.
        # Tranco-top-1000 registrables are the real sites: never typosquats,
        # and reputable even when the WHOIS age lookup is rate-limited away
        # (the fixture's whois fallback has age=None, mimicking RDAP 429).
        for url in ("https://bbc.com", "https://shopify.com",
                    "https://amazon-adsystem.com", "https://mail.ru"):
            r = scan(url)
            assert r["verdict"] == "SAFE", (url, r["risk_score"], r["flags"])

    def test_lookalike_of_a_famous_domain_still_flags(self, patched_sources):
        # The exemption is exact-registrable only — a lookalike must still burn.
        r = scan("http://bbc-news-verify.xyz/login")
        assert r["verdict"] in ("SUSPICIOUS", "MALICIOUS"), (r["risk_score"], r["flags"])

    def test_midband_ml_alone_never_convicts(self, patched_sources):
        # Retrained-model regression 2026-07-16: hyphenated multi-word .com
        # domains read mid-band phishy to the v2 lexical model (~0.6-0.7).
        # With reputation silent, no strong flag and quiet heuristics, a lone
        # mid-confidence ML opinion must be dropped from the blend — ordinary
        # small-business domains stay SAFE.
        for url in ("https://an-ordinary-site.com/page",
                    "https://my-cooking-blog.com/recipes",
                    "https://north-shore-dental.com/"):
            r = scan(url)
            assert r["verdict"] == "SAFE", (url, r["risk_score"], r["flags"])
        # the probability itself stays visible for transparency
        r = scan("https://an-ordinary-site.com/page")
        assert r.get("ml_probability") is not None

    def test_high_confidence_ml_alone_never_convicts_either(self, patched_sources):
        # M1 retrain 2026-07-17: fresh feed data pushed the SAME lexical shape
        # (hyphenated multi-word .com) from mid-band to 0.97+, escaping the old
        # 0.75 band and hitting the >=0.85 escalation floor (SUSPICIOUS 69 on a
        # quiet, reputation-silent domain). The corroboration requirement — not
        # the band — is the rule: a lone lexical opinion at ANY confidence is
        # neutral. Corroborated/loud scans keep the full ML channel.
        r = scan("https://quiet-unknown-domain.com/")
        assert r["verdict"] == "SAFE", (r["risk_score"], r["flags"])
        r = scan("https://an-ordinary-site.com/page")
        assert r["verdict"] == "SAFE", (r["risk_score"], r["flags"])

    def test_two_engine_vt_only_on_brand_tld_is_noise(self, patched_sources):
        # Live FP 2026-07-16 (BUG 1, second layer): the real c.gle link carried
        # a 2/92-engine VT detection — paranoid engines flag Google's random-
        # token redirect URLs constantly. On a CLOSED single-registrant brand
        # TLD no third party can publish content, so a VT-only detection at or
        # below the strong-engine bar, with every blocklist clean, is noise.
        # (dzen.ru-style user-content platforms keep 2-engine escalation.)
        patched_sources["vt"] = vt("warn", 2)
        r = scan("https://c.gle/AOExmq19VZiar9bZdhTgSTKMO_MCzQRgSYgVlo8tY")
        assert r["verdict"] == "SAFE", (r["risk_score"], r["flags"])
        assert any(f.startswith("VirusTotal:") for f in r["flags"])  # transparency

    def test_three_engine_vt_on_brand_tld_still_malicious(self, patched_sources):
        # Real engine consensus must still win on a brand TLD.
        patched_sources["vt"] = vt("warn", 3)
        r = scan("https://c.gle/genuinely-abused")
        assert r["verdict"] == "MALICIOUS"
        assert r["risk_score"] >= 80

    def test_single_engine_vt_on_provider_host_is_noise(self, patched_sources):
        # Live FP 2026-07-14: dzen.ru floored at SUSPICIOUS 60 by ONE paranoid
        # VT engine. Single-engine-only VT on a provider-allowlisted host is
        # reputation noise; the VT detail stays listed for transparency.
        patched_sources["vt"] = vt("warn", 1)
        r = scan("https://dzen.ru/")
        assert r["verdict"] == "SAFE", (r["risk_score"], r["flags"])
        assert any(f.startswith("VirusTotal:") for f in r["flags"])

    def test_two_engine_vt_on_provider_host_is_malicious(self, patched_sources):
        patched_sources["vt"] = vt("warn", 2)
        r = scan("https://dzen.ru/")
        assert r["verdict"] == "MALICIOUS"

    def test_single_engine_vt_plus_second_source_still_counts(self, patched_sources):
        # VT(1) + URLHaus flag = two active sources — not noise.
        patched_sources["vt"] = vt("warn", 1)
        patched_sources["uh"] = src("flag", "listed (phishing)")
        r = scan("https://dzen.ru/")
        assert r["verdict"] == "MALICIOUS"


class TestAgedPlatformTenants:
    """Live FNs 2026-07-14: phishing kits on gitbook.io / square.site tenants.
    Neither platform was in SHARED_HOSTING_SUFFIXES, so RDAP age of the
    PLATFORM registration made the tenant page 'reputable' and suppressed its
    content signals. square.site is auto-detected via the PSL private section;
    gitbook.io is manually listed (not on the PSL)."""

    AGED_WHOIS = {"registrar": "R", "created": "2013-01-01", "age": "13 yr",
                  "country": "US", "age_days": 4700}

    LOGIN_PAGE = dict(fetched=True, has_password_field=True,
                      has_login_form=True, content_risk=50)

    @pytest.mark.parametrize("url", [
        "https://metmskaiilizwalet.gitbook.io/",
        "https://trejar-suite.square.site/claim-wallet",
    ])
    def test_platform_age_does_not_suppress_tenant_content(self, patched_sources, url):
        patched_sources["whois"] = dict(self.AGED_WHOIS)
        patched_sources["content"] = content(**self.LOGIN_PAGE)
        r = scan(url)
        assert r["verdict"] != "SAFE", (url, r["risk_score"], r["flags"])
        assert r["risk_score"] >= 45

    def test_harvest_kit_on_aged_platform_tenant_is_malicious(self, patched_sources):
        patched_sources["whois"] = dict(self.AGED_WHOIS)
        patched_sources["content"] = CREDENTIAL_HARVEST_KIT
        r = scan("https://metmskaiilizwalet.gitbook.io/wallet-verify")
        assert r["verdict"] == "MALICIOUS"
        assert r["risk_score"] >= 78

    def test_platform_apexes_stay_safe(self, patched_sources):
        patched_sources["whois"] = dict(self.AGED_WHOIS)
        for url in ("https://gitbook.io/", "https://square.site/"):
            r = scan(url)
            assert r["verdict"] == "SAFE", (url, r["risk_score"], r["flags"])


class TestFeedMembershipBlend:
    """Live FNs 2026-07-14: most of the 13 missed phish were ON the OpenPhish
    feed at scan time — the feed only powered /live-threats, never /scan.
    An exact-URL feed listing is a confirmed reputation hit (strong, like GSB)."""

    @pytest.fixture
    def feed_flagged(self, patched_sources):
        patched_sources["feeds"] = feed("url", "listed on the OpenPhish URL feed")
        return patched_sources

    def test_feed_listed_tenant_is_malicious(self, feed_flagged):
        # Exact live FN: pages.dev tenant with no other strong signal.
        r = scan("https://elavor-brund-5d04be-trkt-crendal.pages.dev/")
        assert r["verdict"] == "MALICIOUS", (r["risk_score"], r["flags"])
        assert r["risk_score"] >= 80
        assert any("OpenPhish" in f for f in r["flags"])

    def test_feed_listing_overrides_reputable_age(self, feed_flagged):
        # A compromised AGED domain on the feed must not hide behind its age.
        feed_flagged["whois"] = {"registrar": "R", "created": "2009-01-01",
                                 "age": "17 yr", "country": "TR", "age_days": 6300}
        r = scan("https://www.endustriyelkececi.com/ire/")
        assert r["verdict"] == "MALICIOUS"
        assert r["risk_score"] >= 80


class TestDomainOnlyFeedHit:
    """A bare-host listing on the Phishing.Database domain feed is a WEAKER
    claim than an exact-URL listing. The live feed carries 73 Tranco top-100k
    registrables (2026-07-27) — legitimate sites listed after a one-off
    compromise — so a host hit alone must floor at SUSPICIOUS and leave the
    MALICIOUS verdict to corroborated evidence."""

    def test_domain_hit_alone_is_suspicious_not_malicious(self, patched_sources):
        patched_sources["feeds"] = feed(
            "domain", "host quiet-unknown-domain.com listed on the "
                      "Phishing.Database domain feed")
        r = scan("https://quiet-unknown-domain.com/")
        assert r["verdict"] == "SUSPICIOUS", (r["risk_score"], r["flags"])
        assert 60 <= r["risk_score"] < 70

    def test_domain_hit_is_still_reported_in_the_flags(self, patched_sources):
        patched_sources["feeds"] = feed(
            "domain", "host quiet-unknown-domain.com listed on the "
                      "Phishing.Database domain feed")
        r = scan("https://quiet-unknown-domain.com/")
        assert any("Phishing.Database" in f for f in r["flags"])

    def test_domain_hit_plus_a_second_source_is_malicious(self, patched_sources):
        # Corroboration turns the weak hit into a conviction.
        patched_sources["feeds"] = feed("domain", "host listed on the "
                                                  "Phishing.Database domain feed")
        patched_sources["uh"] = src("flag", "listed (phishing)")
        r = scan("https://quiet-unknown-domain.com/")
        assert r["verdict"] == "MALICIOUS"


class TestSourcesList:
    """The sources table drives the dashboard grid and the PDF report. It must
    only ever name checks that actually ran — the PhishTank row was a stub
    that returned 'clean' for every URL without making a request."""

    def test_phishtank_is_gone_and_the_blocklist_is_listed(self, patched_sources):
        r = scan("https://an-ordinary-site.com/page")
        names = [s["name"] for s in r["sources"]]
        assert "PhishTank" not in names
        assert names == ["VirusTotal", "Safe Browsing", "URLHaus", "Community Blocklist"]

    def test_blocklist_row_reports_the_feed_result(self, patched_sources):
        patched_sources["feeds"] = feed("url", "listed on the OpenPhish URL feed")
        r = scan("https://elavor-brund-5d04be-trkt-crendal.pages.dev/")
        row = next(s for s in r["sources"] if s["name"] == "Community Blocklist")
        assert row["status"] == "flag"
        assert "OpenPhish" in row["detail"]


class TestMultiPartTldBlend:
    def test_multipart_tld_typosquat_is_malicious(self, patched_sources):
        # Live FN 2026-07-14 (twice in one run): robiox.com.py Roblox clone.
        r = scan("http://www.robiox.com.py/users/455012258686/profile/")
        assert r["verdict"] == "MALICIOUS", (r["risk_score"], r["flags"])
        assert any(f.startswith("Typosquatting") for f in r["flags"])


class TestGCSBucketTenancy:
    """storage.googleapis.com serves customer content like S3 — verified
    asymmetry: it was blanket provider-reputable, so a phishing kit in a GCS
    bucket was capped at SUSPICIOUS while the same kit in an S3 bucket
    escalated. Also guards the self-corroboration fixes: the 'google'/'amazon'
    in the PLATFORM hostname must not count as brand impersonation or as the
    financial value-word, or keyword gating on these tenants never engages."""

    def test_keyword_only_bucket_path_is_not_malicious(self, patched_sources):
        r = scan("https://storage.googleapis.com/secure-login-verify/"
                 "phishing-account-update.html")
        assert r["verdict"] in ("SAFE", "SUSPICIOUS")
        assert r["risk_score"] < 70

    def test_credential_harvest_kit_in_bucket_is_malicious(self, patched_sources):
        # The exact FN the asymmetry caused: a kit in a path-style GCS bucket.
        patched_sources["content"] = CREDENTIAL_HARVEST_KIT
        r = scan("https://storage.googleapis.com/account-portal/secure/login.html")
        assert r["verdict"] == "MALICIOUS"
        assert r["risk_score"] >= 78

    def test_kit_on_virtual_hosted_bucket_is_malicious(self, patched_sources):
        patched_sources["content"] = CREDENTIAL_HARVEST_KIT
        r = scan("https://evil-kit.storage.googleapis.com/login.html")
        assert r["verdict"] == "MALICIOUS"

    def test_blocklisted_bucket_is_malicious(self, patched_sources):
        patched_sources["gsb"] = src("flag", "SOCIAL_ENGINEERING")
        r = scan("https://storage.googleapis.com/some-bucket/file.html")
        assert r["verdict"] == "MALICIOUS"

    def test_s3_keyword_symmetry(self, patched_sources):
        # Mirror case: 'amazon' in s3.amazonaws.com must not self-corroborate.
        r = scan("https://kits.s3.amazonaws.com/secure-login-verify/"
                 "phishing-update.html")
        assert r["verdict"] in ("SAFE", "SUSPICIOUS")
        assert r["risk_score"] < 70


# ---------------------------------------------------------------------------
# Phase 1a — hostname entropy as a CORROBORATING signal
#
# The measured problem: 47 of run 4's 93 misses were one Cloudflare Pages
# campaign with machine-generated tenant labels, every URL pinned at exactly
# 34. The mechanism is the tenant corroboration gate — nothing non-lexical
# vouched for the page, so the lexical ML and the keyword channel were both
# dropped and the blend collapsed just under SUSPICIOUS.
#
# A random hostname label is real, non-lexical evidence about the page, so it
# satisfies that gate. It must NOT do anything else: it adds no points, so a
# random label with nothing else against it cannot move a verdict.
# ---------------------------------------------------------------------------

DGA_TENANT = "https://sp3ct-meslor-biz8-varnex-pisol.pages.dev"
PHISHY_PATH = "/secure-login-verify-account"


class TestHostnameEntropyCorroboration:
    def test_random_label_lets_the_lexical_channel_convict(self, patched_sources):
        """The 34-cluster: a DGA tenant serving a credential-flavoured path is
        no longer held under SUSPICIOUS by the corroboration gate."""
        r = scan(DGA_TENANT + PHISHY_PATH)
        assert r["risk_score"] >= agg.SUSPICIOUS_MIN
        assert r["verdict"] in ("SUSPICIOUS", "MALICIOUS")

    def test_random_label_alone_never_reaches_malicious(self, patched_sources):
        """
        The real invariant, corrected by measurement.

        The first draft of this test asserted that a random label alone must
        leave the verdict untouched. That is incompatible with the goal: ALL 52
        hosts of the recorded pages.dev cluster are bare-root URLs
        (http://0dp-p7u-hb0if-7l7mby-rz1.pages.dev/), so the hostname is the
        only evidence that exists. A signal that may never move those verdicts
        cannot catch them, and Phase 1a would be a no-op.

        So the honest constraint is the one that protects the false-positive
        rate: lexical evidence — a random hostname, a lexical ML opinion,
        path keywords — may reach SUSPICIOUS but never MALICIOUS. MALICIOUS
        stays reserved for non-lexical proof: reputation, credential
        harvesting, brand impersonation, a voting page.
        """
        r = scan(DGA_TENANT + "/")
        assert r["risk_score"] < agg.MALICIOUS_MIN
        assert r["verdict"] != "MALICIOUS"

    def test_ordinary_tenant_label_is_still_gated(self, patched_sources):
        """The paired control: identical path, human-chosen label. Without the
        entropy signal the gate still drops the lexical channels."""
        r = scan("https://octocat.github.io" + PHISHY_PATH)
        assert r["risk_score"] < agg.SUSPICIOUS_MIN
        assert r["verdict"] == "SAFE"

    def test_ci_preview_label_is_still_gated(self, patched_sources):
        """
        The false-positive caution ROAD_TO_90.md names: legitimate CI preview
        deploys and CDN nodes have machine-generated labels too. One hash token
        is not the DGA shape, so this host must behave exactly like any other
        ordinary tenant.
        """
        r = scan("https://ci-7f3a9b.vercel.app" + PHISHY_PATH)
        assert r["risk_score"] < agg.SUSPICIOUS_MIN
        assert r["verdict"] == "SAFE"

    def test_random_label_is_flagged_for_transparency(self, patched_sources):
        r = scan(DGA_TENANT + PHISHY_PATH)
        assert any("machine-generated hostname" in f for f in r["flags"])

    def test_entropy_corroborated_page_is_capped_at_suspicious(
            self, patched_sources):
        """
        Entropy re-opens the lexical channels; it must not hand them the whole
        verdict. Without this cap the DGA host above blends to 86 (MALICIOUS)
        purely on hostname shape plus path keywords.

        The cap matters more than it looks, because the lexical ML turns out to
        be SATURATED on this kind of URL — measured during this work, it returns
        0.9999 for ci-7f3a9b.vercel.app/secure-login-verify-account, a
        LEGITIMATE CI preview host. Its probability is not an independent second
        opinion, so a verdict must never rest on it alone.
        """
        r = scan(DGA_TENANT + PHISHY_PATH)
        assert agg.SUSPICIOUS_MIN <= r["risk_score"] < agg.MALICIOUS_MIN
        assert r["verdict"] == "SUSPICIOUS"

    def test_real_evidence_still_escalates_a_random_host(self, patched_sources):
        """The cap must not overreach: a DGA host running an actual credential
        harvesting kit is corroborated by more than its name and still convicts."""
        patched_sources["content"] = CREDENTIAL_HARVEST_KIT
        r = scan(DGA_TENANT + PHISHY_PATH)
        assert r["verdict"] == "MALICIOUS"
        assert r["risk_score"] >= 78

    def test_blocklisted_random_host_still_escalates(self, patched_sources):
        patched_sources["gsb"] = src("flag", "SOCIAL_ENGINEERING")
        r = scan(DGA_TENANT + "/")
        assert r["verdict"] == "MALICIOUS"
