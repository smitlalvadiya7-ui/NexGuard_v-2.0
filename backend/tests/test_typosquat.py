"""
Unit tests for apis/typosquat.py — provider self-impersonation exemption.

Verified FP class (2026-07-14 live eval): a provider's OWN infrastructure
domains were flagged as typosquats of their own brand (googletagmanager.com ->
"impersonates 'google' via brand_embedded, 72%"), because only the exact BRANDS
official registrables (googleapis.com, amazonaws.com, ...) were exempt.

Every PROVIDER_REPUTABLE_DOMAINS registrable must be exempt on the same
exact-registrable semantics as the officials short-circuit: leet, homoglyph or
embedded VARIANTS of a provider domain (g00glevideo.com,
googletagmanager-login.xyz) still flag.
"""

import pytest

from apis.typosquat import check_typosquatting


class TestProviderSelfImpersonationExempt:
    @pytest.mark.parametrize("domain", [
        "googletagmanager.com",
        "googlevideo.com",
        "googleusercontent.com",
        "microsoftonline.com",
        "apple-dns.net",
        "cloud.microsoft",                 # Microsoft's brand-TLD property
        "googledomains.com",
        "metrics.googletagmanager.com",    # subdomain of a provider domain
        "www.googlevideo.com",
    ])
    def test_provider_own_domain_is_not_a_typosquat(self, domain):
        res = check_typosquatting(domain)
        assert res["is_typosquat"] is False, res

    @pytest.mark.parametrize("domain", [
        "domains.google",      # googledomains.com redirect target (live FP 2026-07-14)
        "about.google",
        "learn.microsoft",
        "support.apple",
        "c.gle",               # Google notification redirector (live FP 2026-07-16, BUG 1)
        "forms.gle",           # Google Forms short links — same closed .gle TLD
        "goo.gle",
    ])
    def test_closed_brand_tld_is_first_party(self, domain):
        # .google/.microsoft/.apple/.gle are closed Spec-13 brand TLDs: only
        # the brand can register there, so every hostname is the brand's own.
        res = check_typosquatting(domain)
        assert res["is_typosquat"] is False, res


class TestFamousDomainsAreNotTyposquats:
    @pytest.mark.parametrize("domain", [
        "bbc.com",        # was flagged as a typosquat of 'hsbc' (eval FP 2026-07-16)
        "shopify.com",    # was flagged as a typosquat of 'spotify'
        "webex.com",
        "www.bbc.com",    # subdomain of a famous registrable
    ])
    def test_top_domain_is_first_party(self, domain):
        # A Tranco-top-1000 registrable IS the real site — it cannot be a
        # typosquat of some other brand (backend/data/top_domains.txt).
        res = check_typosquatting(domain)
        assert res["is_typosquat"] is False, res


class TestLookalikesOfProvidersStillFlag:
    @pytest.mark.parametrize("domain", [
        "g00glevideo.com",               # leetspeak variant of a provider domain
        "rnicrosoftonline.com",          # rn->m char swap
        "googletagmanager-login.xyz",    # brand embedded on an attacker domain
    ])
    def test_variant_still_flags(self, domain):
        res = check_typosquatting(domain)
        assert res["is_typosquat"] is True, res


class TestMultiPartTldRegistrable:
    """robiox.com.py (roblox typosquat, live FN 2026-07-14) was invisible:
    naive last-2-labels root extraction yielded 'com.py', so 'robiox' was
    never compared against any brand. Registrable parsing must use the PSL."""

    def test_robiox_com_py_flags_as_roblox(self):
        res = check_typosquatting("www.robiox.com.py")
        assert res["is_typosquat"] is True, res
        assert res["impersonated_brand"] == "roblox"

    def test_official_roblox_stays_clean(self):
        assert check_typosquatting("roblox.com")["is_typosquat"] is False

    def test_deep_cctld_brand_official_stays_clean(self):
        assert check_typosquatting("foo.barclays.co.uk")["is_typosquat"] is False

    def test_split_registrable_uses_psl(self):
        from apis.typosquat import _split_registrable
        assert _split_registrable("www.robiox.com.py") == ("robiox.com.py", "robiox")
        assert _split_registrable("foo.barclays.co.uk") == ("barclays.co.uk", "barclays")
        assert _split_registrable("cloud.microsoft") == ("cloud.microsoft", "cloud")
        assert _split_registrable("localhost") == ("localhost", "localhost")


class TestExistingBehaviourUnchanged:
    @pytest.mark.parametrize("domain", [
        "paypal-secure-login.xyz",
        "paypai.com",
        "rnicrosoft.com",
    ])
    def test_classic_typosquats_still_flag(self, domain):
        assert check_typosquatting(domain)["is_typosquat"] is True

    @pytest.mark.parametrize("domain", [
        "google.com",
        "amazon.co.uk",
        "apple.com",
        "googleapis.com",
    ])
    def test_official_brand_domains_stay_clean(self, domain):
        assert check_typosquatting(domain)["is_typosquat"] is False


class TestEstablishedBrandCcTlds:
    """BUG-4 (found by the honest benchmark, 2026-07-18): a brand's own
    foreign-country domain was convicted as a typosquat of the brand —
    dhl.de (DHL's GERMAN home domain) as 'lookalike of dhl' 88%, google.lt /
    google.com.gt as google lookalikes, casa.it as edit-distance-2 from
    'chase', microsoftazuread-sso.com as brand_embedded. An ESTABLISHED
    registrable (Tranco top-100k snapshot, data/established_domains.txt) is
    exonerated from the non-deception techniques; deception shapes
    (homoglyph / leetspeak) and unestablished brand-label ccTLDs still flag.
    """

    @pytest.mark.parametrize("domain", [
        "dhl.de",                       # exact brand label, real DHL domain
        "google.lt",
        "google.com.gt",
        "www.dhl.de",                   # subdomain of an established registrable
        "casa.it",                      # edit-distance-2 from 'chase', real site
        "microsoftazuread-sso.com",     # brand_embedded, real Microsoft infra
    ])
    def test_established_registrable_is_not_a_typosquat(self, domain):
        res = check_typosquatting(domain)
        assert res["is_typosquat"] is False, res

    @pytest.mark.parametrize("domain", [
        "dhl.gq",       # exact brand label on a free TLD, NOT established
        "dhl.tk",
        "chase.cf",
    ])
    def test_unestablished_brand_label_cctld_still_flags(self, domain):
        # The dhl.gq hole must stay closed: same lexical shape as dhl.de,
        # but no established traffic -> still a lookalike conviction.
        res = check_typosquatting(domain)
        assert res["is_typosquat"] is True, res
        assert res["technique"] == "lookalike"

    def test_deception_shapes_never_get_establishment_cover(self, monkeypatch):
        # Even if a leet/homoglyph domain somehow ranked (traffic from typos),
        # deliberate character deception is judged BEFORE establishment.
        import apis.typosquat as tsq
        monkeypatch.setattr(tsq, "is_established_registrable", lambda r: True)
        assert check_typosquatting("g00gle.com")["is_typosquat"] is True
        assert check_typosquatting("rnicrosoft.com")["is_typosquat"] is True

    def test_heuristic_impersonation_flag_skips_established(self):
        # Same BUG-4 class in the heuristic engine: microsoftazuread-sso.com
        # (Microsoft's real Azure-AD SSO domain, unresolvable on public DNS)
        # was still SUSPICIOUS 50 via "Possible impersonation: microsoft".
        from ai_engine import heuristic_scan
        flags = heuristic_scan("https://microsoftazuread-sso.com").get("flags", [])
        assert not any(f.startswith("Possible impersonation") for f in flags), flags
        # an unestablished brand-bearing domain still gets the flag
        flags2 = heuristic_scan("https://microsoft-account-verify.top").get("flags", [])
        assert any(f.startswith("Possible impersonation") for f in flags2), flags2

    def test_tenant_on_established_platform_never_inherits_rank(self):
        # blogspot.com is top-100k, but a tenant kit keeps its PSL-private
        # label — establishment must NOT silence the impersonation heuristic
        # for paypal-login.blogspot.com (naive last-2-labels root would).
        from ai_engine import heuristic_scan
        flags = heuristic_scan("https://paypal-login.blogspot.com").get("flags", [])
        assert any(f.startswith("Possible impersonation") for f in flags), flags
        from top_domains import is_established_registrable_host
        assert is_established_registrable_host("www.dhl.de") is True
        assert is_established_registrable_host("paypal-login.blogspot.com") is False
