"""
Two shippable builds from one codebase.

NexGuard sells a Premium tier through Stripe, which makes it a COMMERCIAL
product — and that disqualifies three of the sources the scanner leans on:

    VirusTotal Public API   "must not be used in commercial products or services"
    Safe Browsing v4        "for non-commercial use only" (Google says use Web Risk)
    OpenPhish community     non-commercial

The 96.7% catch rate measured against a known-malicious corpus on 2026-07-28 was
borrowed from exactly those APIs. Shipping it in a paid product would be a
licence violation, so the profile decides which sources may run:

    commercial      Web Risk, Phishing.Database, URLhaus, a user's OWN VT key
    noncommercial   all of the above plus VT public, Safe Browsing v4, OpenPhish

Two builds, one code path, one switch — because two branches drift and the one
that drifts is always the one nobody is measuring.

The default is COMMERCIAL. It fails closed: an unconfigured deployment declines
to use a source rather than silently violating its licence, and the cost of
that mistake is legal rather than technical.
"""

import pytest

import deployment_profile as dp


@pytest.fixture(autouse=True)
def _clean_profile(monkeypatch):
    # Set it explicitly rather than deleting it: deleting falls back to the
    # BUILD's default, which differs between the commercial and non-commercial
    # deliverables, and a test must not change meaning depending on which
    # folder it runs in.
    monkeypatch.setenv("NEXGUARD_DEPLOYMENT_PROFILE", "commercial")
    dp.profile.cache_clear()
    yield
    dp.profile.cache_clear()


# ---------------------------------------------------------------------------
# The switch
# ---------------------------------------------------------------------------

class TestProfileSelection:
    def test_the_unconfigured_default_is_a_real_profile(self, monkeypatch):
        """
        Fails closed, and states its identity.

        The default IS the difference between the two deliverables — v1 ships
        COMMERCIAL, v2 ships NONCOMMERCIAL — so this asserts the default is one
        of the two and that `describe()` agrees with it, rather than hard-coding
        one build's answer and failing in the other.
        """
        monkeypatch.delenv("NEXGUARD_DEPLOYMENT_PROFILE", raising=False)
        dp.profile.cache_clear()
        active = dp.profile()
        assert active in (dp.COMMERCIAL, dp.NONCOMMERCIAL)
        # Assert the BEHAVIOUR the default implies, not the wording of
        # describe() — an earlier version compared "NONCOMMERCIAL" against the
        # hyphenated display string "NON-COMMERCIAL" and failed in the v2 build
        # for a reason that had nothing to do with licensing.
        if active == dp.COMMERCIAL:
            assert dp.blocked_sources(), "a commercial build must block sources"
            assert dp.is_allowed("virustotal_public") is False
        else:
            assert dp.blocked_sources() == []
            assert dp.is_allowed("virustotal_public") is True

    def test_profile_comes_from_the_environment(self, monkeypatch):
        monkeypatch.setenv("NEXGUARD_DEPLOYMENT_PROFILE", "noncommercial")
        dp.profile.cache_clear()
        assert dp.profile() == dp.NONCOMMERCIAL

    def test_unknown_value_never_unlocks_restricted_sources(self, monkeypatch):
        """A typo must not quietly enable a non-commercial API. In the
        commercial build that means falling back to commercial; in the
        non-commercial build there is nothing to protect."""
        monkeypatch.delenv("NEXGUARD_DEPLOYMENT_PROFILE", raising=False)
        dp.profile.cache_clear()
        build_default = dp.profile()
        monkeypatch.setenv("NEXGUARD_DEPLOYMENT_PROFILE", "whatever")
        dp.profile.cache_clear()
        assert dp.profile() == build_default

    def test_value_is_case_and_space_insensitive(self, monkeypatch):
        monkeypatch.setenv("NEXGUARD_DEPLOYMENT_PROFILE", "  NonCommercial ")
        dp.profile.cache_clear()
        assert dp.profile() == dp.NONCOMMERCIAL


# ---------------------------------------------------------------------------
# What each profile may use
# ---------------------------------------------------------------------------

RESTRICTED = ("virustotal_public", "safe_browsing_v4", "openphish")
ALWAYS_OK = ("web_risk", "phishing_database", "urlhaus", "virustotal_user_key")


class TestCommercialProfile:
    @pytest.mark.parametrize("source", RESTRICTED)
    def test_non_commercial_sources_are_blocked(self, source):
        assert dp.is_allowed(source) is False

    @pytest.mark.parametrize("source", ALWAYS_OK)
    def test_commercially_licensed_sources_are_allowed(self, source):
        assert dp.is_allowed(source) is True

    def test_a_users_own_virustotal_key_is_allowed(self):
        """Bring-your-own-key is the user calling VirusTotal as themselves,
        under their own licence — not the product shipping a free key."""
        assert dp.is_allowed("virustotal_user_key") is True
        assert dp.is_allowed("virustotal_public") is False

    def test_blocked_sources_are_listable_for_the_operator(self):
        assert set(dp.blocked_sources()) == set(RESTRICTED)


class TestNonCommercialProfile:
    @pytest.fixture(autouse=True)
    def _noncommercial(self, monkeypatch):
        monkeypatch.setenv("NEXGUARD_DEPLOYMENT_PROFILE", "noncommercial")
        dp.profile.cache_clear()

    @pytest.mark.parametrize("source", RESTRICTED + ALWAYS_OK)
    def test_everything_is_allowed(self, source):
        assert dp.is_allowed(source) is True

    def test_nothing_is_blocked(self):
        assert dp.blocked_sources() == []


# ---------------------------------------------------------------------------
# The licence table is the point — it has to be readable and complete
# ---------------------------------------------------------------------------

class TestLicenceTable:
    def test_every_source_records_why_it_is_restricted(self):
        """A future reader must be able to check the claim without re-reading
        four vendors' terms of service."""
        for source in RESTRICTED:
            reason = dp.licence_note(source)
            assert reason and len(reason) > 20, source

    def test_an_unknown_source_is_refused_in_commercial(self):
        """Fail closed: a source nobody has reviewed is not cleared to ship."""
        assert dp.is_allowed("some_new_feed_nobody_vetted") is False

    def test_an_unknown_source_is_permitted_in_noncommercial(self, monkeypatch):
        monkeypatch.setenv("NEXGUARD_DEPLOYMENT_PROFILE", "noncommercial")
        dp.profile.cache_clear()
        assert dp.is_allowed("some_new_feed_nobody_vetted") is True

    def test_summary_names_the_profile_and_the_blocked_sources(self):
        text = dp.describe()
        assert "commercial" in text.lower()
        assert "virustotal" in text.lower()
