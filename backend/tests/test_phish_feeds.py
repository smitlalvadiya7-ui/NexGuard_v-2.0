"""
Unit tests for apis/phish_feeds.py — community blocklist membership on the
scan path.

Two layers, deliberately weighted differently by the aggregator:

  * URL layer    — OpenPhish + the Phishing.Database ACTIVE links feed. An
                   exact (normalised) URL match is a CONFIRMED hit.
  * domain layer — the Phishing.Database ACTIVE domains feed. A host match is
                   a WEAKER signal, so it is guarded: the feed genuinely lists
                   shared platforms and legitimate-but-once-compromised sites
                   (sites.google.com and banrisul.com.br are both on the live
                   list, 2026-07-27), and flagging those would be a false
                   positive on every page they host.

Live FNs (2026-07-14 eval): 13 missed phish, most of them ON the OpenPhish
feed at scan time — the feed only powered /live-threats, never /scan.
"""

import asyncio
import os
import time

import pytest

from apis import phish_feeds


@pytest.fixture(autouse=True)
def _all_feeds_enabled(monkeypatch):
    """
    Exercise the feed MACHINERY with every feed switched on.

    The default deployment profile is `commercial`, which filters OpenPhish out
    of `active_feeds()` because its community feed is licensed for
    non-commercial use only. That is correct for a shipped build and wrong for
    this file: these tests are about fetching, caching, TTLs and matching, not
    about licensing, and several of them count feeds. The licence filter has its
    own coverage in tests/test_profile_gating.py.
    """
    import deployment_profile as dp

    monkeypatch.setenv("NEXGUARD_DEPLOYMENT_PROFILE", "noncommercial")
    dp.profile.cache_clear()
    yield
    dp.profile.cache_clear()


class _FakeResponse:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        return None


OPENPHISH_TEXT = """\
http://ntitwapp.wojiaogg.com/
https://elavor-brund-5d04be-trkt-crendal.pages.dev/
https://www.robiox.com.py/users/455012258686/profile/
http://58hpi8cz7gg1.id.wasmer.app/index2.php
"""

# Phishing.Database ACTIVE links — same shape, different upstream.
LINKS_TEXT = """\
# comment line the parser must skip
http://kit-host.tld/wp-admin/secure/login.php

https://0000gg.000webhostapp.com/yahoo/login.php
https://amazon.com
https://banrisul.com.br/
"""

# Phishing.Database ACTIVE domains — bare hosts, one per line. The last two
# are real entries from the live feed that MUST NOT flag.
DOMAINS_TEXT = """\
# comment
kit-host.tld
0000gg.000webhostapp.com
alice.blogspot.com
sites.google.com
banrisul.com.br
"""


def _feed_text(url: str) -> str:
    if "openphish" in url:
        return OPENPHISH_TEXT
    if "links" in url:
        return LINKS_TEXT
    if "domains" in url:
        return DOMAINS_TEXT
    raise AssertionError(f"unexpected feed url: {url}")


@pytest.fixture(autouse=True)
def isolated_cache(monkeypatch, tmp_path):
    """Every test in this module gets its own snapshot cache directory.

    Autouse and unconditional: a test that lets the module write to the real
    backend/data/feed_cache leaks a snapshot into later tests (a fetch-failure
    case then reads a cached snapshot and reports "clean" instead of
    "unavailable"), and pollutes the developer's checkout besides.
    """
    monkeypatch.setattr(phish_feeds, "_CACHE_DIR", tmp_path / "feed_cache")


@pytest.fixture
def fresh_feeds(monkeypatch):
    """Reset module state and stub every feed fetch with fixed content."""
    calls = {"n": 0}

    def fake_get(url, timeout=None):
        calls["n"] += 1
        return _FakeResponse(_feed_text(url))

    monkeypatch.setattr(phish_feeds.requests, "get", fake_get)
    monkeypatch.setattr(phish_feeds, "_sets", {})
    monkeypatch.setattr(phish_feeds, "_next_fetch", {})
    # The off-request-path refresh worker is a module global with a single-flight
    # guard, so a worker still alive from a previous test would make the next
    # test's refresh correctly no-op and fail for the wrong reason.
    monkeypatch.setattr(phish_feeds, "_refresh_worker", None)
    monkeypatch.delenv("NEXGUARD_DISABLE_FEEDS", raising=False)
    return calls


def _simulate_restart(monkeypatch):
    """Drop the in-memory snapshots, keeping the on-disk cache — what a fresh
    process sees."""
    monkeypatch.setattr(phish_feeds, "_sets", {})
    monkeypatch.setattr(phish_feeds, "_next_fetch", {})


def check(url):
    return asyncio.run(phish_feeds.check_phish_feeds(url))


# ---------------------------------------------------------------------------
# URL layer — exact (normalised) match, a confirmed hit
# ---------------------------------------------------------------------------

class TestUrlLayer:
    def test_openphish_url_flags_as_a_url_match(self, fresh_feeds):
        res = check("http://ntitwapp.wojiaogg.com/")
        assert res["status"] == "flag"
        assert res["match"] == "url"
        assert "OpenPhish" in res["detail"]

    def test_links_feed_url_flags_as_a_url_match(self, fresh_feeds):
        res = check("http://kit-host.tld/wp-admin/secure/login.php")
        assert res["status"] == "flag"
        assert res["match"] == "url"
        assert "Phishing.Database" in res["detail"]

    @pytest.mark.parametrize("variant", [
        "https://ntitwapp.wojiaogg.com/",       # scheme differs from feed entry
        "http://ntitwapp.wojiaogg.com",         # trailing slash differs
        "http://www.ntitwapp.wojiaogg.com/",    # www. differs
        "HTTP://NTITWAPP.WOJIAOGG.COM/",        # host case differs
    ])
    def test_normalized_variants_still_flag(self, fresh_feeds, variant):
        assert check(variant)["status"] == "flag"

    def test_unlisted_url_is_clean(self, fresh_feeds):
        res = check("https://example.com/")
        assert res["status"] == "clean"
        assert res["detail"] == "clean"
        assert res["match"] is None

    def test_comment_and_blank_lines_are_not_entries(self, fresh_feeds):
        assert check("http://comment/")["status"] == "clean"

    # The live Phishing.Database links feed lists Amazon's bare homepage. On
    # 2026-10-01 that made https://www.amazon.com read MALICIOUS 90 in the
    # test-pack batch: an exact URL listing counts as a confirmed source. A URL
    # entry with no path is a host listing in disguise, so it gets the same
    # top-site / established-site exemption as the domain layer.
    @pytest.mark.parametrize("url", [
        "https://www.amazon.com", "https://amazon.com/", "http://AMAZON.com",
        "https://banrisul.com.br",
    ])
    def test_a_bare_homepage_listing_never_convicts_a_top_site(self, fresh_feeds, url):
        assert check(url)["status"] == "clean"

    def test_a_bare_homepage_listing_still_convicts_an_ordinary_host(self, fresh_feeds):
        # ntitwapp.wojiaogg.com is listed with no path and is nobody's top site.
        assert check("http://ntitwapp.wojiaogg.com/")["match"] == "url"


# ---------------------------------------------------------------------------
# Domain layer — host match, a weaker signal, guarded against shared platforms
# ---------------------------------------------------------------------------

class TestDomainLayer:
    def test_listed_host_flags_any_path_as_a_domain_match(self, fresh_feeds):
        # The exact URL is NOT on any links feed — only the host is listed.
        res = check("http://kit-host.tld/some/other/page?a=1")
        assert res["status"] == "flag"
        assert res["match"] == "domain"
        assert "kit-host.tld" in res["detail"]

    def test_www_prefix_ignored_for_host_match(self, fresh_feeds):
        assert check("https://www.kit-host.tld/x")["match"] == "domain"

    def test_url_match_takes_precedence_over_domain_match(self, fresh_feeds):
        # kit-host.tld is on BOTH feeds; the exact-URL hit is the stronger
        # claim and must be the one reported.
        res = check("http://kit-host.tld/wp-admin/secure/login.php")
        assert res["match"] == "url"

    def test_subdomain_of_a_listed_host_does_not_flag(self, fresh_feeds):
        # Host matching is exact: a listed registrable never convicts its
        # subdomains, which is how one listed platform would take out every
        # tenant under it.
        assert check("http://login.kit-host.tld/")["status"] == "clean"

    def test_tenant_host_on_a_shared_platform_still_flags(self, fresh_feeds):
        # The tenant itself is listed — that is a real, specific listing.
        assert check("http://0000gg.000webhostapp.com/other")["match"] == "domain"
        assert check("http://alice.blogspot.com/")["match"] == "domain"

    def test_top_ranked_platform_host_is_never_convicted(self, fresh_feeds):
        # sites.google.com IS on the live Phishing.Database domain feed.
        # Flagging it would mark every Google Sites page as phishing.
        assert check("https://sites.google.com/view/a-real-company")["status"] == "clean"

    def test_established_site_on_the_feed_is_never_convicted(self, fresh_feeds):
        # banrisul.com.br (a real Brazilian bank) is on the live feed too.
        assert check("https://banrisul.com.br/login")["status"] == "clean"


# ---------------------------------------------------------------------------
# Refresh, failure modes and the kill switch
# ---------------------------------------------------------------------------

class TestFeedRefresh:
    def test_each_feed_fetched_once_within_ttl(self, fresh_feeds):
        check("https://example.com/")
        check("https://example.org/")
        check("http://ntitwapp.wojiaogg.com/")
        assert fresh_feeds["n"] == len(phish_feeds.FEEDS)

    def test_background_warm_loads_the_snapshot_off_the_request_path(self, fresh_feeds):
        # The live links feed is ~63 MB and takes over a minute cold. Without a
        # warm at startup every scan in that window silently loses the source,
        # because the per-scan budget gives up long before the fetch lands.
        worker = phish_feeds.warm_in_background()
        worker.join(timeout=30)
        assert not worker.is_alive()
        assert fresh_feeds["n"] == len(phish_feeds.FEEDS)
        # The snapshot is already warm, so the scan itself refetches nothing.
        assert check("http://ntitwapp.wojiaogg.com/")["status"] == "flag"
        assert fresh_feeds["n"] == len(phish_feeds.FEEDS)


class TestDiskSnapshotCache:
    """Local runs restart constantly (uvicorn --reload). Re-downloading ~74 MB
    and waiting ~90 s for the blocklist on every restart is unusable, so a
    successful fetch is persisted and reloaded until its TTL expires."""

    def test_a_successful_fetch_is_persisted(self, fresh_feeds):
        check("https://example.com/")
        cached = list((phish_feeds._CACHE_DIR).glob("*.bin"))
        assert len(cached) == len(phish_feeds.FEEDS)
        assert all(f.stat().st_size > 0 for f in cached)

    def test_a_restart_loads_from_disk_without_refetching(self, fresh_feeds, monkeypatch):
        check("https://example.com/")
        assert fresh_feeds["n"] == len(phish_feeds.FEEDS)

        _simulate_restart(monkeypatch)
        assert check("http://ntitwapp.wojiaogg.com/")["status"] == "flag"
        assert check("http://kit-host.tld/some/other/page")["match"] == "domain"
        assert fresh_feeds["n"] == len(phish_feeds.FEEDS), "refetched despite a warm cache"

    def test_a_stale_snapshot_is_refetched(self, fresh_feeds, monkeypatch):
        check("https://example.com/")
        # Age every snapshot past the longest TTL.
        oldest = time.time() - max(f.ttl for f in phish_feeds.FEEDS) - 60
        for f in phish_feeds._CACHE_DIR.glob("*.bin"):
            os.utime(f, (oldest, oldest))

        _simulate_restart(monkeypatch)
        check("https://example.com/")
        assert fresh_feeds["n"] == 2 * len(phish_feeds.FEEDS)

    def test_a_corrupt_snapshot_is_ignored_and_refetched(self, fresh_feeds, monkeypatch):
        check("https://example.com/")
        for f in phish_feeds._CACHE_DIR.glob("*.bin"):
            f.write_bytes(b"not a digest blob")      # length is not a multiple of 8

        _simulate_restart(monkeypatch)
        assert check("http://ntitwapp.wojiaogg.com/")["status"] == "flag"
        assert fresh_feeds["n"] == 2 * len(phish_feeds.FEEDS)

    def test_an_unwritable_cache_dir_does_not_break_the_check(self, fresh_feeds, monkeypatch):
        # A read-only deployment must still scan, just without the shortcut.
        def boom(*a, **kw):
            raise OSError("read-only file system")

        monkeypatch.setattr(phish_feeds.Path, "mkdir", boom)
        assert check("http://ntitwapp.wojiaogg.com/")["status"] == "flag"


class TestFeedFailureModes:
    def test_total_fetch_failure_is_unavailable_not_clean(self, monkeypatch):
        """
        A feed that could not be downloaded must report UNAVAILABLE, and must
        not flag.

        This asserted `status == "clean"` until 2026-07-28. That is what let a
        190,542-domain known-malicious corpus scan 73% SAFE: with no API keys
        loaded, every source returned "clean" and the sources table showed a
        clean bill of health for checks that never ran. The neutrality is the
        part that mattered, so it is now asserted directly rather than implied
        by the word "clean".
        """
        def boom(url, timeout=None):
            raise OSError("network down")

        monkeypatch.setattr(phish_feeds.requests, "get", boom)
        monkeypatch.setattr(phish_feeds, "_sets", {})
        monkeypatch.setattr(phish_feeds, "_next_fetch", {})
        monkeypatch.delenv("NEXGUARD_DISABLE_FEEDS", raising=False)
        res = check("https://example.com/")
        assert res["status"] == "unavailable"
        assert res["detail"] == "unavailable"
        assert res["status"] != "flag", "an unreachable feed must never convict"
        assert res["match"] is None

    def test_one_dead_feed_does_not_silence_the_others(self, monkeypatch):
        def half_dead(url, timeout=None):
            if "openphish" in url:
                raise OSError("network down")
            return _FakeResponse(_feed_text(url))

        monkeypatch.setattr(phish_feeds.requests, "get", half_dead)
        monkeypatch.setattr(phish_feeds, "_sets", {})
        monkeypatch.setattr(phish_feeds, "_next_fetch", {})
        monkeypatch.delenv("NEXGUARD_DISABLE_FEEDS", raising=False)
        assert check("http://kit-host.tld/wp-admin/secure/login.php")["status"] == "flag"

    def test_kill_switch_also_skips_the_background_warm(self, monkeypatch):
        # main.py warms at import time; the suite (and any eval run) sets the
        # kill switch, so importing the app must not pull ~74 MB of feeds.
        calls = {"n": 0}

        def counting_get(url, timeout=None):
            calls["n"] += 1
            return _FakeResponse(_feed_text(url))

        monkeypatch.setattr(phish_feeds.requests, "get", counting_get)
        monkeypatch.setattr(phish_feeds, "_sets", {})
        monkeypatch.setattr(phish_feeds, "_next_fetch", {})
        monkeypatch.setenv("NEXGUARD_DISABLE_FEEDS", "1")
        phish_feeds.warm_in_background().join(timeout=10)
        assert calls["n"] == 0

    def test_kill_switch_disables_without_fetching(self, monkeypatch):
        def boom(url, timeout=None):  # must never be called
            raise AssertionError("fetched despite kill switch")

        monkeypatch.setattr(phish_feeds.requests, "get", boom)
        monkeypatch.setattr(phish_feeds, "_next_fetch", {})
        monkeypatch.setenv("NEXGUARD_DISABLE_FEEDS", "1")
        res = check("http://ntitwapp.wojiaogg.com/")
        # "unavailable", not "clean": the switch is off, so this check produced
        # no opinion at all — it did not look and find nothing.
        assert res == {"status": "unavailable", "detail": "disabled", "match": None}


# ---------------------------------------------------------------------------
# A TTL refresh must never run inline on a scan.
#
# Measured 2026-07-27: check_phish_feeds awaited _refresh_if_due_sync on EVERY
# scan. warm_in_background() only covers the first load at startup, so once the
# 24 h TTL on the ~63 MB links feed expired during normal operation, the next
# scan to arrive pulled the whole file inside the request path. Every concurrent
# scan then competed with that download for bandwidth: page-content fetches
# starved, the content model stopped voting, and recall collapsed from 73% to
# 40% for the duration of the refresh. In production that is a daily,
# minutes-long halving of detection quality.
#
# The module already supports stale-ok reads, so a scan must answer from the
# snapshot it has and hand the refresh to a background worker.
# ---------------------------------------------------------------------------

class TestTtlRefreshStaysOffTheRequestPath:
    def test_scan_does_not_block_on_a_due_refresh(self, fresh_feeds, monkeypatch):
        import asyncio
        import time

        # A snapshot exists but every feed is due for refresh.
        asyncio.run(phish_feeds.check_phish_feeds("https://example.com/"))
        monkeypatch.setattr(phish_feeds, "_next_fetch", {})

        slow_calls = []

        def slow_refresh():
            slow_calls.append(time.monotonic())
            time.sleep(3.0)          # stands in for the 63 MB download

        monkeypatch.setattr(phish_feeds, "_refresh_if_due_sync", slow_refresh)

        t0 = time.monotonic()
        asyncio.run(phish_feeds.check_phish_feeds("https://example.com/"))
        elapsed = time.monotonic() - t0

        assert elapsed < 1.0, (
            f"check_phish_feeds blocked {elapsed:.1f}s on a due refresh — a TTL "
            "expiry must not stall the scan that happens to trigger it"
        )

    def test_a_due_refresh_is_still_started(self, fresh_feeds, monkeypatch):
        """Off the request path, not skipped: the snapshot must still refresh."""
        import asyncio
        import threading
        import time

        asyncio.run(phish_feeds.check_phish_feeds("https://example.com/"))
        monkeypatch.setattr(phish_feeds, "_next_fetch", {})

        started = threading.Event()
        monkeypatch.setattr(phish_feeds, "_refresh_if_due_sync", started.set)

        asyncio.run(phish_feeds.check_phish_feeds("https://example.com/"))
        assert started.wait(timeout=5.0), "a due refresh must still be triggered"

    def test_concurrent_scans_trigger_only_one_refresh(self, fresh_feeds, monkeypatch):
        """A burst of traffic must not launch a download per request."""
        import asyncio
        import time

        asyncio.run(phish_feeds.check_phish_feeds("https://example.com/"))
        monkeypatch.setattr(phish_feeds, "_next_fetch", {})

        calls = []

        def counting_refresh():
            calls.append(1)
            time.sleep(0.5)

        monkeypatch.setattr(phish_feeds, "_refresh_if_due_sync", counting_refresh)

        async def burst():
            await asyncio.gather(*[
                phish_feeds.check_phish_feeds(f"https://example.com/{i}")
                for i in range(12)
            ])

        asyncio.run(burst())
        time.sleep(1.0)
        assert len(calls) <= 1, (
            f"{len(calls)} refreshes started for 12 concurrent scans — one "
            "in-flight refresh must serve them all"
        )
