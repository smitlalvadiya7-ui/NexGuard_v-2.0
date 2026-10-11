"""
Phase 1 — the stored corpus (ROAD_TO_90.md).

The measurement that forced this: four benchmark runs of the SAME code gave
recall 73.5%, 73.6%, 37.6%, 38.4%. The cause was corpus composition, not code —
one campaign flooded the live feed on the day of the later runs. A one-shot run
against a live feed cannot measure detection quality, so every number
downstream of it is untrustworthy, including the original 64.3% baseline.

The fix is a corpus that is COLLECTED ONCE AND STORED. Requirements the plan
states, each pinned by a test here:

  * raw HTML + final URL + TLS metadata + fetch timestamp — stored, so features
    can be re-extracted later without re-fetching (phishing kits die in hours;
    a URL you did not capture today is gone tomorrow),
  * negatives too, including deliberately HARD ones — real bank logins are the
    critical case: password field, brand name, exactly like phishing,
  * a permanent hash-based train/eval split, the discipline dataset_utils
    already has,
  * idempotent, so a daily run costs one fetch per NEW url and re-running it
    never overwrites what was captured earlier.
"""

import asyncio
import json
from pathlib import Path

import pytest

from eval import corpus_collector as cc
from ml.dataset_utils import feed_split


# ---------------------------------------------------------------------------
# A fetcher that never touches the network. Injected, not monkeypatched: the
# collector takes its fetcher as an argument precisely so this is possible.
# ---------------------------------------------------------------------------

def fake_fetcher(pages):
    """pages: url -> dict(final_url=, status=, html=bytes, tls=dict) or an Exception."""
    calls = []

    async def _fetch(url, timeout=None):
        calls.append(url)
        page = pages.get(url)
        if isinstance(page, Exception):
            raise page
        if page is None:
            raise cc.FetchFailed("no route to host")
        return cc.Fetched(
            final_url=page.get("final_url", url),
            status_code=page.get("status", 200),
            html=page.get("html", b"<html></html>"),
            tls=page.get("tls", {}),
        )

    _fetch.calls = calls
    return _fetch


PHISH_URL = "http://sp3ct-meslor-biz8-varnex-pisol.pages.dev/"
PHISH_HTML = b"<html><body><form><input type=password></form></body></html>"

PAGES = {
    PHISH_URL: {
        "final_url": "https://sp3ct-meslor-biz8-varnex-pisol.pages.dev/login",
        "status": 200,
        "html": PHISH_HTML,
        "tls": {"issuer": "R3", "cert_age_days": 2, "is_free_ca": True},
    },
}


@pytest.fixture
def root(tmp_path):
    return tmp_path / "corpus"


def collect(root, urls, label, fetcher, **kw):
    return asyncio.run(cc.collect(urls, label=label, root=root,
                                  fetcher=fetcher, **kw))


# ---------------------------------------------------------------------------
# What a record has to carry
# ---------------------------------------------------------------------------

class TestRecordContents:
    def test_record_carries_every_field_the_plan_names(self, root):
        collect(root, [PHISH_URL], "phish", fake_fetcher(PAGES), source="openphish")
        rec = cc.load_records(root)[0]
        assert rec["url"] == PHISH_URL
        assert rec["final_url"].endswith("/login")
        assert rec["label"] == "phish"
        assert rec["source"] == "openphish"
        assert rec["fetched_at"].endswith("+00:00")
        assert rec["status_code"] == 200
        assert rec["tls"]["cert_age_days"] == 2

    def test_raw_html_is_stored_verbatim(self, root):
        """Stored so features can be re-extracted without re-fetching — the
        whole point, since the page will not exist next week."""
        collect(root, [PHISH_URL], "phish", fake_fetcher(PAGES))
        rec = cc.load_records(root)[0]
        assert cc.read_html(root, rec) == PHISH_HTML

    def test_final_url_is_recorded_separately_from_the_listed_url(self, root):
        """A kit that redirects is a different page from the URL the feed
        listed, and both matter."""
        collect(root, [PHISH_URL], "phish", fake_fetcher(PAGES))
        rec = cc.load_records(root)[0]
        assert rec["url"] != rec["final_url"]


# ---------------------------------------------------------------------------
# The permanent split
# ---------------------------------------------------------------------------

class TestPermanentSplit:
    def test_split_matches_the_existing_hash_partition(self, root):
        collect(root, [PHISH_URL], "phish", fake_fetcher(PAGES))
        rec = cc.load_records(root)[0]
        assert rec["split"] == feed_split(PHISH_URL)

    def test_split_is_stable_across_runs(self, root):
        assert cc.split_of(PHISH_URL) == cc.split_of(PHISH_URL)
        assert cc.split_of(PHISH_URL) in ("train", "eval")

    def test_records_can_be_read_back_by_split(self, root):
        collect(root, [PHISH_URL], "phish", fake_fetcher(PAGES))
        wanted = feed_split(PHISH_URL)
        assert len(cc.load_records(root, split=wanted)) == 1
        other = "train" if wanted == "eval" else "eval"
        assert cc.load_records(root, split=other) == []


# ---------------------------------------------------------------------------
# Idempotence — a daily job must not re-fetch or overwrite
# ---------------------------------------------------------------------------

class TestIdempotence:
    def test_second_run_does_not_refetch(self, root):
        f1 = fake_fetcher(PAGES)
        collect(root, [PHISH_URL], "phish", f1)
        f2 = fake_fetcher(PAGES)
        stats = collect(root, [PHISH_URL], "phish", f2)
        assert f2.calls == []
        assert stats["skipped"] == 1
        assert stats["collected"] == 0

    def test_first_capture_is_never_overwritten(self, root):
        """The capture is evidence with a timestamp. A later run seeing a
        different page must not silently replace what was recorded."""
        collect(root, [PHISH_URL], "phish", fake_fetcher(PAGES))
        before = cc.load_records(root)[0]
        changed = {PHISH_URL: {**PAGES[PHISH_URL], "html": b"<html>DEFACED</html>"}}
        collect(root, [PHISH_URL], "phish", fake_fetcher(changed))
        after = cc.load_records(root)[0]
        assert after["fetched_at"] == before["fetched_at"]
        assert cc.read_html(root, after) == PHISH_HTML


# ---------------------------------------------------------------------------
# Failure is data
# ---------------------------------------------------------------------------

class TestFailures:
    def test_dead_url_is_recorded_not_silently_dropped(self, root):
        """
        A phishing URL that is already taken down is a FACT about the feed's
        latency, and the benchmark needs it to separate 'missed' from 'dead'.
        Dropping it would quietly bias the corpus toward long-lived kits.
        """
        stats = collect(root, ["http://gone.example/"], "phish",
                        fake_fetcher({}))
        assert stats["failed"] == 1
        rec = cc.load_records(root, include_failed=True)[0]
        assert rec["error"]
        assert rec["status_code"] is None

    def test_failed_records_are_excluded_from_the_usable_corpus(self, root):
        collect(root, ["http://gone.example/"], "phish", fake_fetcher({}))
        assert cc.load_records(root) == []

    def test_one_failure_does_not_stop_the_run(self, root):
        stats = collect(root, ["http://gone.example/", PHISH_URL], "phish",
                        fake_fetcher(PAGES))
        assert stats["collected"] == 1
        assert stats["failed"] == 1

    def test_unknown_label_is_rejected(self, root):
        with pytest.raises(ValueError):
            collect(root, [PHISH_URL], "maybe-phish", fake_fetcher(PAGES))


# ---------------------------------------------------------------------------
# The negatives that decide whether any of this works
# ---------------------------------------------------------------------------

class TestHardNegatives:
    def test_real_bank_logins_are_in_the_hard_negative_set(self):
        """
        'Real bank login pages are the critical negatives: they have password
        fields and brand names, exactly like phishing. If your model cannot
        separate those, it is useless.'
        """
        hosts = " ".join(cc.HARD_NEGATIVES).lower()
        for bank in ("hdfcbank", "icicibank", "onlinesbi", "chase", "paypal"):
            assert bank in hosts, bank

    def test_hard_negatives_cover_every_category_the_plan_names(self):
        cats = {c for _, c in cc.HARD_NEGATIVE_ENTRIES}
        assert {"bank-login", "checkout", "govt-portal", "security-blog"} <= cats

    def test_hard_negatives_are_all_https_urls(self):
        assert all(u.startswith("https://") for u in cc.HARD_NEGATIVES)

    def test_hard_negatives_are_unique(self):
        assert len(cc.HARD_NEGATIVES) == len(set(cc.HARD_NEGATIVES))


# ---------------------------------------------------------------------------
# Layout on disk
# ---------------------------------------------------------------------------

class TestLayout:
    def test_records_are_one_json_file_per_url(self, root):
        collect(root, [PHISH_URL], "phish", fake_fetcher(PAGES))
        files = list((root / "records").rglob("*.json"))
        assert len(files) == 1
        assert json.loads(files[0].read_text(encoding="utf-8"))["url"] == PHISH_URL

    def test_record_id_is_stable_for_a_url(self):
        assert cc.record_id(PHISH_URL) == cc.record_id(PHISH_URL)
        assert cc.record_id(PHISH_URL) != cc.record_id(PHISH_URL + "x")

    def test_corpus_survives_a_missing_directory(self, root):
        assert cc.load_records(root) == []


# ---------------------------------------------------------------------------
# TLS metadata
#
# Regression: the collector's first implementation read the certificate with
# ctx.verify_mode = CERT_NONE and then called getpeercert() with no arguments —
# which returns an EMPTY dict when verification is disabled. Every record it
# wrote had "tls": {}, silently losing one of the four things the plan requires
# it to capture. Found by inspecting a live capture, not by a test, so here is
# the test: a real TLS handshake against a real self-signed certificate, served
# from localhost so the suite stays offline.
# ---------------------------------------------------------------------------

class TestTlsCapture:
    def test_certificate_fields_are_captured_from_a_real_handshake(self, tls_server):
        host, port = tls_server
        tls = cc.tls_metadata(f"https://{host}:{port}/")
        assert tls.get("has_cert") is True
        assert "NexGuard Test CA" in (tls.get("issuer") or "")
        assert isinstance(tls.get("cert_age_days"), int)
        assert tls.get("expires")

    def test_plain_http_has_no_certificate(self):
        assert cc.tls_metadata("http://example.invalid/") == {}

    def test_unreachable_host_fails_neutral(self):
        """A missing cert must never cost us the page capture."""
        assert cc.tls_metadata("https://127.0.0.1:1/") in ({}, None) or \
            cc.tls_metadata("https://127.0.0.1:1/").get("has_cert") is not True


# ---------------------------------------------------------------------------
# Storage cost
#
# This runs daily for weeks. A live capture of 37 pages took 8.8 MB, which
# extrapolates to ~2.6 GB over the two-week collection the plan calls for —
# enough to make people delete the corpus, which is the one thing that must not
# happen to it. HTML compresses ~5x.
# ---------------------------------------------------------------------------

class TestStorageCost:
    def test_stored_html_is_compressed(self, root):
        bulky = b"<html>" + b"<div class='row'>content</div>" * 2000 + b"</html>"
        pages = {PHISH_URL: {**PAGES[PHISH_URL], "html": bulky}}
        collect(root, [PHISH_URL], "phish", fake_fetcher(pages))
        rec = cc.load_records(root)[0]
        on_disk = cc.html_path(root, rec).stat().st_size
        assert on_disk < len(bulky) / 3, f"{on_disk} bytes vs {len(bulky)} raw"

    def test_compressed_html_reads_back_byte_identical(self, root):
        """Compression must be invisible: what went in is what comes out."""
        collect(root, [PHISH_URL], "phish", fake_fetcher(PAGES))
        rec = cc.load_records(root)[0]
        assert cc.read_html(root, rec) == PHISH_HTML

    def test_record_states_the_uncompressed_size(self, root):
        """html_bytes describes the PAGE, not the file — a later analysis
        comparing page sizes must not be reading compression ratios."""
        collect(root, [PHISH_URL], "phish", fake_fetcher(PAGES))
        assert cc.load_records(root)[0]["html_bytes"] == len(PHISH_HTML)
