"""
M1 — honest benchmark selection in eval/realworld_eval.py.

The legit corpus comes from DEEPER Tranco ranks (default 2000-10000) and must
never contain a famous-domain-exemption domain (those scan SAFE by design, so
they would pad the benchmark). The phish corpus must never contain a URL that
is in the training dataset, and both corpora only draw from the "eval" half of
the permanent hash split.
"""

import pytest

rw = pytest.importorskip("eval.realworld_eval")

from top_domains import TOP_DOMAINS  # noqa: E402


def _fake_ranked(n=12000):
    """Rank-ordered fake Tranco list whose first 1000 are the REAL exemption
    domains (like the real list) and the rest are synthetic."""
    top = sorted(TOP_DOMAINS)[:1000]
    rest = [f"deep{i}.example" for i in range(len(top) + 1, n + 1)]
    return top + rest


def test_eval_legit_avoids_exemption_and_stays_deep():
    domains = _fake_ranked()
    got = rw.select_eval_legit(domains, n=200, min_rank=2000, max_rank=10000)
    assert got
    assert not (set(got) & TOP_DOMAINS)          # no free passes in the benchmark
    for d in got:
        assert d.startswith("deep")              # nothing from the top ranks


def test_eval_legit_excludes_non_website_arpa_zone():
    # Tranco ranks by DNS traffic, so reverse-DNS infrastructure like
    # 142.in-addr.arpa appears in it — but .arpa is not a browsable website
    # namespace and doesn't belong in a user-facing benchmark.
    domains = _fake_ranked()
    domains[2500] = "142.in-addr.arpa"
    got = rw.select_eval_legit(domains, n=8000, min_rank=2000, max_rank=12000)
    assert "142.in-addr.arpa" not in got


def test_eval_legit_is_deterministic():
    domains = _fake_ranked()
    assert rw.select_eval_legit(domains, 100, 2000, 10000) == \
           rw.select_eval_legit(domains, 100, 2000, 10000)


def test_eval_phish_excludes_training_urls_and_train_half():
    from ml.dataset_utils import feed_split
    feed = [f"http://phish{i}.top/login" for i in range(200)]
    trained = set(feed[:50])                     # pretend these were trained on
    got = rw.select_eval_phish(feed, cap=500, training_urls=trained)
    assert got
    assert not (set(got) & trained)              # never benchmark training URLs
    assert all(feed_split(u) == "eval" for u in got)


def test_eval_phish_respects_cap():
    feed = [f"http://phish{i}.top/a" for i in range(400)]
    got = rw.select_eval_phish(feed, cap=20, training_urls=set())
    assert len(got) == 20


def test_load_training_urls_reads_the_dataset(tmp_path, monkeypatch):
    # isolate from the real dev DB — accepted-feedback union has its own tests
    # in test_active_learning.py (running pytest from backend/ sees scans.db)
    monkeypatch.setattr(rw, "accepted_feedback_urls", lambda: set())
    csv = tmp_path / "ds.csv"
    csv.write_text("url,status\nhttp://a.top/x,phishing\nhttps://b.com/,legitimate\n",
                   encoding="utf-8")
    urls = rw.load_training_urls(csv)
    assert urls == {"http://a.top/x", "https://b.com/"}
    # missing file fails safe to an empty set, never raises
    assert rw.load_training_urls(tmp_path / "missing.csv") == set()


# ---------------------------------------------------------------------------
# Audit finding 1 (2026-07-27) — the benchmark must not grade a feed lookup.
#
# The phish corpus is built with fetch_openphish(), and apis/phish_feeds.py puts
# that SAME OpenPhish feed on the scan path as FEEDS[0]. Only training URLs were
# excluded, so every phishing URL in the benchmark was guaranteed to be in a
# blocklist the scanner reads: 19/19 of the graded set matched OpenPhish and
# 0/19 matched the independent Phishing.Database lists. The published 97.12%
# recall was measured with that loop closed (feed landed d51b7f3 2026-07-14,
# metrics generated 2026-07-18).
# ---------------------------------------------------------------------------

def test_scan_path_feed_state_is_recorded_in_the_payload():
    """A run's metrics must state whether the scan path had feed assistance."""
    assert hasattr(rw, "scan_path_feed_state"), (
        "realworld_eval must expose scan_path_feed_state() so every metrics "
        "payload records whether recall was measured with feed assistance"
    )


def test_feed_assist_is_disabled_by_default(monkeypatch):
    """
    Default must be the honest measurement: the corpus-source feed OFF, so
    recall reflects the engine rather than a lookup of the corpus itself.
    """
    monkeypatch.delenv("NEXGUARD_DISABLE_FEEDS", raising=False)
    args = rw.build_arg_parser().parse_args([])
    assert args.feed_assist is False, (
        "--feed-assist must default to False; a benchmark whose corpus comes "
        "from a scan-path feed cannot measure detection with that feed on"
    )


def test_feed_assist_flag_marks_the_result_as_circular(monkeypatch):
    monkeypatch.setenv("NEXGUARD_DISABLE_FEEDS", "")
    state = rw.scan_path_feed_state(feed_assist=True, phish_source="openphish")
    assert "circular" in state.lower(), (
        f"feed assistance over an openphish corpus must be labelled circular, got {state!r}"
    )


def test_honest_run_is_not_labelled_circular(monkeypatch):
    monkeypatch.setenv("NEXGUARD_DISABLE_FEEDS", "1")
    state = rw.scan_path_feed_state(feed_assist=False, phish_source="openphish")
    assert "circular" not in state.lower()
    assert "disabled" in state.lower()


# ---------------------------------------------------------------------------
# Infrastructure hostnames are not "legitimate websites"
#
# On 2026-07-29 the Tranco download failed and the harness fell back to Cisco
# Umbrella without saying so loudly. Umbrella ranks DNS TRAFFIC, so it is full
# of CDN and infrastructure names, and three of that run's four false positives
# were exactly that:
#
#     sandbox.itunes-apple.com.akadns.net
#     prod.do.dsp.mp.microsoft.com.edgekey.net
#     radarsubmissions.apple.com.akadns.net
#
# Nobody browses those. Grading them as legitimate websites measures nothing
# about phishing detection and inflates the false-positive rate — the same
# reason `.arpa` was already excluded.
# ---------------------------------------------------------------------------

INFRASTRUCTURE_HOSTS = [
    "sandbox.itunes-apple.com.akadns.net",
    "prod.do.dsp.mp.microsoft.com.edgekey.net",
    "radarsubmissions.apple.com.akadns.net",
    "e1234.dscx.akamaiedge.net",
    "a1.cdn.edgesuite.net",
    "something.trafficmanager.net",
    "d111111abcdef8.cloudfront.net",
    "host.1-2-3.deploy.static.akamaitechnologies.com",
]

BROWSABLE_HOSTS = [
    "unc.edu",
    "mofa.gov.sa",
    "teepublic.com",
    "oceanofpdf.com",
    "hu-berlin.de",
    "vseinstrumenti.ru",
    "akamai.com",          # the CDN VENDOR's own site is a real website
]


@pytest.mark.parametrize("host", INFRASTRUCTURE_HOSTS)
def test_infrastructure_hostnames_are_recognised(host):
    from eval.realworld_eval import is_infrastructure_host

    assert is_infrastructure_host(host) is True


@pytest.mark.parametrize("host", BROWSABLE_HOSTS)
def test_real_websites_are_not_mistaken_for_infrastructure(host):
    """The filter must not quietly shrink the corpus. Note akamai.com — the
    CDN vendor's own website is a website; only its edge nodes are not."""
    from eval.realworld_eval import is_infrastructure_host

    assert is_infrastructure_host(host) is False


def test_arpa_is_still_excluded():
    """The guard that already existed, kept in the same place."""
    from eval.realworld_eval import is_infrastructure_host

    assert is_infrastructure_host("1.0.0.127.in-addr.arpa") is True


def test_the_recorded_false_positives_are_filtered_out(monkeypatch):
    """
    Replay of the actual 2026-07-29 run, through the real selection function.

    sample_band applies the permanent hash split, so the assertion is that
    nothing infrastructural SURVIVES — not that everything else does.
    """
    from eval.realworld_eval import select_eval_legit

    corpus = INFRASTRUCTURE_HOSTS + BROWSABLE_HOSTS
    kept = select_eval_legit(corpus, n=len(corpus), min_rank=1, max_rank=len(corpus))
    assert not [h for h in kept if h in INFRASTRUCTURE_HOSTS]
