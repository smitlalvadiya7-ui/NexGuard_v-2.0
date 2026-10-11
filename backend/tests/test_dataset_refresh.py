"""
M1 — dataset refresh + honest eval sampling. Pure logic in ml/dataset_utils.py:
feed URL cleaning, the permanent hash-parity train/eval split (a URL or domain
can NEVER be in both the training set and the benchmark), deterministic
rank-band sampling for legit domains, and the dataset merge rules.
"""

import pytest

dataset_utils = pytest.importorskip("ml.dataset_utils")

from ml.dataset_utils import (  # noqa: E402
    clean_feed_urls,
    feed_split,
    merge_dataset,
    sample_band,
)


# ---------------------------------------------------------------------------
# clean_feed_urls
# ---------------------------------------------------------------------------

def test_clean_keeps_only_http_https_and_dedupes():
    lines = [
        " https://a.example/path ",
        "http://b.example/",
        "https://a.example/path",          # duplicate after strip
        "ftp://c.example/",                # wrong scheme
        "not a url",
        "",
    ]
    assert clean_feed_urls(lines) == ["https://a.example/path", "http://b.example/"]


def test_clean_drops_absurdly_long_urls():
    ok = "https://ok.example/" + "a" * 100
    huge = "https://huge.example/" + "a" * 3000
    assert clean_feed_urls([ok, huge]) == [ok]


def test_clean_respects_cap():
    lines = [f"https://s{i}.example/" for i in range(10)]
    assert len(clean_feed_urls(lines, cap=3)) == 3


def test_phishtank_csv_parsing():
    text = ("phish_id,url,phish_detail_url,submission_time,verified\n"
            "1,http://evil.top/login,http://d/1,2026-07-17,yes\n"
            "2,https://fake.example/pay,http://d/2,2026-07-17,yes\n"
            "3,not-a-url,http://d/3,2026-07-17,yes\n")
    from ml.dataset_utils import phishtank_urls_from_csv
    assert phishtank_urls_from_csv(text) == \
        ["http://evil.top/login", "https://fake.example/pay"]
    assert phishtank_urls_from_csv(text, cap=1) == ["http://evil.top/login"]
    assert phishtank_urls_from_csv("garbage") == []


# ---------------------------------------------------------------------------
# feed_split — permanent train/eval partition
# ---------------------------------------------------------------------------

def test_split_is_deterministic_and_binary():
    for item in ("https://x.example/a", "google.com", "http://phish.top/login"):
        first = feed_split(item)
        assert first in ("train", "eval")
        assert all(feed_split(item) == first for _ in range(5))


def test_split_is_roughly_balanced():
    n = 2000
    buckets = [feed_split(f"https://site{i}.example/p{i}") for i in range(n)]
    train_share = buckets.count("train") / n
    assert 0.4 < train_share < 0.6


def test_split_case_and_whitespace_insensitive():
    assert feed_split(" Google.COM ") == feed_split("google.com")


# ---------------------------------------------------------------------------
# sample_band — legit domains from deeper Tranco ranks
# ---------------------------------------------------------------------------

DOMAINS = [f"rank{i}.example" for i in range(1, 101)]   # index 0 = rank 1


def test_sample_band_stays_inside_the_band():
    got = sample_band(DOMAINS, n=10, min_rank=20, max_rank=60, exclude=set(), seed=42)
    assert len(got) == 10
    for d in got:
        rank = int(d.removeprefix("rank").removesuffix(".example"))
        assert 20 <= rank <= 60


def test_sample_band_never_returns_excluded_domains():
    exclude = {f"rank{i}.example" for i in range(1, 51)}
    got = sample_band(DOMAINS, n=20, min_rank=1, max_rank=100, exclude=exclude, seed=42)
    assert got
    assert not (set(got) & exclude)


def test_sample_band_is_deterministic():
    a = sample_band(DOMAINS, n=15, min_rank=10, max_rank=90, exclude=set(), seed=42)
    b = sample_band(DOMAINS, n=15, min_rank=10, max_rank=90, exclude=set(), seed=42)
    assert a == b
    c = sample_band(DOMAINS, n=15, min_rank=10, max_rank=90, exclude=set(), seed=7)
    assert a != c


def test_sample_band_short_band_returns_everything_available():
    got = sample_band(DOMAINS, n=50, min_rank=95, max_rank=100, exclude=set(), seed=42)
    assert sorted(got) == sorted(DOMAINS[94:100])


def test_sample_band_split_filter_partitions():
    train = sample_band(DOMAINS, n=100, min_rank=1, max_rank=100,
                        exclude=set(), seed=42, split="train")
    ev = sample_band(DOMAINS, n=100, min_rank=1, max_rank=100,
                     exclude=set(), seed=42, split="eval")
    assert train and ev
    assert not (set(train) & set(ev))                  # disjoint pools
    assert len(train) + len(ev) == 100
    assert all(feed_split(d) == "train" for d in train)


# ---------------------------------------------------------------------------
# merge_dataset
# ---------------------------------------------------------------------------

BASE = [
    ("http://old-phish.top/login", "phishing"),
    ("https://old-legit.com/about", "legitimate"),
]


def test_merge_appends_new_rows_and_counts():
    rows, added = merge_dataset(BASE, [("https://new.example/", "legitimate"),
                                       ("http://fresh.top/verify", "phishing")])
    assert added == 2
    assert len(rows) == 4
    assert ("http://fresh.top/verify", "phishing") in rows


def test_merge_existing_url_wins_over_addition():
    rows, added = merge_dataset(BASE, [("http://old-phish.top/login", "legitimate")])
    assert added == 0
    assert rows == BASE                                 # unchanged, base label kept


def test_merge_drops_new_legit_on_a_host_already_labeled_phishing():
    rows, added = merge_dataset(BASE, [("https://old-phish.top/", "legitimate")])
    assert added == 0
    assert all(status == "phishing" for url, status in rows if "old-phish" in url)


def test_merge_keeps_new_phish_even_on_a_known_legit_host():
    # a phishing page CAN live on a legit host (forms, tenants) — never drop it
    rows, added = merge_dataset(BASE, [("https://old-legit.com/phish-page", "phishing")])
    assert added == 1
    assert ("https://old-legit.com/phish-page", "phishing") in rows
