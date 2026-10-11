"""
Feature-extractor contract for the retrained model (WORK_PLAN Task 3).

The hard rule of ml/features.py: every feature derives ONLY from the URL
string — deterministic, offline, identical at train and predict time.
The v2 additions (hashed char n-grams, graded TLD risk, extra lexical
scalars) must keep that contract.
"""

from ml.features import (
    FEATURE_NAMES,
    NGRAM_BUCKETS,
    extract_features,
    tld_risk,
)


def test_vector_matches_feature_names_and_is_deterministic():
    url = "http://paypal-secure-login-verify.xyz/account?id=123"
    v1 = extract_features(url)
    v2 = extract_features(url)
    assert len(v1) == len(FEATURE_NAMES)
    assert v1 == v2  # crc32 hashing — no per-process salt allowed


def test_ngram_buckets_present_and_react_to_content():
    ngram_names = [n for n in FEATURE_NAMES if n.startswith("ng_")]
    assert len(ngram_names) == NGRAM_BUCKETS
    a = extract_features("http://evil-login-verify.top/steal")
    b = extract_features("https://www.wikipedia.org/wiki/Cat")
    a_ng = a[-NGRAM_BUCKETS:]
    b_ng = b[-NGRAM_BUCKETS:]
    assert a_ng != b_ng  # different URLs hash to different bucket patterns
    assert sum(a_ng) > 0


def test_tld_risk_is_graded_not_binary():
    assert tld_risk("google.com") == 0
    assert tld_risk("example.org") == 0
    # heavily-abused TLDs score highest
    assert tld_risk("login-verify.tk") == 3
    assert tld_risk("account.top") == 3
    # watch-listed TLDs sit in between
    assert 1 <= tld_risk("promo.icu") <= 3
    # unknown/rare TLD is low but nonzero
    assert tld_risk("something.example") == 1


def test_new_lexical_scalars():
    names = set(FEATURE_NAMES)
    for expected in ("tld_risk", "length_path", "length_query", "nb_percent",
                     "has_punycode", "nb_path_segments", "max_digit_run"):
        assert expected in names, expected

    idx = {n: i for i, n in enumerate(FEATURE_NAMES)}
    v = extract_features("http://xn--pypal-4ve.com/a/b/c?x=1%20%20y=2")
    assert v[idx["has_punycode"]] == 1
    assert v[idx["nb_path_segments"]] == 3
    assert v[idx["nb_percent"]] == 2
    assert v[idx["length_query"]] == len("x=1%20%20y=2")

    v2 = extract_features("http://host1234567.com/")
    assert v2[idx["max_digit_run"]] == 7


def test_legacy_features_unchanged_in_order():
    # The first 24 features keep their layout so nothing silently shifts.
    assert FEATURE_NAMES[:24] == [
        "length_url", "length_hostname", "has_ip", "nb_dots", "nb_hyphens",
        "nb_at", "nb_qm", "nb_and", "nb_eq", "nb_underscore", "nb_slash",
        "nb_digits", "ratio_digits_url", "ratio_digits_host", "nb_subdomains",
        "prefix_suffix", "has_https", "is_shortener", "suspicious_tld",
        "domain_entropy", "nb_phish_hints", "brand_in_subdomain_or_path",
        "longest_word_host", "tld_in_path",
    ]
