"""
Phase 1a — hostname entropy (ROAD_TO_90.md).

Why this module exists, from measurement rather than intuition: 47 of the 93
misses in post-fix benchmark run 4 were a single Cloudflare Pages campaign whose
tenant labels are machine-generated —

    sp3ct-meslor-biz8-varnex-pisol.pages.dev
    77v-bqgb7-8074z-cy9gp-q6su.pages.dev
    qtwiz553bf-vlypxskru-1d8c3f-fyn9t.pages.dev

— every one of them pinned at exactly 34, six points under SUSPICIOUS. One
feature separates that shape from every legitimate hostname: legitimate labels
are pronounceable and dictionary-ish, these are not.

The two cautions from the plan are tested here as hard requirements, not
aspirations:

  * Some LEGITIMATE hosts have random labels — CI preview deploys, CDN nodes
    (ci-7f3a9b.vercel.app). One hash-looking token must never be enough.
  * The false-positive rate bought in Phase 0 (0.74%) must not be spent here,
    so `test_tranco_labels_are_overwhelmingly_not_random` calibrates the
    threshold against 5000 real Tranco labels with the established-domain
    exemption deliberately bypassed.
"""

import json
from pathlib import Path
from urllib.parse import urlparse

import pytest

import hostname_entropy as he


# --- the measured miss cluster --------------------------------------------

# Verbatim from docs/Detection_Accuracy_Audit/ROAD_TO_90.md §1b — real hosts
# from the OpenPhish feed on 2026-07-27, all scored 34 by the pipeline.
DGA_HOSTS = [
    "sp3ct-meslor-biz8-varnex-pisol.pages.dev",
    "77v-bqgb7-8074z-cy9gp-q6su.pages.dev",
    "qtwiz553bf-vlypxskru-1d8c3f-fyn9t.pages.dev",
]


@pytest.mark.parametrize("host", DGA_HOSTS)
def test_dga_tenant_label_is_random(host):
    """The 34-cluster is exactly what this feature exists to separate."""
    assert he.is_random_hostname(host) is True


# The same campaign's second shape: PRONOUNCEABLE nonsense. Every token obeys
# consonant-vowel-consonant rules, so no single token looks machine-generated —
# what gives it away is five tokens in a row and not one real word among them.
PRONOUNCEABLE_NONSENSE_HOSTS = [
    "sp25ct7-belnor-biz-havsen-kolrik.pages.dev",
    "sp25ct7-warnor-biz-kemsen-favlor.pages.dev",
    "sp29ct-qarnel-biz-mostik-havqen.pages.dev",
    "sp29ct-lomqak-biz-hentor-prasvik.pages.dev",
]


@pytest.mark.parametrize("host", PRONOUNCEABLE_NONSENSE_HOSTS)
def test_pronounceable_nonsense_campaign_is_random(host):
    assert he.is_random_hostname(host) is True


@pytest.mark.parametrize("host", DGA_HOSTS)
def test_dga_verdict_names_its_evidence(host):
    """A signal that changes a verdict has to be explainable in the flags."""
    res = he.hostname_randomness(host)
    assert res["random"] is True
    assert res["reason"]
    assert res["label"] in host


# --- the false-positive cautions the plan names ---------------------------

LEGITIMATE_RANDOMISH_HOSTS = [
    # CI preview deploys / CDN nodes: one hash token is normal and legitimate.
    "ci-7f3a9b.vercel.app",
    "deploy-preview-42.netlify.app",
    "pr-1234-abc123.onrender.com",
    "d1a2b3c4e5f6g7.cloudfront.net",
]


@pytest.mark.parametrize("host", LEGITIMATE_RANDOMISH_HOSTS)
def test_single_hash_token_is_not_random(host):
    """A lone machine-generated token is a build ID, not a DGA label."""
    assert he.is_random_hostname(host) is False


ORDINARY_TENANT_HOSTS = [
    "octocat.github.io",
    "my-portfolio.pages.dev",
    "nexguard-docs.pages.dev",
    "smit-resume-site.vercel.app",
    "team-handbook.gitbook.io",
    "invoice-generator.netlify.app",
]


@pytest.mark.parametrize("host", ORDINARY_TENANT_HOSTS)
def test_ordinary_tenant_label_is_not_random(host):
    assert he.is_random_hostname(host) is False


@pytest.mark.parametrize("host", [
    "vseinstrumenti.ru",     # real Tranco site, consonant-heavy transliteration
    "beget.ru",
    "smotrim.ru",
    "bbc.com",
    "www.hdfcbank.com",
])
def test_established_registrable_is_never_random(host):
    """
    A host whose registrable is in the Tranco top-100k snapshot IS the real
    site. Non-English and transliterated labels look statistically odd
    (vseinstrumenti has a 4-consonant run) and would otherwise be the first
    false positives this feature produced.
    """
    assert he.is_random_hostname(host) is False


# --- what is actually being measured -------------------------------------

def test_analysed_label_is_the_tenant_label_not_the_platform():
    """
    On shared hosting the platform suffix is chosen by Cloudflare, not the
    attacker. Measuring 'pages.dev' would add the same constant to every
    tenant and wash the signal out.
    """
    assert he.analysed_label("sp3ct-meslor-biz8-varnex-pisol.pages.dev") == \
        "sp3ct-meslor-biz8-varnex-pisol"


def test_analysed_label_is_the_registrable_label_off_shared_hosting():
    assert he.analysed_label("login.qtwiz553bf.com") == "qtwiz553bf"


def test_analysed_label_ignores_www():
    assert he.analysed_label("www.hdfcbank.com") == "hdfcbank"


def test_features_report_the_documented_measurements():
    """The seven features ROAD_TO_90.md Phase 1a specifies."""
    f = he.label_features("sp3ct-meslor-biz8-varnex-pisol")
    assert set(f) >= {
        "entropy", "digit_ratio", "hyphen_count", "token_count",
        "mean_token_length", "dict_word_ratio", "max_consonant_run",
    }
    assert f["hyphen_count"] == 4
    assert f["token_count"] == 5
    assert f["dict_word_ratio"] == 0.0


def test_digit_ratio_counts_digits_in_the_label():
    # 9 digits (7,7 · 7 · 8,0,7,4 · 9 · 6) across 26 characters.
    f = he.label_features("77v-bqgb7-8074z-cy9gp-q6su")
    assert f["digit_ratio"] == pytest.approx(9 / 26, abs=1e-3)


def test_dictionary_tokens_are_recognised():
    f = he.label_features("secure-login-account")
    assert f["dict_word_ratio"] == 1.0


def test_compound_of_two_words_is_a_dictionary_token():
    """'cloudbank' is in no word list, but it decomposes into two words that
    are — which is exactly how a human names things."""
    assert he.label_features("cloudbank")["dict_word_ratio"] == 1.0


def test_token_that_merely_starts_with_a_word_is_not_a_dictionary_token():
    """
    The tell that separates the pronounceable-nonsense campaign from real
    labels. 'warnor' opens with 'warn' and 'mostik' with 'most', but neither
    decomposes into words — treating a chance prefix as a dictionary hit let
    two campaign hosts through when this was substring matching.
    """
    f = he.label_features("sp25ct7-warnor-biz-kemsen-favlor")
    assert f["dict_word_ratio"] == 0.0


def test_common_web_vocabulary_is_recognised():
    """Words that show up constantly in legitimate tenant labels. Every entry
    can only make the detector more conservative."""
    for word in ("preview", "staging", "sandbox", "landing", "starter",
                 "template", "portal", "gateway", "wallet", "dashboard"):
        assert he.label_features(word)["dict_word_ratio"] == 1.0, word


def test_consonant_run_is_measured():
    assert he.label_features("vlypxskru")["max_consonant_run"] >= 4
    assert he.label_features("banana")["max_consonant_run"] == 1


# --- degenerate input -----------------------------------------------------

@pytest.mark.parametrize("host", ["", None, ".", "..", "localhost", "192.168.1.1"])
def test_degenerate_host_is_not_random(host):
    """Fail neutral: an unparseable host must never manufacture a signal."""
    assert he.is_random_hostname(host) is False


# --- calibration against real negatives ----------------------------------

def _tranco_labels(n: int) -> list[str]:
    """Labels of the first n registrables in the bundled Tranco top-100k."""
    path = Path(he.__file__).resolve().parent / "data" / "established_domains.txt"
    out = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        label = he.analysed_label(line)
        if label:
            out.append(label)
        if len(out) >= n:
            break
    return out


def _audit_data(name: str) -> dict:
    path = (Path(he.__file__).resolve().parents[1]
            / "docs" / "Detection_Accuracy_Audit" / "data" / name)
    return json.loads(path.read_text(encoding="utf-8"))


def test_no_false_positive_on_the_benchmark_legit_corpus():
    """
    The Phase 1a gate, pinned to the corpus it was promised on.

    Phase 0 bought the false-positive rate down to 0.74% and the plan is
    explicit that Phase 1a must not spend it. This scores the exact 216 URLs of
    the benchmark's legit corpus (recorded in legit_dist.json): not one may
    look machine-generated.

    That makes the false-positive guarantee STRUCTURAL rather than statistical.
    The aggregator change is inert unless is_random_hostname() fires, so if it
    fires on none of these hosts, none of their scores can move and the
    measured FPR is unchanged by construction.
    """
    hosts = [urlparse(u).hostname or "" for u in _audit_data("legit_dist.json")["scores"]]
    assert len(hosts) == 216, "legit corpus snapshot changed — re-measure the gate"
    flagged = [h for h in hosts if he.is_random_hostname(h)]
    assert flagged == []


def test_the_recorded_miss_cluster_is_separated():
    """
    The other half of the gate: the 34-cluster has to actually be caught.

    Scores the pages.dev hosts recorded as misses in post-fix run 4. This is
    the measurement Phase 1a exists to move, so it is a test rather than a
    number in a document that can quietly stop being true.
    """
    misses = _audit_data("postfix_run4_conc6.json")["arms"]["D_own_plus_PDB"]["misses"]
    cluster = [urlparse(u).hostname or "" for u in misses
               if (urlparse(u).hostname or "").endswith(".pages.dev")]
    assert len(cluster) == 52
    caught = [h for h in cluster if he.is_random_hostname(h)]
    assert len(caught) >= 50, f"only {len(caught)}/52 separated"


def test_tranco_labels_are_overwhelmingly_not_random():
    """
    Threshold calibration, and the guard on Phase 0's false-positive rate.

    Scores 5000 real Tranco labels through the RAW scorer, bypassing the
    established-domain exemption that would otherwise make this trivially
    pass — so it measures the thresholds themselves. Legitimate labels of
    every language are in here; if more than 1% of them look random, the
    thresholds are wrong and this feature would cost more in false positives
    than it gains in recall.
    """
    labels = _tranco_labels(5000)
    assert len(labels) >= 1000, "Tranco snapshot missing — cannot calibrate"
    flagged = [lab for lab in labels
               if he.label_randomness_score(lab) >= he.RANDOM_SCORE_MIN]
    rate = len(flagged) / len(labels)
    assert rate <= 0.01, (
        f"{rate:.2%} of real Tranco labels scored as random "
        f"(limit 1%); examples: {flagged[:20]}"
    )
