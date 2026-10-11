"""
NexGuard real-world evaluation harness  (standalone script)
===========================================================

Measures how the LIVE scanning pipeline (aggregator.full_scan) performs on real,
current data — not the held-out training split. Two corpora:

  LEGIT  — Tranco domains sampled from DEEPER ranks (default 2000-10000,
           deterministic seed) — NOT the top of the list, because the
           famous-domain exemption (backend/data/top_domains.txt, top-1000)
           makes those scan SAFE by design and would pad the benchmark
           (honesty fix, M1). Exemption-list domains are excluded outright.
           Plus a small hand-picked set of known-safe security / educational
           pages. Any of these flagged SUSPICIOUS or MALICIOUS is a FALSE
           POSITIVE.

  PHISH  — recent live phishing URLs from the OpenPhish and/or PhishTank feeds
           (capped). Any flagged SUSPICIOUS or MALICIOUS is a TRUE POSITIVE
           (a catch); one flagged SAFE is a FALSE NEGATIVE (a miss).

  Train/test hygiene (M1): both corpora keep only the "eval" half of the
  permanent hash split (ml.dataset_utils.feed_split), and any URL present in
  the training dataset (ml/raw_dataset.csv) is excluded from the phish corpus
  — the benchmark can never contain training data.

We treat "threat" (verdict in {SUSPICIOUS, MALICIOUS}) as the POSITIVE class and
report precision, recall, F1, false-positive rate, false-negative rate and the
median scan time — honestly, with the dataset sizes and the date.

Output: metrics_realworld.json (consumed by the Model Performance page) + a
printed summary.

Usage
-----
    python -m eval.realworld_eval                 # defaults: ~600 legit / 300 phish
    python -m eval.realworld_eval --legit 800 --phishing 250 --concurrency 16
    python -m eval.realworld_eval --legit 20 --phishing 20   # quick smoke run
    python -m eval.realworld_eval --offline       # bundled legit set only, no phish

Everything is fail-safe: feeds that don't download are skipped and the run
continues with whatever data it has, recording the true sizes used.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Make the backend package importable whether run as a module or a file.
_BACKEND = Path(__file__).resolve().parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from aggregator import full_scan  # noqa: E402
from eval.run_log import (  # noqa: E402
    append_run, format_report, load_runs, summarise,
)
from ml.dataset_utils import (  # noqa: E402
    fetch_openphish, fetch_phishtank, fetch_tranco, fetch_umbrella,
    feed_split, sample_band,
)
from top_domains import TOP_DOMAINS  # noqa: E402

OUT_PATH = _BACKEND / "metrics_realworld.json"
TRAIN_DATASET = _BACKEND / "ml" / "raw_dataset.csv"

# Known-safe security / educational pages — these legitimately contain security
# vocabulary ("phishing", "login", "malware") and so are a deliberately hard
# false-positive test for the heuristic/ML lexical signals.
SAFE_SECURITY_PAGES = [
    "https://www.virustotal.com",
    "https://www.phishtank.com",
    "https://owasp.org",
    "https://www.cisa.gov",
    "https://www.sans.org",
    "https://krebsonsecurity.com",
    "https://www.kaspersky.com/resource-center/threats/phishing",
    "https://support.google.com/accounts/answer/6010255",   # "avoid phishing"
    "https://www.ncsc.gov.uk/guidance/phishing",
    "https://us-cert.cisa.gov",
    "https://www.malwarebytes.com",
    "https://haveibeenpwned.com",
    "https://www.eff.org",
    "https://www.schneier.com",
    "https://portal.mdn.mozilla.org",
    "https://developer.mozilla.org/en-US/docs/Web/Security",
]

# Offline fallback legit domains (used only if every download fails).
FALLBACK_LEGIT = [
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "amazon.com",
    "microsoft.com", "apple.com", "github.com", "stackoverflow.com", "reddit.com",
    "netflix.com", "linkedin.com", "x.com", "instagram.com", "cloudflare.com",
    "mozilla.org", "wordpress.org", "adobe.com", "office.com", "live.com",
    "yahoo.com", "bing.com", "paypal.com", "dropbox.com", "spotify.com",
    "ibm.com", "oracle.com", "salesforce.com", "cisco.com", "intel.com",
    "nvidia.com", "samsung.com", "bbc.com", "cnn.com", "nytimes.com",
    "wikipedia.org", "twitch.tv", "ebay.com", "wellsfargo.com", "chase.com",
]

# ---------------------------------------------------------------------------
# Honest corpus selection (M1) — feed downloads live in ml.dataset_utils
# ---------------------------------------------------------------------------

# CDN edge nodes, reverse-DNS zones and traffic-management endpoints. Both
# Tranco and Umbrella rank DNS TRAFFIC, so these appear near the top — but
# nobody browses them, and grading one as a "legitimate website" measures
# nothing about phishing detection.
#
# Found the hard way on 2026-07-29: the Tranco download failed, the harness fell
# back to Umbrella, and three of that run's four false positives were
# sandbox.itunes-apple.com.akadns.net, radarsubmissions.apple.com.akadns.net and
# prod.do.dsp.mp.microsoft.com.edgekey.net. The false-positive rate went 0% ->
# 1.9% on corpus composition alone.
#
# Matched as a SUFFIX, so the CDN vendors' own websites (akamai.com,
# cloudflare.com) are unaffected — only their edge hostnames are.
_INFRASTRUCTURE_SUFFIXES = (
    ".arpa",                      # reverse DNS
    ".akadns.net", ".akamaiedge.net", ".akamaitechnologies.com",
    ".akamaized.net", ".edgekey.net", ".edgesuite.net",
    ".trafficmanager.net", ".cloudfront.net", ".azureedge.net",
    ".fastly.net", ".fastlylb.net", ".llnwd.net", ".footprint.net",
    ".cdn77.org", ".gslb.net", ".c.gle",
)


def is_infrastructure_host(host: str) -> bool:
    """
    True for a hostname that is plumbing rather than a website.

    Exclusion from the legit corpus, not from scanning: a CDN edge node can
    absolutely serve a phishing page, and the scanner still judges it. This
    only says such a host does not belong in a benchmark of "legitimate sites
    a person visits".
    """
    h = (host or "").lower().strip().rstrip(".")
    return bool(h) and h.endswith(_INFRASTRUCTURE_SUFFIXES)


def select_eval_legit(domains: list[str], n: int,
                      min_rank: int, max_rank: int) -> list[str]:
    """
    Deterministic legit sample from deeper ranks: never a famous-domain-
    exemption domain (those scan SAFE by design — benchmarking them proves
    nothing), never an infrastructure hostname (see is_infrastructure_host),
    and only the "eval" half of the permanent train/eval split.
    """
    got = sample_band(domains, n=n, min_rank=min_rank, max_rank=max_rank,
                      exclude=set(TOP_DOMAINS), seed=42, split="eval")
    return [d for d in got if not is_infrastructure_host(d)]


def select_eval_phish(feed_urls: list[str], cap: int,
                      training_urls: set[str]) -> list[str]:
    """Eval-half feed URLs that are NOT in the training dataset, capped."""
    out = [u for u in feed_urls
           if u not in training_urls and feed_split(u) == "eval"]
    return out[:cap]


def accepted_feedback_urls() -> set[str]:
    """
    URLs of admin-ACCEPTED verdict feedback (M3): retrain.py trains on them,
    so the benchmark may never contain them. Fail-safe empty set — note that
    db_config binds SQLite relative to the cwd, so run the eval from backend/
    (as documented) for this exclusion to see the real DB.
    """
    try:
        from db_config import SessionLocal
        from models import VerdictFeedback
        db = SessionLocal()
        try:
            rows = (db.query(VerdictFeedback.url)
                    .filter(VerdictFeedback.status == "accepted").all())
            return {(r[0] or "").strip() for r in rows if (r[0] or "").strip()}
        finally:
            db.close()
    except Exception:
        return set()


def load_training_urls(path=TRAIN_DATASET) -> set[str]:
    """Every URL any training pass has seen: the dataset CSV plus accepted
    feedback rows. Empty set when unreadable (the eval still runs)."""
    urls: set[str] = set()
    try:
        with open(path, encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.reader(f)
            header = next(reader, [])
            col = header.index("url") if "url" in header else 0
            urls = {row[col].strip() for row in reader if row and row[col].strip()}
    except Exception:
        pass
    try:
        urls |= accepted_feedback_urls()
    except Exception:
        pass
    return urls


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def _is_threat(verdict: str) -> bool:
    return (verdict or "").upper() in ("SUSPICIOUS", "MALICIOUS")


async def _scan_one(target: str, sem: asyncio.Semaphore, timeout: float) -> dict:
    """Scan a single target under a concurrency gate and a hard timeout."""
    async with sem:
        t0 = time.perf_counter()
        try:
            res = await asyncio.wait_for(full_scan(target), timeout=timeout)
            return {
                "target": target,
                "verdict": (res.get("verdict") or "ERROR").upper(),
                "score": int(res.get("risk_score", 0) or 0),
                "scan_time_ms": int(res.get("scan_time_ms")
                                    or round((time.perf_counter() - t0) * 1000)),
                "resolved_ip": res.get("resolved_ip"),
                # A live-feed phishing URL is frequently taken down before we scan
                # it: the host no longer resolves AND no page could be fetched.
                # Such "dead" targets can't be graded as a catch or a miss.
                "reachable": bool(res.get("resolved_ip")),
                "error": None,
            }
        except (asyncio.TimeoutError, Exception) as e:  # noqa: BLE001
            return {
                "target": target,
                "verdict": "ERROR",
                "score": 0,
                "scan_time_ms": int(round((time.perf_counter() - t0) * 1000)),
                "resolved_ip": None,
                "reachable": False,
                "error": type(e).__name__,
            }


async def scan_all(targets: list[str], concurrency: int, timeout: float,
                   label: str) -> list[dict]:
    sem = asyncio.Semaphore(concurrency)
    total = len(targets)
    print(f"  scanning {total} {label} URLs (concurrency={concurrency})…")
    results: list[dict] = []
    tasks = [asyncio.create_task(_scan_one(t, sem, timeout)) for t in targets]
    done = 0
    for fut in asyncio.as_completed(tasks):
        results.append(await fut)
        done += 1
        if done % 25 == 0 or done == total:
            print(f"    {label}: {done}/{total}")
    return results


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def compute_metrics(legit: list[dict], phish: list[dict]) -> dict:
    # Exclude ERROR scans from the corpus they couldn't be classified in, but
    # report how many there were for honesty.
    legit_ok = [r for r in legit if r["verdict"] != "ERROR"]
    phish_scored = [r for r in phish if r["verdict"] != "ERROR"]
    # Live-feed phishing URLs that are already DEAD (host doesn't resolve) can't
    # be fairly graded — the evidence is gone. Bucket them separately so the
    # catch rate reflects performance on URLs that were still UP at scan time.
    phish_dead = [r for r in phish_scored if not r.get("reachable")]
    phish_ok = [r for r in phish_scored if r.get("reachable")]

    # Positive class = "threat".
    tp = sum(1 for r in phish_ok if _is_threat(r["verdict"]))   # phish caught
    fn = sum(1 for r in phish_ok if not _is_threat(r["verdict"]))  # phish missed
    fp = sum(1 for r in legit_ok if _is_threat(r["verdict"]))   # legit wrongly flagged
    tn = sum(1 for r in legit_ok if not _is_threat(r["verdict"]))  # legit correct

    def safe_div(a, b):
        return (a / b) if b else 0.0

    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)            # == true-positive (catch) rate
    f1 = safe_div(2 * precision * recall, precision + recall)
    fpr = safe_div(fp, fp + tn)               # false-positive rate (on legit)
    fnr = safe_div(fn, fn + tp)               # false-negative (miss) rate (on phish)

    times = [r["scan_time_ms"] for r in (legit + phish) if r["scan_time_ms"] is not None]
    median_ms = int(statistics.median(times)) if times else None
    p95_ms = int(_percentile(times, 95)) if times else None

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "true_positive_rate": round(recall, 4),
        "median_scan_time_ms": median_ms,
        "p95_scan_time_ms": p95_ms,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "counts": {
            "legit_total": len(legit),
            "legit_scored": len(legit_ok),
            "legit_errors": len(legit) - len(legit_ok),
            "phish_total": len(phish),
            "phish_scored": len(phish_ok),            # live (reachable) phishing graded
            "phish_dead_excluded": len(phish_dead),   # taken down before scan
            "phish_errors": len(phish) - len(phish_scored),
        },
    }


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def run(args) -> dict:
    print("NexGuard real-world evaluation")
    print("=" * 60)

    # --- LEGIT corpus -----------------------------------------------------
    print("Building LEGIT corpus…")
    sources_used = {}
    legit_domains: list[str] = []
    band = f"ranks {args.legit_min_rank}-{args.legit_max_rank}"
    if not args.offline:
        ranked = fetch_tranco(args.legit_max_rank)
        source = "tranco"
        if not ranked:
            ranked = fetch_umbrella(args.legit_max_rank)
            source = "umbrella(fallback)"
        if ranked:
            legit_domains = select_eval_legit(
                ranked, args.legit, args.legit_min_rank, args.legit_max_rank)
            sources_used["legit"] = (f"{source}[{band}] sample={len(legit_domains)} "
                                     "seed=42 eval-half, top-1000 exemption excluded")
    if not legit_domains:
        legit_domains = list(FALLBACK_LEGIT)
        sources_used["legit"] = "bundled(fallback)"
    legit_targets = [f"https://{d}" for d in legit_domains] + SAFE_SECURITY_PAGES
    # de-dup, preserve order
    seen: set = set()
    legit_targets = [t for t in legit_targets if not (t in seen or seen.add(t))]
    print(f"  LEGIT: {len(legit_targets)} URLs (source: {sources_used['legit']}, "
          f"+{len(SAFE_SECURITY_PAGES)} security pages)")

    # --- PHISH corpus -----------------------------------------------------
    phish_targets: list[str] = []
    if not args.offline:
        print("Building PHISH corpus…")
        training_urls = load_training_urls()
        # Fetch extra: roughly half the feed belongs to the train split.
        feed = fetch_openphish(args.phishing * 3)
        source = "openphish"
        if not feed:
            feed = fetch_phishtank(args.phishing * 3)
            source = "phishtank(fallback)"
        if feed:
            phish_targets = select_eval_phish(feed, args.phishing, training_urls)
            dropped = len(feed) - len(phish_targets)
            sources_used["phish"] = (f"{source} eval-half, {dropped} train-half/"
                                     "already-trained URLs excluded")
        print(f"  PHISH: {len(phish_targets)} URLs "
              f"(source: {sources_used.get('phish', 'none')})")
    else:
        print("Offline mode: skipping phishing feeds.")

    if not phish_targets:
        print("  WARNING: no phishing URLs available — recall/precision will be partial.")

    # --- Scan -------------------------------------------------------------
    print("Scanning…")
    t0 = time.perf_counter()
    legit_res = await scan_all(legit_targets, args.concurrency, args.timeout, "legit")
    phish_res = await scan_all(phish_targets, args.concurrency, args.timeout, "phish") \
        if phish_targets else []
    wall_s = round(time.perf_counter() - t0, 1)

    # --- Metrics ----------------------------------------------------------
    metrics = compute_metrics(legit_res, phish_res)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evaluated_on_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "dataset_sources": sources_used,
        "wall_time_s": wall_s,
        "threat_positive_class": "verdict in {SUSPICIOUS, MALICIOUS}",
        # Audit finding 1 (2026-07-27): a recall figure is meaningless without
        # this. Travels with the metrics so the Model Performance page can never
        # display a circular number as if it were a detection result.
        "feed_assist": bool(getattr(args, "feed_assist", False)),
        # Which stack actually ran. Before 2026-07-28 this harness never loaded
        # backend/.env, so VirusTotal and Safe Browsing were silently absent
        # from every run while the output read as a measurement of the product.
        # Recording it means a later run cannot be compared against an earlier
        # one that measured something else.
        "intel_stack": intel_stack(),
        "scan_path_feeds": scan_path_feed_state(
            getattr(args, "feed_assist", False),
            sources_used.get("phish", "none"),
        ),
        **metrics,
        # A few example misses / false positives for qualitative review.
        "examples": {
            "false_positives": [r["target"] for r in legit_res if _is_threat(r["verdict"])][:15],
            "false_negatives": [r["target"] for r in phish_res if not _is_threat(r["verdict"])
                                and r["verdict"] != "ERROR" and r.get("reachable")][:15],
        },
    }

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    # Every run joins the permanent log. A single run cannot establish a recall
    # figure — four runs of identical code once spanned 73.5% to 37.6% on feed
    # composition alone — so the log tracks how many honest runs exist across
    # how many DAYS, and refuses to call the number quotable until there are
    # three of each. Appending is fail-safe: it never aborts a finished run.
    append_run(payload)
    _print_summary(payload, args.out)
    print()
    print(format_report(summarise(load_runs())))
    return payload


def _print_summary(p: dict, out_path) -> None:
    c = p["counts"]
    cm = p["confusion_matrix"]
    print("\n" + "=" * 60)
    print("REAL-WORLD EVALUATION RESULTS")
    print("=" * 60)
    print(f"Date evaluated     : {p['evaluated_on_date']}")
    print(f"Dataset sources    : {p['dataset_sources']}")
    print(f"Scan-path feeds    : {p.get('scan_path_feeds', 'unknown')}")
    print(f"Intel stack        : {p.get('intel_stack', 'unrecorded')}")
    if p.get("feed_assist") and "CIRCULAR" in (p.get("scan_path_feeds") or ""):
        print("  *** WARNING: this recall figure is CIRCULAR — the corpus came "
              "from a feed the\n      scanner reads. Re-run without --feed-assist "
              "for a detection measurement. ***")
    print(f"Legit scored       : {c['legit_scored']} (errors: {c['legit_errors']})")
    print(f"Phishing scored    : {c['phish_scored']} live "
          f"(dead/taken-down excluded: {c.get('phish_dead_excluded', 0)}, "
          f"errors: {c['phish_errors']})")
    print(f"Confusion (threat=positive): TP={cm['tp']} FP={cm['fp']} "
          f"TN={cm['tn']} FN={cm['fn']}")
    print("-" * 60)
    pct = lambda v: "n/a" if v is None else f"{v * 100:.2f}%"
    print(f"Precision                : {pct(p['precision'])}")
    print(f"Recall / catch rate (TPR): {pct(p['recall'])}")
    print(f"F1 score                 : {pct(p['f1'])}")
    print(f"False-positive rate      : {pct(p['false_positive_rate'])}")
    print(f"False-negative rate      : {pct(p['false_negative_rate'])}")
    print(f"Median scan time         : {p['median_scan_time_ms']} ms")
    print(f"p95 scan time            : {p['p95_scan_time_ms']} ms")
    print("-" * 60)
    print(f"Saved -> {out_path}")


def intel_stack() -> str:
    """
    "full" when the third-party reputation keys are reachable, otherwise
    "own-engine-only".

    This is not cosmetic. The two configurations score very differently — an
    A/B over one corpus measured 100% recall with the keys and 73.7% without —
    so a figure is meaningless unless you know which one produced it.
    """
    have_vt = bool(os.getenv("VIRUSTOTAL_API_KEY", "").strip())
    have_gsb = bool(os.getenv("GOOGLE_SAFEBROWSING_API_KEY", "").strip())
    if have_vt and have_gsb:
        return "full"
    if have_vt or have_gsb:
        return "partial"
    return "own-engine-only"


def scan_path_feed_state(feed_assist: bool, phish_source: str) -> str:
    """
    Human-readable description of the scan path's blocklist state, recorded in
    every metrics payload (audit finding 1, 2026-07-27).

    The phish corpus is built with fetch_openphish(), and apis/phish_feeds.py
    puts that SAME feed on the scan path as FEEDS[0]. Grading a scan that may
    look the corpus up in the feed the corpus came from measures a LOOKUP, not
    detection — 19/19 of the audited graded set matched OpenPhish while 0/19
    matched the independent Phishing.Database lists, and the published 97.12%
    recall was produced that way.

    So a run that keeps feeds ON over a feed-derived corpus is labelled
    CIRCULAR in its own output, and cannot be quoted as a detection figure.
    """
    source = (phish_source or "").lower()
    corpus_is_feed_derived = any(
        name in source for name in ("openphish", "phishtank", "phishing.database")
    )
    if not feed_assist:
        return ("scan-path community blocklist DISABLED — recall measures the "
                "detection engine, not feed membership")
    if corpus_is_feed_derived:
        return (f"scan-path community blocklist ENABLED over a {phish_source} "
                "corpus — CIRCULAR: recall reflects feed membership, not "
                "detection, and must not be quoted as an accuracy figure")
    return ("scan-path community blocklist ENABLED over a corpus from an "
            "independent source")


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="NexGuard real-world evaluation harness")
    ap.add_argument("--legit", type=int, default=600,
                    help="number of Tranco domains to test (default 600)")
    ap.add_argument("--legit-min-rank", type=int, default=2000,
                    help="lowest Tranco rank to sample legit domains from "
                         "(default 2000 — clear of the top-1000 exemption)")
    ap.add_argument("--legit-max-rank", type=int, default=10000,
                    help="highest Tranco rank to sample from (default 10000)")
    ap.add_argument("--phishing", type=int, default=300,
                    help="max phishing URLs to test (default 300)")
    ap.add_argument("--concurrency", type=int, default=12,
                    help="parallel scans (default 12)")
    ap.add_argument("--timeout", type=float, default=30.0,
                    help="per-scan timeout seconds (default 30)")
    ap.add_argument("--offline", action="store_true",
                    help="use bundled legit set only, skip all downloads/phish")
    # Audit finding 1: OFF by default. The phish corpus comes from OpenPhish and
    # the scan path reads OpenPhish, so leaving feeds on grades a lookup of the
    # corpus against itself. Opt in only to measure the DEPLOYED stack (feeds
    # included), knowing the result is labelled circular.
    ap.add_argument("--feed-assist", action="store_true", default=False,
                    help="leave the scan-path community blocklist ENABLED. Off "
                         "by default: the phish corpus is feed-derived, so an "
                         "assisted run measures feed membership, not detection, "
                         "and is labelled CIRCULAR in the output.")
    ap.add_argument("--out", default=str(OUT_PATH),
                    help=f"output JSON path (default {OUT_PATH})")
    return ap


def main():
    args = build_arg_parser().parse_args()
    # Applied before the first scan so every arm of the run sees one state.
    # phish_feeds reads this per call (apis/phish_feeds.py:_feeds_disabled).
    os.environ["NEXGUARD_DISABLE_FEEDS"] = "" if args.feed_assist else "1"
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
