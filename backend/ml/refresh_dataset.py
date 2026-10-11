"""
Refresh + grow the training dataset (M1).

Adds RECENT phishing URLs (OpenPhish, plus PhishTank when it isn't
rate-limiting) and DIVERSE legit URLs (Tranco ranks 1001-50000 — deeper than
the famous-domain exemption, so the model learns from sites it can't just
look up) to `raw_dataset.csv`, keeping the two classes balanced.

Honesty rules baked in:
  * only the "train" half of the permanent hash split is ever added — the
    real-world benchmark draws exclusively from the "eval" half, so training
    data and benchmark can never overlap (see ml/dataset_utils.feed_split);
  * equal phish/legit additions per run (the base set is balanced 50/50);
  * the previous CSV is backed up to raw_dataset.csv.bak (gitignored) and
    every run is recorded in dataset_log.json.

Re-runnable: each run appends only URLs not already present, so running it
weekly ACCUMULATES a growing, current dataset (pairs with M5 scheduled
retrain later).

Usage:
    python refresh_dataset.py [--max-add 5000] [--dry-run]
Then retrain + judge by the REAL gate:
    python train.py
    python -m eval.realworld_eval        # precision must stay >= 97%
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
for p in (BACKEND, HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from dataset_utils import (  # noqa: E402
    clean_feed_urls, feed_split, fetch_openphish, fetch_phishtank,
    fetch_tranco, fetch_umbrella, merge_dataset, phishtank_urls_from_csv,
    sample_band,
)
from top_domains import TOP_DOMAINS  # noqa: E402

DATASET = os.path.join(HERE, "raw_dataset.csv")
BACKUP = DATASET + ".bak"
LOG = os.path.join(HERE, "dataset_log.json")

LEGIT_MIN_RANK = 1001          # below the exemption list; nothing famous
LEGIT_MAX_RANK = 50000
LEGIT_SEED = 7                 # NOT the eval seed; pools are disjoint anyway


def load_base(path: str = DATASET) -> list[tuple[str, str]]:
    """(url, status) rows from the current dataset; extra columns ignored."""
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f)
        header = next(reader, [])
        u = header.index("url") if "url" in header else 0
        s = header.index("status") if "status" in header else len(header) - 1
        return [(row[u].strip(), row[s].strip())
                for row in reader if row and row[u].strip()]


def fresh_phish(cap: int, phishtank_file: str | None = None) -> tuple[list[str], list[str]]:
    """Train-half recent phishing URLs + the list of sources that answered."""
    sources, urls = [], []
    op = fetch_openphish(cap * 3)
    if op:
        sources.append(f"openphish({len(op)})")
        urls.extend(op)
    if phishtank_file:
        # An already-downloaded online-valid.csv (PhishTank rate-limits hard;
        # one manual download can be reused instead of fetching again).
        with open(phishtank_file, encoding="utf-8", errors="replace") as f:
            pt = phishtank_urls_from_csv(f.read())
        if pt:
            sources.append(f"phishtank-file({len(pt)})")
            urls.extend(pt)
    else:
        pt = fetch_phishtank(cap * 3)
        if pt:
            sources.append(f"phishtank({len(pt)})")
            urls.extend(pt)
    urls = [u for u in clean_feed_urls(urls) if feed_split(u) == "train"]
    return urls[:cap], sources


def fresh_legit(n: int) -> tuple[list[str], str]:
    """Train-half deeper-rank Tranco domains as https:// URLs + source name."""
    ranked = fetch_tranco(LEGIT_MAX_RANK)
    source = "tranco"
    if not ranked:
        ranked = fetch_umbrella(LEGIT_MAX_RANK)
        source = "umbrella(fallback)"
    if not ranked:
        return [], "none"
    domains = sample_band(ranked, n=n, min_rank=LEGIT_MIN_RANK,
                          max_rank=LEGIT_MAX_RANK, exclude=set(TOP_DOMAINS),
                          seed=LEGIT_SEED, split="train")
    return [f"https://{d}" for d in domains], \
        f"{source}[ranks {LEGIT_MIN_RANK}-{LEGIT_MAX_RANK}]"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-add", type=int, default=5000,
                    help="max URLs to add PER CLASS this run (default 5000)")
    ap.add_argument("--phishtank-file", default=None,
                    help="path to an already-downloaded PhishTank "
                         "online-valid.csv (skips the rate-limited fetch)")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would be added; write nothing")
    args = ap.parse_args()

    base = load_base()
    n_phish_base = sum(1 for _, s in base if "phish" in s.lower())
    print(f"Base dataset: {len(base)} rows "
          f"({n_phish_base} phishing / {len(base) - n_phish_base} legitimate)")

    print("Fetching recent phishing (train half)…")
    phish_urls, phish_sources = fresh_phish(args.max_add, args.phishtank_file)
    print(f"  {len(phish_urls)} candidate URLs from {', '.join(phish_sources) or 'no source'}")
    if not phish_urls:
        print("No phishing feed reachable — nothing to add today. Try again later.")
        return

    # Balanced additions: as many legit as we have fresh phish.
    print("Fetching deeper-rank legit domains (train half)…")
    legit_urls, legit_source = fresh_legit(len(phish_urls))
    print(f"  {len(legit_urls)} candidate URLs from {legit_source}")

    n_add = min(len(phish_urls), len(legit_urls)) if legit_urls else len(phish_urls)
    additions = ([(u, "phishing") for u in phish_urls[:n_add]]
                 + [(u, "legitimate") for u in legit_urls[:n_add]])
    merged, added = merge_dataset(base, additions)
    print(f"After dedupe/conflict rules: {added} rows actually added "
          f"-> {len(merged)} total")

    if args.dry_run:
        print("Dry run — nothing written.")
        return
    if not added:
        print("Everything already present — dataset unchanged.")
        return

    shutil.copyfile(DATASET, BACKUP)
    with open(DATASET, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["url", "status"])
        w.writerows(merged)
    n_phish = sum(1 for _, s in merged if "phish" in s.lower())
    print(f"Wrote {DATASET} ({len(merged)} rows: {n_phish} phishing / "
          f"{len(merged) - n_phish} legitimate; backup at {BACKUP})")

    entry = {
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "phish_sources": phish_sources,
        "legit_source": legit_source,
        "added": added,
        "total_rows": len(merged),
    }
    log = []
    if os.path.exists(LOG):
        try:
            with open(LOG, encoding="utf-8") as f:
                log = json.load(f)
        except Exception:
            log = []
    log.append(entry)
    with open(LOG, "w", encoding="utf-8") as f:
        json.dump(log, f, indent=2)
    print(f"Run logged -> {LOG}")
    print("\nNext: python train.py   then   python -m eval.realworld_eval")


if __name__ == "__main__":
    main()
