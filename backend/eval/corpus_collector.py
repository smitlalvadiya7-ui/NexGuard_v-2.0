"""
Phase 1 — the stored corpus collector (ROAD_TO_90.md).

WHY THIS EXISTS
---------------
Four benchmark runs of the SAME code produced recall 73.5%, 73.6%, 37.6% and
38.4%. The cause was corpus composition, not code: one campaign flooded the live
OpenPhish feed on the day of the later runs, and 47 of run 4's 93 misses were
that single actor. A one-shot run against a live feed cannot measure detection
quality — composition swings recall by 35 points — so every figure downstream of
one is untrustworthy, including the original 64.3% baseline.

The corpus has to be COLLECTED ONCE AND STORED. Everything else in the plan
(the page-content classifier, trained fusion, threshold-as-policy) needs
labelled page CONTENT, and content cannot be recovered later: phishing kits die
in hours, so a URL not captured today is gone tomorrow. That is also why this
stores raw HTML rather than extracted features — feature extraction can be
redesigned, re-fetching cannot happen.

WHAT IT STORES
--------------
Per URL, one JSON record plus the raw response body:

    <root>/records/<label>/<split>/<id>.json     the metadata
    <root>/html/<id>.html.gz                     the body, gzipped
                                                (read_html gives back the
                                                original bytes)

    url          the URL as listed by the feed
    final_url    where it actually landed (a kit that redirects is a
                 different page from the one the feed named)
    label        "phish" | "legit"
    source       which feed / list it came from
    split        permanent train|eval partition (ml.dataset_utils.feed_split)
    fetched_at   UTC ISO-8601, so kit lifetime can be measured later
    status_code, html_sha1, html_bytes
    tls          issuer / subject / not_before / cert_age_days / is_free_ca
    error        set instead of the above when the fetch failed

DESIGN RULES
------------
* IDEMPOTENT. A daily run costs one fetch per NEW url, and a capture is never
  overwritten — it is dated evidence, not a cache entry.
* FAILURE IS DATA. A phishing URL already taken down is a fact about feed
  latency, and the benchmark needs it to tell "missed" from "dead". Dropping
  those would bias the corpus toward long-lived kits.
* NEGATIVES MATTER MORE THAN POSITIVES. Tranco pages across ranks, plus the
  deliberately hard ones in HARD_NEGATIVES — real bank logins above all, which
  carry a password field and a brand name exactly like phishing does.
* NO SCANNING. This module only fetches and stores. It never calls full_scan,
  so a corpus can never be labelled by the thing it is meant to measure.

Usage
-----
    # from backend/ — daily, feeds off the scan path is irrelevant here
    python -m eval.corpus_collector --phish 500 --legit 300
    python -m eval.corpus_collector --hard-negatives-only
    python -m eval.corpus_collector --stats

Schedule it daily (Task Scheduler / cron). Speed matters: it fetches
concurrently and should run within minutes of a feed listing.
"""

from __future__ import annotations

import argparse
import asyncio
import gzip
import hashlib
import json
import ssl
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

_BACKEND = Path(__file__).resolve().parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from ml.dataset_utils import (  # noqa: E402
    fetch_openphish, fetch_phishtank, fetch_tranco, feed_split, sample_band,
)
from top_domains import TOP_DOMAINS  # noqa: E402

DEFAULT_ROOT = _BACKEND / "data" / "corpus"
LABELS = ("phish", "legit")
MAX_HTML_BYTES = 2_000_000      # a kit is a few KB; anything larger is not a page
DEFAULT_TIMEOUT = 20.0


class FetchFailed(Exception):
    """The page could not be retrieved. Recorded, never raised to the caller."""


@dataclass
class Fetched:
    final_url: str
    status_code: int
    html: bytes
    tls: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# The hard negatives
#
# "Real bank login pages are the critical negatives: they have password fields
# and brand names, exactly like phishing. If your model cannot separate those,
# it is useless." Everything here is a page a content classifier will find
# genuinely difficult — not filler.
# ---------------------------------------------------------------------------

HARD_NEGATIVE_ENTRIES = [
    # Real bank / payment logins: password field + brand, the phishing shape.
    ("https://netbanking.hdfcbank.com/netbanking/", "bank-login"),
    ("https://www.icicibank.com/personal-banking/insta-banking/internet-banking", "bank-login"),
    ("https://www.onlinesbi.sbi/", "bank-login"),
    ("https://www.axisbank.com/retail/online-services/internet-banking", "bank-login"),
    ("https://www.kotak.com/en/personal-banking/ways-to-bank/net-banking.html", "bank-login"),
    ("https://www.pnbindia.in/", "bank-login"),
    ("https://www.bankofbaroda.in/", "bank-login"),
    ("https://secure.chase.com/web/auth/dashboard", "bank-login"),
    ("https://www.wellsfargo.com/", "bank-login"),
    ("https://www.bankofamerica.com/", "bank-login"),
    ("https://www.hsbc.co.uk/", "bank-login"),
    ("https://www.barclays.co.uk/", "bank-login"),
    ("https://www.paypal.com/signin", "bank-login"),
    ("https://www.paytm.com/", "bank-login"),
    ("https://www.phonepe.com/", "bank-login"),
    # Ecommerce checkout / account: forms, brands, urgency copy.
    ("https://www.amazon.in/ap/signin", "checkout"),
    ("https://www.flipkart.com/account/login", "checkout"),
    ("https://www.ebay.com/signin/", "checkout"),
    ("https://www.myntra.com/login", "checkout"),
    ("https://www.bigbasket.com/", "checkout"),
    ("https://www.zomato.com/", "checkout"),
    ("https://www.irctc.co.in/nget/train-search", "checkout"),
    ("https://www.makemytrip.com/", "checkout"),
    # Government / identity portals: the brands phishing impersonates most.
    ("https://www.incometax.gov.in/iec/foportal/", "govt-portal"),
    ("https://uidai.gov.in/", "govt-portal"),
    ("https://www.epfindia.gov.in/site_en/index.php", "govt-portal"),
    ("https://www.india.gov.in/", "govt-portal"),
    ("https://www.gst.gov.in/", "govt-portal"),
    ("https://www.gov.uk/sign-in-universal-credit", "govt-portal"),
    ("https://www.irs.gov/", "govt-portal"),
    ("https://www.ssa.gov/myaccount/", "govt-portal"),
    # Security / educational pages: legitimately full of phishing vocabulary.
    ("https://www.kaspersky.com/resource-center/threats/phishing", "security-blog"),
    ("https://www.ncsc.gov.uk/guidance/phishing", "security-blog"),
    ("https://support.google.com/accounts/answer/6010255", "security-blog"),
    ("https://www.phishtank.com/", "security-blog"),
    ("https://krebsonsecurity.com/", "security-blog"),
    ("https://www.cisa.gov/secure-our-world", "security-blog"),
    ("https://owasp.org/www-community/attacks/", "security-blog"),
    ("https://haveibeenpwned.com/", "security-blog"),
    # Legitimate tenants on the very platforms phishing kits abuse — the
    # controls for every shared-hosting rule in the scanner.
    ("https://docs.github.io/", "shared-hosting-tenant"),
    ("https://developers.cloudflare.com/pages/", "shared-hosting-tenant"),
    ("https://vercel.com/docs", "shared-hosting-tenant"),
]

HARD_NEGATIVES = [u for u, _ in HARD_NEGATIVE_ENTRIES]


# ---------------------------------------------------------------------------
# Identity and layout
# ---------------------------------------------------------------------------

def record_id(url: str) -> str:
    """Stable per-URL id — the same partition key style as feed_split."""
    return hashlib.sha1((url or "").strip().lower().encode("utf-8")).hexdigest()


def split_of(url: str) -> str:
    """Permanent train/eval partition. Reuses the project's existing hash
    partition so a URL lands on the same side here as everywhere else."""
    return feed_split(url)


def records_dir(root: Path, label: str, split: str) -> Path:
    return Path(root) / "records" / label / split


def html_path(root: Path, record: dict) -> Path:
    """
    Where the page body lives. Gzipped: this collector runs daily for weeks and
    a measured live capture of 37 pages was 8.8 MB, which extrapolates to about
    2.6 GB over the collection the plan calls for. HTML compresses roughly 5x,
    and a corpus small enough to keep is a corpus that survives.
    """
    return Path(root) / "html" / f"{record['id']}.html.gz"


def read_html(root: Path, record: dict) -> bytes:
    """The page body exactly as fetched. Compression is an implementation
    detail — callers get the original bytes back."""
    path = html_path(root, record)
    if not path.exists():
        return b""
    with gzip.open(path, "rb") as f:
        return f.read()


def _record_path(root: Path, url: str, label: str) -> Path:
    return records_dir(root, label, split_of(url)) / f"{record_id(url)}.json"


def already_collected(root: Path, url: str) -> bool:
    """True when ANY label already holds this URL — the capture is dated
    evidence and a later run must not overwrite or duplicate it."""
    rid = record_id(url)
    for label in LABELS:
        if (records_dir(root, label, split_of(url)) / f"{rid}.json").exists():
            return True
    return False


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

def tls_metadata(url: str, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """
    Certificate facts for an https URL — issuer, subject, validity window,
    cert age, free-CA marker.

    Delegates to apis.ssl_cert, which already reads the DER form and parses it.
    This module's first attempt reimplemented the read and got it wrong in a way
    no unit test would have shown: it disabled verification and then called
    getpeercert() with no arguments, which returns an EMPTY dict in that mode,
    so every record it wrote carried "tls": {}. Reusing the scanner's reader
    also means the corpus records the same view of a certificate that the
    scanner acts on.

    Fail-safe: {} on anything unexpected. A missing certificate must never cost
    us the page capture, which is the part that cannot be re-fetched later.
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    if parsed.scheme != "https":
        return {}
    host = parsed.hostname or ""
    if not host:
        return {}
    try:
        from apis.ssl_cert import _ssl_sync

        info = _ssl_sync(host, parsed.port or 443)
        return info if isinstance(info, dict) else {}
    except Exception:
        return {}


async def default_fetcher(url: str, timeout: float = DEFAULT_TIMEOUT) -> Fetched:
    """
    Retrieve a page for storage. Deliberately NOT the scanner's fetcher: this
    follows redirects, keeps the body whatever it is, and never judges.
    """
    import requests

    def _get():
        resp = requests.get(
            url, timeout=timeout, allow_redirects=True, stream=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; NexGuard-corpus/1.0)"},
        )
        body = resp.raw.read(MAX_HTML_BYTES, decode_content=True) or b""
        return resp, body

    try:
        resp, body = await asyncio.to_thread(_get)
    except Exception as e:  # noqa: BLE001
        raise FetchFailed(f"{type(e).__name__}: {e}") from e
    final_url = resp.url or url
    tls = await asyncio.to_thread(tls_metadata, final_url, timeout)
    return Fetched(final_url=final_url, status_code=resp.status_code,
                   html=body, tls=tls)


# ---------------------------------------------------------------------------
# Collecting
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _write(root: Path, url: str, label: str, record: dict) -> None:
    path = _record_path(root, url, label)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=1), encoding="utf-8")


async def collect_one(url: str, label: str, root: Path, fetcher,
                      source: str = "unknown",
                      timeout: float = DEFAULT_TIMEOUT) -> str:
    """Fetch and store one URL. Returns "collected", "skipped" or "failed"."""
    if already_collected(root, url):
        return "skipped"
    rid = record_id(url)
    base = {
        "id": rid,
        "url": url,
        "label": label,
        "source": source,
        "split": split_of(url),
        "fetched_at": _now_iso(),
    }
    try:
        got = await fetcher(url, timeout=timeout)
    except Exception as e:  # noqa: BLE001 — failure is data, not an abort
        _write(root, url, label, {
            **base, "final_url": None, "status_code": None, "html_sha1": None,
            "html_bytes": 0, "tls": {}, "error": f"{type(e).__name__}: {e}",
        })
        return "failed"

    html = got.html or b""
    html_file = html_path(root, {"id": rid})
    html_file.parent.mkdir(parents=True, exist_ok=True)
    # mtime=0 so an identical page always produces an identical file — the
    # corpus should not churn on re-capture in a different second.
    with gzip.GzipFile(html_file, "wb", compresslevel=6, mtime=0) as f:
        f.write(html)
    _write(root, url, label, {
        **base,
        "final_url": got.final_url,
        "status_code": got.status_code,
        "html_sha1": hashlib.sha1(html).hexdigest(),
        "html_bytes": len(html),
        "tls": got.tls or {},
        "error": None,
    })
    return "collected"


async def collect(urls, label: str, root: Path, fetcher=None,
                  source: str = "unknown", concurrency: int = 12,
                  timeout: float = DEFAULT_TIMEOUT) -> dict:
    """
    Fetch and store every URL. Never raises for a single bad page — one dead
    kit must not end the day's collection.
    """
    if label not in LABELS:
        raise ValueError(f"label must be one of {LABELS}, got {label!r}")
    fetcher = fetcher or default_fetcher
    root = Path(root)
    sem = asyncio.Semaphore(concurrency)

    async def _one(u):
        async with sem:
            return await collect_one(u, label, root, fetcher, source, timeout)

    outcomes = await asyncio.gather(*(_one(u) for u in urls), return_exceptions=True)
    tally = Counter(o for o in outcomes if isinstance(o, str))
    return {
        "label": label,
        "source": source,
        "requested": len(list(urls)),
        "collected": tally["collected"],
        "skipped": tally["skipped"],
        "failed": tally["failed"],
    }


# ---------------------------------------------------------------------------
# Reading back
# ---------------------------------------------------------------------------

def load_records(root: Path, label: str | None = None, split: str | None = None,
                 include_failed: bool = False) -> list[dict]:
    """
    Every stored record, optionally filtered. Failed captures are EXCLUDED by
    default — they belong in the corpus as a record of feed latency, but they
    are not usable training or evaluation examples.
    """
    root = Path(root)
    base = root / "records"
    if not base.exists():
        return []
    out = []
    for label_dir in sorted(base.iterdir()):
        if not label_dir.is_dir() or (label and label_dir.name != label):
            continue
        for split_dir in sorted(label_dir.iterdir()):
            if not split_dir.is_dir() or (split and split_dir.name != split):
                continue
            for path in sorted(split_dir.glob("*.json")):
                try:
                    rec = json.loads(path.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if rec.get("error") and not include_failed:
                    continue
                out.append(rec)
    return out


def stats(root: Path) -> dict:
    """Corpus size by label / split, plus how much of it is usable."""
    all_recs = load_records(root, include_failed=True)
    usable = [r for r in all_recs if not r.get("error")]
    by = Counter((r["label"], r["split"]) for r in usable)
    days = Counter((r.get("fetched_at") or "")[:10] for r in all_recs)
    return {
        "total_records": len(all_recs),
        "usable": len(usable),
        "failed": len(all_recs) - len(usable),
        "by_label_split": {f"{lab}/{sp}": n for (lab, sp), n in sorted(by.items())},
        "collection_days": len(days),
        "per_day": dict(sorted(days.items())),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

async def _run(args) -> None:
    root = Path(args.root)
    if args.stats:
        print(json.dumps(stats(root), indent=2))
        return

    runs = []
    if args.hard_negatives_only:
        runs.append((HARD_NEGATIVES, "legit", "hard-negative"))
    else:
        if args.phish:
            feed = fetch_openphish(args.phish) or fetch_phishtank(args.phish)
            source = "openphish" if feed else "none"
            if not feed:
                print("  WARNING: no phishing feed available this run")
            runs.append((feed[:args.phish], "phish", source))
        if args.legit:
            ranked = fetch_tranco(args.legit_max_rank)
            if ranked:
                domains = sample_band(ranked, n=args.legit,
                                      min_rank=args.legit_min_rank,
                                      max_rank=args.legit_max_rank,
                                      exclude=set(TOP_DOMAINS), seed=None)
                runs.append(([f"https://{d}" for d in domains], "legit", "tranco"))
            else:
                print("  WARNING: Tranco unavailable — skipping legit sample")
        runs.append((HARD_NEGATIVES, "legit", "hard-negative"))

    for urls, label, source in runs:
        if not urls:
            continue
        print(f"Collecting {len(urls)} {label} URLs from {source}…")
        result = await collect(urls, label=label, root=root, source=source,
                               concurrency=args.concurrency, timeout=args.timeout)
        print(f"  {result}")

    print("\nCorpus now:")
    print(json.dumps(stats(root), indent=2))


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="NexGuard stored-corpus collector")
    ap.add_argument("--root", default=str(DEFAULT_ROOT))
    ap.add_argument("--phish", type=int, default=500)
    ap.add_argument("--legit", type=int, default=300)
    ap.add_argument("--legit-min-rank", type=int, default=2000)
    ap.add_argument("--legit-max-rank", type=int, default=100000)
    ap.add_argument("--concurrency", type=int, default=12)
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--hard-negatives-only", action="store_true")
    ap.add_argument("--stats", action="store_true",
                    help="print corpus statistics and exit")
    return ap


def main():
    asyncio.run(_run(build_arg_parser().parse_args()))


if __name__ == "__main__":
    main()
