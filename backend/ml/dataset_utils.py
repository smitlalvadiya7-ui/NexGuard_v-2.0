"""
Shared dataset plumbing for training refresh + real-world eval (M1).

Pure logic (no project imports) so both `ml/refresh_dataset.py` and
`eval/realworld_eval.py` build their corpora from the same rules:

  * clean_feed_urls  — normalize a raw feed into usable http(s) URLs
  * feed_split       — PERMANENT hash-parity partition: every URL/domain is
                       either "train" or "eval" forever, so the benchmark can
                       never contain training data (today or after any future
                       scheduled retrain)
  * sample_band      — deterministic sample of Tranco domains from a rank band
  * merge_dataset    — append new labeled rows without duplicates/conflicts
  * fetch_tranco / fetch_openphish / fetch_phishtank — feed downloads,
                       fail-safe to [] (callers fall back and record honestly)
"""
from __future__ import annotations

import csv
import hashlib
import io
import random
import zipfile

import requests

UA = {"User-Agent": "NexGuard-eval/1.0 (+https://example.com)"}

_MAX_URL_LEN = 2048


# ---------------------------------------------------------------------------
# Pure logic
# ---------------------------------------------------------------------------

def clean_feed_urls(lines, cap: int | None = None) -> list[str]:
    """Strip, keep http(s) only, drop absurd lengths, dedupe preserving order."""
    seen: set[str] = set()
    out: list[str] = []
    for raw in lines or []:
        u = (raw or "").strip()
        if not u.startswith(("http://", "https://")) or len(u) > _MAX_URL_LEN:
            continue
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
        if cap is not None and len(out) >= cap:
            break
    return out


def feed_split(item: str) -> str:
    """
    Permanent train/eval partition by content hash (case/space-insensitive).
    Roughly 50/50, deterministic across machines and time. Training code keeps
    only "train" items; the benchmark keeps only "eval" items.
    """
    digest = hashlib.sha1((item or "").strip().lower().encode("utf-8")).digest()
    return "train" if digest[-1] % 2 == 0 else "eval"


def sample_band(domains: list[str], n: int, min_rank: int, max_rank: int,
                exclude: set, seed: int = 42, split: str | None = None) -> list[str]:
    """
    Deterministically sample up to n domains whose rank (1-based position in
    the rank-ordered `domains` list) lies in [min_rank, max_rank], skipping
    `exclude` (e.g. the famous-domain exemption list) and, when `split` is
    given, anything on the other side of the permanent hash partition.
    """
    lo = max(min_rank - 1, 0)
    band = domains[lo:max_rank]
    pool = [d for d in band
            if d not in exclude and (split is None or feed_split(d) == split)]
    if len(pool) <= n:
        return pool
    return random.Random(seed).sample(pool, n)


def merge_dataset(base_rows: list[tuple[str, str]],
                  additions: list[tuple[str, str]]) -> tuple[list[tuple[str, str]], int]:
    """
    Append additions to the base dataset. Rules:
      * exact URL already present -> skip (the existing label wins),
      * a NEW LEGIT row on a host that the base already labels phishing is
        dropped (a popularity list can't overrule a phishing label),
      * a new PHISH row is always kept — phishing pages do live on otherwise
        legitimate hosts (forms, shared hosting, tenants).
    Returns (merged_rows, number_actually_added).
    """
    seen_urls = {u for u, _ in base_rows}
    phish_hosts = {_host(u) for u, s in base_rows if "phish" in s.lower()}
    merged = list(base_rows)
    added = 0
    for url, status in additions:
        if url in seen_urls:
            continue
        if "phish" not in status.lower() and _host(url) in phish_hosts:
            continue
        merged.append((url, status))
        seen_urls.add(url)
        if "phish" in status.lower():
            phish_hosts.add(_host(url))
        added += 1
    return merged, added


def _host(url: str) -> str:
    rest = url.split("://", 1)[-1]
    return rest.split("/", 1)[0].split("?", 1)[0].split("@")[-1].split(":")[0].lower()


# ---------------------------------------------------------------------------
# Feed downloads (fail-safe: return [] and let the caller fall back)
# ---------------------------------------------------------------------------

def fetch_tranco(n: int) -> list[str]:
    """Latest Tranco top-n registrable domains (rank order). [] on failure."""
    try:
        meta = requests.get("https://tranco-list.eu/api/lists/date/latest",
                            headers=UA, timeout=20).json()
        list_id = meta.get("list_id")
        if list_id:
            url = f"https://tranco-list.eu/download/{list_id}/{max(n, 1)}"
        elif meta.get("download"):
            url = meta["download"]
        else:
            return []
        resp = requests.get(url, headers=UA, timeout=120)
        resp.raise_for_status()
        return _parse_rank_csv(resp.content, n)
    except Exception as e:
        print(f"  [tranco] download failed: {e}")
        return []


def fetch_umbrella(n: int) -> list[str]:
    """Cisco Umbrella top-1m — keyless zipped CSV. Tranco fallback."""
    try:
        url = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
        resp = requests.get(url, headers=UA, timeout=120)
        resp.raise_for_status()
        return _parse_rank_csv(resp.content, n)
    except Exception as e:
        print(f"  [umbrella] download failed: {e}")
        return []


def _parse_rank_csv(content: bytes, n: int) -> list[str]:
    """Parse a rank,domain CSV payload (raw or zipped) into a domain list."""
    data = content
    if content[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            name = next((x for x in zf.namelist() if x.endswith(".csv")),
                        zf.namelist()[0])
            data = zf.read(name)
    out: list[str] = []
    reader = csv.reader(io.StringIO(data.decode("utf-8", errors="replace")))
    for row in reader:
        if len(row) >= 2 and row[1].strip():
            out.append(row[1].strip().lower())
        elif len(row) == 1 and row[0].strip():
            out.append(row[0].strip().lower())
        if len(out) >= n:
            break
    return out


def fetch_openphish(cap: int) -> list[str]:
    """OpenPhish community feed — plaintext, one live phishing URL per line."""
    try:
        resp = requests.get("https://openphish.com/feed.txt", headers=UA, timeout=30)
        resp.raise_for_status()
        return clean_feed_urls(resp.text.splitlines(), cap=cap)
    except Exception as e:
        print(f"  [openphish] feed failed: {e}")
        return []


def phishtank_urls_from_csv(text: str, cap: int | None = None) -> list[str]:
    """URL column of a PhishTank online-valid CSV payload, cleaned."""
    urls = [(row.get("url") or "").strip()
            for row in csv.DictReader(io.StringIO(text or ""))]
    return clean_feed_urls(urls, cap=cap)


def fetch_phishtank(cap: int) -> list[str]:
    """PhishTank online-valid feed (CSV). Often rate-limited without a key."""
    try:
        resp = requests.get("https://data.phishtank.com/data/online-valid.csv",
                            headers=UA, timeout=60)
        resp.raise_for_status()
        return phishtank_urls_from_csv(resp.text, cap=cap)
    except Exception as e:
        print(f"  [phishtank] feed failed: {e}")
        return []
