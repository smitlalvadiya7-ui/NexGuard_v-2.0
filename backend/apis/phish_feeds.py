"""
Community blocklist membership — phishing feeds on the scan path.

Live FNs (2026-07-14 eval): most of the 13 missed phish were ON the OpenPhish
feed at scan time — the feed only powered /live-threats, never /scan.

Two layers, deliberately NOT weighted the same by aggregator._reputation_score:

  * URL layer    — OpenPhish community feed + the Phishing.Database ACTIVE
                   links feed. An exact (normalised) URL match is a CONFIRMED
                   reputation hit, weighted like a Safe Browsing flag.
  * domain layer — the Phishing.Database ACTIVE domains feed. Matching a bare
                   host is a WEAKER claim than matching the exact URL, so it
                   scores lower and never convicts on its own.

The domain layer is guarded (`_host_is_exempt`). The live feed really does
list shared platforms and legitimate sites that were compromised once —
sites.google.com and banrisul.com.br were both on it on 2026-07-27, and 73 of
the Tranco top-100k appear in total. Convicting those would false-positive
every page they host, so a host that IS a top-1000 registrable (or one of its
subdomains) or IS itself an established top-100k registrable is exempt from
the domain layer. Specific tenants stay convictable: alice.blogspot.com and
kit.000webhostapp.com are listings of one attacker's site, not of a platform.

Host matching is EXACT — a listed registrable never convicts its subdomains,
which is how a single platform listing would otherwise take out every tenant
under it.

Public surface
--------------
  async check_phish_feeds(url) -> {"status": "clean|flag",
                                   "detail": str,
                                   "match": "url" | "domain" | None}

Each feed snapshot is fetched at most once per its own TTL per process and
shared by every scan (in-memory sets; O(1) lookups). A fetch failure keeps the
previous snapshot (stale-ok) and retries after _RETRY seconds, per feed — one
dead feed never silences the others. NEXGUARD_DISABLE_FEEDS=1 disables the
check entirely — pipeline-quality evals use it to measure the scoring engine
without feed assistance.
"""

import sys as _sys
from pathlib import Path as _Path
# Fill missing env vars from backend/.env before any key is read. Without
# this, only main.py and telegram_bot.py had the keys and every other entry
# point scanned with this source silently switched off (see env_config).
_BACKEND = _Path(__file__).resolve().parent.parent
if str(_BACKEND) not in _sys.path:
    _sys.path.insert(0, str(_BACKEND))
import env_config  # noqa: E402,F401  — imported for its side effect


import asyncio
import hashlib
import os
import re
import threading
import time
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urlsplit

import requests

from top_domains import is_established_registrable, is_top_registrable_host

_PDB = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/"


class _Feed(NamedTuple):
    label: str      # lands in the flag detail
    url: str
    kind: str       # "url" (exact URL entries) | "domain" (bare hosts)
    ttl: float      # refresh cadence on success
    timeout: float  # the multi-MB feeds need far longer than the small one


# OpenPhish community needs no key and refreshes upstream every ~12 h. The
# Phishing.Database lists are big and regenerate roughly daily, so their TTLs
# are sized against download cost, not freshness: the links file is ~63 MB
# (24 h -> one download a day) and the domains file ~11 MB (6 h). Timeouts are
# generous because a cold fetch outlives the per-scan budget by design — see
# warm_in_background(), which keeps that off the request path.
FEEDS = (
    _Feed("OpenPhish", "https://openphish.com/feed.txt", "url", 900.0, 10.0),
    _Feed("Phishing.Database", _PDB + "phishing-links-ACTIVE.txt", "url", 86400.0, 180.0),
    _Feed("Phishing.Database", _PDB + "phishing-domains-ACTIVE.txt", "domain", 21600.0, 120.0),
)

# Which of the feeds above this build is licensed to use. OpenPhish's community
# feed is non-commercial only, so a paid build must not read it — see
# deployment_profile. FEEDS stays the complete catalogue; this filters it.
_FEED_SOURCE_IDS = {
    "OpenPhish": "openphish",
    "Phishing.Database": "phishing_database",
}


def active_feeds() -> tuple:
    """The feeds this deployment profile permits. Everything downstream —
    refresh, lookup, cache warming — iterates this rather than FEEDS."""
    from deployment_profile import is_allowed
    return tuple(f for f in FEEDS
                 if is_allowed(_FEED_SOURCE_IDS.get(f.label, f.label)))


_RETRY = 120.0    # retry cadence after a failed fetch

# Snapshots survive a restart on disk. Local development restarts constantly
# (uvicorn --reload) and re-downloading ~74 MB each time — ~90 s during which
# every scan silently loses the source — is not workable. The cache also means
# several workers on one host share one download.
_CACHE_DIR = Path(__file__).resolve().parents[1] / "data" / "feed_cache"

_lock = threading.Lock()
_sets: dict = {}          # feed url -> frozenset of entries
_next_fetch: dict = {}    # feed url -> earliest next fetch (monotonic wall time)

# Single-flight guard for the off-request-path TTL refresh. Separate from _lock,
# which protects the snapshot maps and must never be held across a download.
_refresh_guard = threading.Lock()
_refresh_worker: "threading.Thread | None" = None

_CLEAN = {"status": "clean", "detail": "clean", "match": None}
_UNAVAILABLE = {"status": "unavailable", "detail": "unavailable", "match": None}
_DISABLED = {"status": "unavailable", "detail": "disabled", "match": None}


def _normalize(url: str) -> str:
    """
    Scheme, host case, a www. prefix, a trailing slash and fragments never
    distinguish a phishing URL from its feed entry; path/query stay exact.
    'HTTP://WWW.Evil.com/kit/'  and  'https://evil.com/kit'  both map to
    'evil.com/kit'.
    """
    raw = (url or "").strip()
    try:
        parts = urlsplit(raw if "//" in raw else "//" + raw)
    except ValueError:
        return raw.lower()
    host = (parts.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    out = host + parts.path.rstrip("/")
    if parts.query:
        out += "?" + parts.query
    return out


def _normalize_host(value: str) -> str:
    """Bare-host form of a feed line or a scanned URL: lowercase, no www.,
    no trailing dot, no scheme or path."""
    raw = (value or "").strip().lower().rstrip(".")
    if not raw:
        return ""
    try:
        parts = urlsplit(raw if "//" in raw else "//" + raw)
        host = (parts.hostname or "").rstrip(".")
    except ValueError:
        host = raw
    if host.startswith("www."):
        host = host[4:]
    return host


def _host_is_exempt(host: str) -> bool:
    """
    True when a bare-host listing must not convict — the host is a top-1000
    registrable or a subdomain of one (sites.google.com), or is itself an
    established top-100k registrable that was presumably listed after a
    one-off compromise (banrisul.com.br). Tenant hosts under a platform are
    NOT exempt: their registrable is the tenant's own, not the platform's.
    """
    return is_top_registrable_host(host) or is_established_registrable(host)


def _digest(value: str) -> bytes:
    return hashlib.blake2b(value.encode("utf-8", "replace"), digest_size=8).digest()


class _DigestSet:
    """
    Membership over 8-byte digests held in ONE sorted bytes blob.

    The two Phishing.Database feeds are ~550k entries; as frozensets of their
    source strings they measured 69 MB of heap, which is a lot to spend on a
    single reputation source in a container that also holds the ML models.
    Digests bring that to ~4.4 MB with O(log n) lookups. A 64-bit digest over
    550k entries collides with probability ~1e-8 — orders of magnitude below
    the feeds' own error rate, and the aggregator never convicts on a bare
    domain hit alone anyway.
    """

    __slots__ = ("_blob", "_n")

    def __init__(self, entries):
        digests = sorted({_digest(e) for e in entries})
        self._blob = b"".join(digests)
        self._n = len(digests)

    @classmethod
    def from_blob(cls, blob: bytes):
        """Rebuild from a persisted blob, or None if the file is not one."""
        if not blob or len(blob) % 8:
            return None
        obj = cls.__new__(cls)
        obj._blob = blob
        obj._n = len(blob) // 8
        return obj

    @property
    def blob(self) -> bytes:
        return self._blob

    def __len__(self) -> int:
        return self._n

    def __bool__(self) -> bool:
        return self._n > 0

    def __contains__(self, value: str) -> bool:
        target = _digest(value)
        lo, hi = 0, self._n
        while lo < hi:
            mid = (lo + hi) // 2
            if self._blob[mid * 8:mid * 8 + 8] < target:
                lo = mid + 1
            else:
                hi = mid
        return lo < self._n and self._blob[lo * 8:lo * 8 + 8] == target


def _parse(kind: str, text: str) -> _DigestSet:
    normalize = _normalize if kind == "url" else _normalize_host
    return _DigestSet(
        entry for entry in (
            normalize(line) for line in (text or "").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ) if entry
    )


def _cache_path(feed: _Feed) -> Path:
    slug = re.sub(r"[^a-z0-9]+", "-", f"{feed.label}-{feed.kind}".lower()).strip("-")
    tag = hashlib.blake2b(feed.url.encode("utf-8"), digest_size=4).hexdigest()
    return _CACHE_DIR / f"{slug}-{tag}.bin"


def _load_cached(feed: _Feed):
    """(entries, seconds_of_freshness_left) from disk, or None when the file is
    missing, stale, corrupt or unreadable — every one of which just means
    'fetch it'."""
    path = _cache_path(feed)
    try:
        age = time.time() - path.stat().st_mtime
        if age < 0 or age > feed.ttl:
            return None
        entries = _DigestSet.from_blob(path.read_bytes())
    except OSError:
        return None
    if not entries:
        return None
    return entries, feed.ttl - age


def _store_cached(feed: _Feed, entries) -> None:
    """Persist a freshly fetched snapshot. Written to a temp file and renamed
    so a crash mid-write can never leave a half-snapshot behind; a read-only
    filesystem simply means no caching."""
    path = _cache_path(feed)
    tmp = path.with_suffix(".tmp")
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        tmp.write_bytes(entries.blob)
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass


def _feeds_disabled() -> bool:
    return os.getenv("NEXGUARD_DISABLE_FEEDS", "").strip().lower() in ("1", "true", "yes")


def _refresh_if_due_sync() -> None:
    """Refresh every feed whose TTL has expired. Per-feed state, so a slow or
    dead feed neither blocks nor invalidates the others."""
    if _feeds_disabled():
        return
    for feed in active_feeds():
        with _lock:
            if time.time() < _next_fetch.get(feed.url, 0.0):
                continue
            # Claim the fetch window immediately so concurrent scans don't
            # stampede; extended to the full TTL below only on success.
            _next_fetch[feed.url] = time.time() + _RETRY
        # A snapshot persisted by an earlier run (or another worker) that is
        # still inside its TTL saves the whole download.
        cached = _load_cached(feed)
        if cached is not None:
            entries, fresh_for = cached
            with _lock:
                _sets[feed.url] = entries
                _next_fetch[feed.url] = time.time() + fresh_for
            continue

        try:
            resp = requests.get(feed.url, timeout=feed.timeout)
            resp.raise_for_status()
            entries = _parse(feed.kind, resp.text)
        except Exception:
            continue          # keep the previous snapshot (stale-ok)
        if not entries:
            continue          # an empty payload is a bad fetch, not an empty feed
        _store_cached(feed, entries)
        with _lock:
            _sets[feed.url] = entries
            _next_fetch[feed.url] = time.time() + feed.ttl


def _any_feed_due() -> bool:
    """True when at least one feed's TTL has expired."""
    now = time.time()
    with _lock:
        return any(now >= _next_fetch.get(feed.url, 0.0) for feed in active_feeds())


def _any_feed_cold() -> bool:
    """
    True when some feed has NO snapshot at all — nothing to serve, stale or
    otherwise. Distinct from merely due: a cold feed cannot answer, whereas a
    stale one answers slightly out of date, which is the documented behaviour.
    """
    with _lock:
        return any(not _sets.get(feed.url) for feed in active_feeds())


def _refresh_due_in_background() -> threading.Thread | None:
    """
    Start a due refresh OFF the request path and return immediately.

    A scan must never pay for a TTL expiry. warm_in_background() covers only
    the first load at startup; before this, check_phish_feeds awaited
    _refresh_if_due_sync inline on EVERY scan, so the first request after the
    24 h TTL lapsed pulled the ~63 MB links feed while holding up the scan —
    and, because each request called it independently, a burst of concurrent
    traffic launched a download PER REQUEST (measured: 12 concurrent scans =>
    12 simultaneous fetches).

    Measured impact (2026-07-27): during a refresh window every concurrent scan
    competed with the download for bandwidth, page-content fetches starved, the
    content model stopped voting, and recall fell from 73% to 40%. In
    production that is a daily, minutes-long halving of detection quality.

    The module already reads stale-ok, so the correct behaviour is to answer
    from the snapshot we have and let a single background worker catch up.
    """
    global _refresh_worker
    if _feeds_disabled() or not _any_feed_due():
        return None
    with _refresh_guard:
        if _refresh_worker is not None and _refresh_worker.is_alive():
            return _refresh_worker      # single-flight: one refresh serves all
        _refresh_worker = threading.Thread(target=_refresh_if_due_sync,
                                           name="phish-feeds-refresh",
                                           daemon=True)
        _refresh_worker.start()
        return _refresh_worker


def _lookup(url: str) -> dict:
    target = _normalize(url)
    host = _normalize_host(url)
    # A URL entry with no path or query is a HOST listing in disguise, so it
    # gets the domain layer's exemption: the live Phishing.Database links feed
    # lists https://amazon.com, which made www.amazon.com read MALICIOUS 90 on
    # 2026-10-01. A listed path (amazon-host.example/signin.php), or the bare
    # homepage of a host that is nobody's top site, still convicts.
    bare_exempt_host = bool(host) and target == host and _host_is_exempt(host)

    # URL layer first — the exact-match claim is the stronger one, so it is
    # the one reported when a host appears on both kinds of feed.
    for feed in active_feeds():
        entries = _sets.get(feed.url)
        if (feed.kind == "url" and entries and target and target in entries
                and not bare_exempt_host):
            return {"status": "flag",
                    "detail": f"listed on the {feed.label} URL feed",
                    "match": "url"}

    if host and not _host_is_exempt(host):
        for feed in active_feeds():
            entries = _sets.get(feed.url)
            if feed.kind == "domain" and entries and host in entries:
                return {"status": "flag",
                        "detail": f"host {host} listed on the {feed.label} domain feed",
                        "match": "domain"}

    if not _sets:
        return _UNAVAILABLE.copy()
    return _CLEAN.copy()


def warm_in_background() -> threading.Thread:
    """
    Start the first feed load off the request path and return the worker.

    The links feed is ~63 MB and takes over a minute cold — far beyond the
    per-scan source budget — so without this every scan in the first minute
    after a restart quietly loses the community blocklist. Called once at
    server startup; failures are swallowed exactly as they are per-scan
    (stale-ok, retry after _RETRY).
    """
    worker = threading.Thread(target=_refresh_if_due_sync,
                              name="phish-feeds-warm", daemon=True)
    worker.start()
    return worker


async def check_phish_feeds(url: str) -> dict:
    """
    Non-blocking feed-membership lookup for use inside full_scan().

    Genuinely non-blocking now: a due TTL refresh is handed to one background
    worker (see _refresh_due_in_background) and this call answers from the
    snapshot already in memory. Reading a slightly stale snapshot is the
    documented, intended behaviour — blocking a scan on a 63 MB download is not.
    """
    if _feeds_disabled():
        return _DISABLED.copy()
    if _any_feed_cold():
        # No snapshot at all: there is nothing to serve stale, and silently
        # answering "clean" would lose the source entirely. Load it. In a
        # deployment this is startup only, and warm_in_background() normally
        # gets there first (main.py calls it at import), so a request rarely
        # takes this path. A disk snapshot inside its TTL makes it near-free.
        await asyncio.to_thread(_refresh_if_due_sync)
    else:
        # Snapshot present but past its TTL: serve it and refresh behind the
        # scenes. This is the path that used to stall every scan for the
        # duration of a 63 MB download.
        _refresh_due_in_background()
    return _lookup(url)


# ---------------------------------------------------------------------------
# Self-test  (python -m apis.phish_feeds <url> ...)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    async def _main():
        targets = sys.argv[1:] or ["https://example.com/"]
        for t in targets:
            print(f"{t!r:60} -> {await check_phish_feeds(t)}")
        for feed in active_feeds():
            print(f"(snapshot: {len(_sets.get(feed.url, ())):>7,} {feed.kind} "
                  f"entries from {feed.label})")

    asyncio.run(_main())
