"""
Famous-domain exemption: a static Tranco top-1000 snapshot
(backend/data/top_domains.txt).

A registrable domain on this list IS the real site. Two consequences:
  * it cannot be a typosquat of some other brand (live eval FPs 2026-07-16:
    bbc.com convicted as a 'typosquat of hsbc', shopify.com as 'spotify'),
  * it stays reputable when the RDAP/WHOIS age lookup is rate-limited away
    (the age branch is neutral on failure by design, which left top sites
    unprotected under load).

Exact-registrable semantics: lookalikes (bbc-news-verify.xyz) and tenant
pages on popular platforms (alice.blogspot.com — whose PSL registrable keeps
the tenant label) are NOT exempt. Attackers cannot register these domains,
so the exemption cannot create false negatives.

Leaf module within the project (imports no project modules); uses tldextract
with the bundled offline PSL snapshot, same configuration as apis.typosquat.
"""
from pathlib import Path

import tldextract

# Offline PSL snapshot only (no network); private section INCLUDED so a
# tenant page keeps its label (amazon-login.blogspot.com stays whole and is
# never exempted through the platform's own popularity).
_tld_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

_DATA_PATH = Path(__file__).resolve().parent / "data" / "top_domains.txt"


def _load() -> frozenset:
    try:
        lines = _DATA_PATH.read_text(encoding="utf-8-sig").splitlines()
    except Exception:
        return frozenset()   # fail-safe: no file -> no exemption
    return frozenset(
        line.strip().lower().rstrip(".")
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    )


TOP_DOMAINS = _load()


# Established-domain check (BUG-4, 2026-07-18): a Tranco top-100k snapshot
# with WEAKER semantics than the top-1000 exemption above — "established"
# only means the registrable has real sustained traffic. It exonerates the
# non-deception typosquat techniques (dhl.de / google.lt / casa.it are real
# sites, not lookalikes of dhl.com / google.com / chase.com); it never skips
# scanning and never covers homoglyph/leetspeak shapes. Loaded lazily —
# most scans never need it.
_ESTABLISHED_PATH = Path(__file__).resolve().parent / "data" / "established_domains.txt"
_established: frozenset | None = None


def _load_established() -> frozenset:
    global _established
    if _established is None:
        try:
            lines = _ESTABLISHED_PATH.read_text(encoding="utf-8-sig").splitlines()
            _established = frozenset(
                line.strip().lower().rstrip(".")
                for line in lines
                if line.strip() and not line.lstrip().startswith("#")
            )
        except Exception:
            _established = frozenset()   # fail-safe: no file -> nothing exempt
    return _established


def is_established_registrable(registrable: str) -> bool:
    """Exact match: the PSL registrable is in the Tranco top-100k snapshot."""
    return (registrable or "").lower().strip().rstrip(".") in _load_established()


def is_established_registrable_host(host: str) -> bool:
    """Tenant-safe host check against the top-100k snapshot: www.dhl.de ->
    dhl.de -> True, but a tenant page keeps its PSL-private label
    (paypal-login.blogspot.com) and never inherits the platform's rank."""
    d = (host or "").lower().strip().rstrip(".")
    if not d:
        return False
    established = _load_established()
    if d in established:
        return True
    try:
        ext = _tld_extract(d)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}" in established
    except Exception:
        pass
    return False


def registrable_of(host: str) -> str:
    """The host's PSL registrable, private section included (tenant-safe):
    secure.bankofamerica.com -> bankofamerica.com; alice.github.io stays
    alice.github.io. Empty string when it cannot be determined."""
    d = (host or "").lower().strip().rstrip(".")
    try:
        ext = _tld_extract(d)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    except Exception:
        pass
    return ""


def is_top_registrable(registrable: str) -> bool:
    """Exact match: the PSL registrable itself is on the top list."""
    return (registrable or "").lower().strip().rstrip(".") in TOP_DOMAINS


def is_top_domain(host: str) -> bool:
    """True when host IS, or is a subdomain of, a top-list registrable
    (www.bbc.com -> bbc.com). Callers must handle shared-hosting tenants
    BEFORE this check — a suffix match alone does not prove first-party."""
    d = (host or "").lower().strip().rstrip(".")
    if not d:
        return False
    parts = d.split(".")
    return any(".".join(parts[i:]) in TOP_DOMAINS for i in range(len(parts) - 1))


def is_top_registrable_host(host: str) -> bool:
    """Tenant-safe host check: True when the host's PSL registrable (private
    section included) is on the top list. www.bbc.com -> bbc.com -> True;
    amazon-login.blogspot.com keeps its tenant label -> False."""
    d = (host or "").lower().strip().rstrip(".")
    if not d:
        return False
    if d in TOP_DOMAINS:
        return True
    try:
        ext = _tld_extract(d)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}" in TOP_DOMAINS
    except Exception:
        pass
    return False
