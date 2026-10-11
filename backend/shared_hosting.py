"""
Shared-hosting tenant classification — the single source of truth.

Lives outside aggregator.py so apis/typosquat.py can consult it too. aggregator
imports typosquat, so the classifier could not stay in aggregator without an
import cycle (audit finding 5, 2026-07-27): typosquat.py was applying the
"established registrable" exemption to tenant hosts, which switched brand
detection off for every tenant on a platform missing from the PSL private
section — robinhood-logint.gitbook.io and helptrezor-suite.wasmer.app both
scored 0, while the same label on pages.dev flagged at 72.

Public surface
-------------
  shared_hosting_class(host) -> "tenant" | "apex" | None
  is_shared_hosting_tenant(host) -> bool
  SHARED_HOSTING_SUFFIXES, TENANT_CONTENT_APEXES
"""

import tldextract

from provider_domains import is_provider_domain

# Bundled-snapshot PSL only (suffix_list_urls=()): no network fetch, no cache
# writes, fully deterministic. The private/ICANN pair identifies PSL
# PRIVATE-section suffixes (square.site, blogspot.com, …) = tenant platforms.
_PSL_PRIVATE = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
_PSL_ICANN = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)

# Shared-hosting platforms: every user subdomain / project is a SEPARATE,
# untrusted tenant. Visiting the PLATFORM apex (github.io itself) is reputable,
# but a tenant page (alice.github.io, proj.vercel.app, jxvtd.wasmer.app) is NOT
# blanket-capped — it is judged on CONTENT + corroborated ML so fresh phishing
# kits hosted on these platforms can still escalate (see full_scan). This also
# covers tenant-content CDN / object stores (S3, CloudFront, Fastly, Azure edge),
# which sit between "pure infra" and "shared hosting" and DO serve phishing.
SHARED_HOSTING_SUFFIXES = (
    "github.io", "pages.dev", "vercel.app", "netlify.app", "web.app",
    "firebaseapp.com", "wasmer.app", "workers.dev", "r2.dev", "glitch.me",
    "repl.co", "replit.app", "herokuapp.com", "onrender.com", "surge.sh",
    "azurewebsites.net",
    # Tenant platforms NOT on the PSL private section (which auto-covers
    # square.site, blogspot.com, …) — live FN 2026-07-14: gitbook.io kit.
    "gitbook.io",
    #
    # DELIBERATELY NOT EXTENDED (measured 2026-07-27). Adding the platforms that
    # carried audit misses — replit.dev, typedream.app, framer.website,
    # webflow.io, mybluehost.me, 000webhostapp.com, us.cc — made recall WORSE,
    # not better: 38% vs 73%, with 52 of 93 misses pinned at exactly 34.
    #
    # Mechanism: tenant classification is what triggers
    # `tenant_lexical_uncorroborated` in full_scan, which DROPS the lexical ML
    # from the blend unless something corroborates it. _weighted_score then
    # renormalises over the heuristic alone, so the score collapses to ~34 —
    # just under SUSPICIOUS. Listing a platform therefore SUPPRESSES detection
    # on it whenever the page content does not vote.
    #
    # So this list is a false-positive control, not a coverage list, and every
    # addition costs recall on that platform. Catching tenant phishing needs the
    # signals in ROAD_TO_90.md (page-content model, hostname entropy), not more
    # suffixes here. Revisit only once the content model votes reliably.
    #
    # Tenant-content CDN / object stores (customer-controlled paths/subdomains).
    "amazonaws.com", "cloudfront.net", "fastly.net", "fastlylb.net",
    "azureedge.net", "akamaized.net", "akamaihd.net",
)

# Tenant-content object stores that serve customer files from the APEX itself
# via path-style URLs (storage.googleapis.com/<bucket>/file) — the GCS
# equivalent of S3. Unlike a SHARED_HOSTING_SUFFIXES platform apex, even the
# bare apex hosts arbitrary customer (phishing) content, so the apex AND all
# subdomains are tenant-class: never blanket-reputable, judged on content +
# corroborated lexical signals. Checked BEFORE the provider allowlist, which
# would otherwise swallow *.googleapis.com.
TENANT_CONTENT_APEXES = (
    "storage.googleapis.com",
    "firebasestorage.googleapis.com",
)


def _psl_private_suffix(host: str) -> str | None:
    """
    The PSL PRIVATE-section suffix covering host ('square.site',
    'blogspot.com'), or None when host sits under a plain ICANN suffix.
    """
    try:
        priv = _PSL_PRIVATE(host).suffix
        icann = _PSL_ICANN(host).suffix
    except Exception:
        return None
    return priv if priv and priv != icann else None


def shared_hosting_class(domain: str) -> str | None:
    """
    'tenant'  — customer-controlled page (alice.github.io, x.square.site,
                storage.googleapis.com/<bucket>, bucket.s3.amazonaws.com),
    'apex'    — the shared-hosting platform itself (github.io, square.site),
    None      — not shared hosting.

    Beyond the manual lists, any host under a PSL PRIVATE-section suffix is a
    tenant: thousands of platforms (square.site, blogspot.com, …) register
    their tenant boundary on the Public Suffix List. Provider-allowlisted
    domains are exempt from the PSL fallback — googleapis.com is ALSO on the
    private PSL, and provider subdomains (fonts.googleapis.com) must stay
    provider-class, with their tenant stores handled by TENANT_CONTENT_APEXES.
    """
    d = (domain or "").lower().strip().rstrip(".")
    if not d:
        return None
    # Path-style object stores: the APEX itself serves customer content
    # (storage.googleapis.com/<bucket>/...), so apex AND subdomains are tenants.
    for apex in TENANT_CONTENT_APEXES:
        if d == apex or d.endswith("." + apex):
            return "tenant"
    for suf in SHARED_HOSTING_SUFFIXES:
        if d == suf:
            return "apex"
        if d.endswith("." + suf):
            return "tenant"
    if not is_provider_domain(d):
        priv = _psl_private_suffix(d)
        if priv:
            return "apex" if d == priv else "tenant"
    return None


def is_shared_hosting_tenant(domain: str) -> bool:
    """
    True for a user/project subdomain on a shared-hosting platform (e.g.
    alice.github.io, proj.vercel.app, x.square.site) — i.e. anything UNDER a
    shared suffix (manual lists + PSL private section), but NOT the bare
    platform apex itself.
    """
    return shared_hosting_class(domain) == "tenant"
