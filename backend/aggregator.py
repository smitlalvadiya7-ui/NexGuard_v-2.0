"""
Full-pipeline URL scan consumed by the /scan endpoint.

All I/O runs in parallel via asyncio.gather().  The result conforms to the
documented JSON contract:

  url, domain, resolved_ip, verdict, risk_score, confidence, ml_probability,
  ssl, redirects, scan_time_ms, flags, sources

Plus backward-compat fields: score, reasons, ai_explanation.

Score weighting
---------------
  ML           35 %   (local RandomForest)
  Heuristic    25 %   (rule-based, no network)
  Reputation   40 %   (VT 40 + GSB 35 + community-blocklist URL match 35 +
                       URLHaus 25 + community-blocklist domain match 20, cap 100)

Reputation only ADDS risk when a source ACTIVELY flags the URL.  Absence from
the blocklists (clean / not listed / unavailable / disabled) is NEUTRAL: the
source is dropped from the blend and the remaining weights are renormalised,
so a not-yet-listed brand-new phishing URL is never dragged down toward SAFE.

After blending, escalation floors are applied (see _escalate): a confirmed
reputation hit, a high ML phishing probability, or high-confidence typosquatting
each raise the score into the MALICIOUS band.

Verdict thresholds: >=70 MALICIOUS | 40-69 SUSPICIOUS | <40 SAFE
"""

import asyncio
import copy
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import unquote, urljoin, urlparse, urlsplit, urlunsplit

import requests as _http

# Side effect: fills missing env vars from backend/.env. Imported HERE, at the
# top of the shared scan path, so every entry point gets the API keys — not
# just main.py and telegram_bot.py, which were the only two that used to call
# load_dotenv(). See env_config for what that cost.
import env_config  # noqa: F401

from ai_engine import (heuristic_scan, _clean_url, SHORTENERS, TRUSTED_DOMAINS,
                       KEYWORD_WEIGHTS, is_valid_scan_url)
from apis import intel_pool
from apis.virustotal import check_virustotal
from apis.safe_browsing import check_safe_browsing
from apis.web_risk import check_web_risk
from deployment_profile import is_allowed as _source_allowed
from apis.blocklists import check_urlhaus
from apis.phish_feeds import check_phish_feeds
from apis.urlscan import check_urlscan
from apis.whois_geo import check_geo, check_whois
from apis.ssl_cert import check_ssl_cert
from apis.typosquat import check_typosquatting, _split_registrable
from apis.page_content import analyze_page_content
from ml.content_model import CONTENT_ACTIVE_PROB, content_phishing_probability
from apis.url_cache import cache_get, cache_put
from provider_domains import PROVIDER_REPUTABLE_DOMAINS, is_provider_domain, is_brand_tld_host
from shared_hosting import (SHARED_HOSTING_SUFFIXES, TENANT_CONTENT_APEXES,
                            _psl_private_suffix as _sh_psl_private_suffix,
                            is_shared_hosting_tenant, shared_hosting_class)
from top_domains import is_established_registrable, is_top_domain
from hostname_entropy import hostname_randomness

import tldextract

# Bundled-snapshot PSL only (suffix_list_urls=()): no network fetch, no cache
# writes, fully deterministic. The private/ICANN pair identifies PSL
# PRIVATE-section suffixes (square.site, blogspot.com, …) = tenant platforms.
_PSL_PRIVATE = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
_PSL_ICANN = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)

# Per-URL ML explainability (SHAP, with feature-importance fallback).
# Import-guarded so a missing model / SHAP never breaks a scan.
try:
    from ml.explain import explain_url as _explain_url
except Exception:
    try:
        from ml import explain as _ml_explain
        _explain_url = _ml_explain.explain_url
    except Exception:
        def _explain_url(url, top_n=5):
            return None


# ---------------------------------------------------------------------------
# Time budgets and the local-engine thread pool
# ---------------------------------------------------------------------------

# How long full_scan waits for each verdict-critical network source, for the
# local engine (rules + ML; only a cold model load is slow), and for the
# enrichment sources. Rate-limit waits and poll loops inside a source must stay
# SHORTER than its budget (apis/quota.py, apis/urlscan.py): a worker thread
# still busy after full_scan has moved on helps nobody and blocks the pool.
CRIT_BUDGET_S = 2.2
LOCAL_BUDGET_S = 8.0
ENRICH_BUDGET_S = 6.0

# The local engine gets threads of its own. On the shared default pool it
# queued behind network work; when rate-limited sources pinned that pool on
# 2026-09-29, heuristic_scan hit its budget and fell back to score 0 with no
# ML — paypal-secure-login.xyz (ML 1.0) came back UNKNOWN 0%. CPU-bound and
# fast, so a few threads are plenty and nothing slow ever lands here.
_LOCAL_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="nexguard-local")


def _local(fn, *args):
    """Run local CPU work (rules, ML, typosquat) on the dedicated pool."""
    return asyncio.get_running_loop().run_in_executor(_LOCAL_POOL, fn, *args)


# ---------------------------------------------------------------------------
# Blocking helpers — each called via asyncio.to_thread()
# ---------------------------------------------------------------------------

def _resolve_ip(domain: str):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


_CHAIN_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml",
}
_CHAIN_HTML_CAP = 2_000_000  # 2 MB terminal-page capture, reused by page_content


def _resolve_chain(url: str, max_hops: int = 5, budget_s: float = 2.0) -> dict:
    """
    Follow HTTP redirects (and thereby expand shorteners — a bit.ly link 301s to
    its target) to the FINAL destination, WITHOUT executing JavaScript. Iterative
    and loop-guarded; bounded by max_hops and an overall time budget. Captures the
    terminal text/html body so the content analyzer can reuse it (no second fetch).

    Returns {"chain": [url, ...], "final": str, "loop": bool, "truncated": bool,
             "html": str|None, "blocked_scheme": bool}.
    Always fail-safe: on any error returns the single-URL chain.
    """
    out = {"chain": [url], "final": url, "loop": False, "truncated": False,
           "html": None, "blocked_scheme": False}
    try:
        deadline = time.monotonic() + budget_s
        seen = {_normalise_url(url)}
        cur = url
        with _http.Session() as s:
            for _ in range(max_hops):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    out["truncated"] = True
                    break
                resp = s.get(
                    cur, allow_redirects=False, stream=True,
                    timeout=min(2.0, max(0.1, remaining)), headers=_CHAIN_HEADERS,
                )
                if 300 <= resp.status_code < 400 and resp.headers.get("Location"):
                    loc = resp.headers["Location"].strip()
                    resp.close()
                    # Non-web schemes are never followed (data:/javascript:/mailto:).
                    low = loc.lower()
                    if low.startswith(("data:", "javascript:", "mailto:", "tel:")):
                        out["blocked_scheme"] = True
                        break
                    nxt = urljoin(cur, loc)
                    norm = _normalise_url(nxt)
                    if norm in seen:
                        out["loop"] = True
                        out["chain"].append(nxt)
                        cur = nxt
                        break
                    seen.add(norm)
                    out["chain"].append(nxt)
                    cur = nxt
                    continue
                # Terminal response: capture HTML body within the byte cap.
                ctype = resp.headers.get("Content-Type", "").lower()
                if "html" in ctype or "xml" in ctype:
                    try:
                        raw = resp.raw.read(_CHAIN_HTML_CAP, decode_content=True)
                        out["html"] = raw.decode(resp.encoding or "utf-8", errors="replace")
                    except Exception:
                        out["html"] = None
                resp.close()
                break
            else:
                out["truncated"] = True
        out["final"] = cur
        return out
    except Exception:
        return out


def _normalise_url(url: str) -> str:
    """
    Canonical form for cache keys and loop detection: lowercase scheme + host,
    strip default ports and the fragment, KEEP the query (phishing kits vary
    content by ?id=...), preserve path case.
    """
    try:
        p = urlsplit(url)
        scheme = (p.scheme or "https").lower()
        host = (p.hostname or "").lower().rstrip(".")
        if p.port and not ((scheme == "http" and p.port == 80) or
                           (scheme == "https" and p.port == 443)):
            host = f"{host}:{p.port}"
        return urlunsplit((scheme, host, p.path or "/", p.query, ""))
    except Exception:
        return (url or "").strip().lower()


async def _budget(awaitable, fallback, timeout: float):
    """Await with a hard per-source timeout; any timeout/error -> neutral fallback."""
    try:
        return await asyncio.wait_for(awaitable, timeout=timeout)
    except (asyncio.TimeoutError, Exception):
        return fallback


async def _noop(value):
    """Return a value as a completed coroutine (used to skip a source cleanly)."""
    return value


def _domain_from_url(url: str) -> str:
    parsed = urlparse(url)
    d = (parsed.netloc or parsed.path).lower().split("@")[-1].split(":")[0]
    return d[4:] if d.startswith("www.") else d


def _root_of(domain: str) -> str:
    parts = (domain or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (domain or "")


# ---------------------------------------------------------------------------
# Reputable-host detection (FIX 1) — maintained provider allowlist
# ---------------------------------------------------------------------------
# PROVIDER_REPUTABLE_DOMAINS (imported above) lives in provider_domains.py so
# ai_engine (brand impersonation) and apis.typosquat (self-impersonation
# exemption) share the exact same list without an import cycle.

# Shared-hosting tenant classification now lives in shared_hosting.py so
# apis/typosquat.py can consult the same lists without an import cycle (audit
# finding 5, 2026-07-27). Re-exported here under the original private names so
# existing call sites and tests keep working.

# Domains reputable in their own right + every provider apex (used by the final
# allowlist safety net). github.io is intentionally NOT here: a tenant page on it
# must be allowed to reach MALICIOUS on real content evidence.
REPUTABLE_DOMAINS = set(PROVIDER_REPUTABLE_DOMAINS) | {"github.com"}


def _host_matches(domain: str, names) -> bool:
    """True when domain equals, or is a subdomain of, any name in `names`."""
    d = (domain or "").lower().strip().rstrip(".")
    if not d:
        return False
    for n in names:
        if d == n or d.endswith("." + n):
            return True
    return False


_psl_private_suffix = _sh_psl_private_suffix
_shared_hosting_class = shared_hosting_class
_is_shared_hosting_tenant = is_shared_hosting_tenant


def _is_reputable_host(domain: str, ssl: bool, who_res: dict,
                       include_established: bool = True) -> bool:
    """
    True when the host is reputable enough that WEAK lexical signals (security
    keywords in the path, an ML probability driven by path tokens like
    'phishing'/'login') must not push it past SUSPICIOUS on their own:

      * a maintained CDN / API / infrastructure provider — and ALL its subdomains
        (googleapis.com, doubleclick.net, microsoftonline.com, apple-dns.net, …),
      * github.com / *.github.com,
      * the bare apex of a shared-hosting platform (github.io itself) — but NOT a
        tenant page on it (alice.github.io), which is judged on content + ML,
      * any valid-HTTPS domain older than ~1 year (per WHOIS/RDAP age), EXCEPT a
        shared-hosting tenant (the platform's apex age says nothing about a tenant).

    A timed-out / unavailable RDAP lookup yields age=None, so the age branch is
    NEUTRAL on failure (it grants nothing and adds nothing).

    include_established
        Whether the offline Tranco top-100k snapshot (branch 3c) counts. It
        exists to suppress FALSE POSITIVES on ordinary established sites when
        RDAP is throttled, so it is on by default.

        full_scan passes False for its `fast_reputable` fetch-skip decision,
        because that answers a DIFFERENT question — "may we skip fetching the
        page?" — and the snapshot is the wrong answer to it, twice over
        (measured 2026-07-27):

          * skipping the content check removed the signal that had been
            DILUTING a suspicious-TLD flag, pushing 9 legitimate .ru/.xyz
            domains from ~20 to exactly 40 (SUSPICIOUS);
          * a COMPROMISED established site would never have its kit page
            inspected — smithandsmith.co.za/mezzlesolicitors in the audit
            corpus — and that is the hardest miss shape there is.

        Being popular means "probably not a typosquat", never "not serving a
        phishing kit today".
    """
    d = (domain or "").lower().strip().rstrip(".")
    if not d:
        return False

    # 0) Tenant-content object stores (GCS / Firebase Storage): customer
    #    content is served from the apex itself, so NOTHING under these is
    #    blanket-reputable. Must run before the provider allowlist, which
    #    would otherwise match *.googleapis.com.
    for apex in TENANT_CONTENT_APEXES:
        if d == apex or d.endswith("." + apex):
            return False

    # 1) Maintained provider allowlist — provider apex + all subdomains,
    #    including closed brand TLDs (.google/.microsoft/.apple).
    if is_provider_domain(d):
        return True

    # 2) Shared hosting (manual lists + PSL private section): the platform
    #    apex is reputable; a tenant page is NOT — and it returns here, before
    #    the age branch, so an old PLATFORM registration can't whitewash a
    #    tenant (live FN mechanism: gitbook.io / square.site kits, 2026-07-14).
    cls = _shared_hosting_class(d)
    if cls == "apex":
        return True
    if cls == "tenant":
        return False

    # 3) github.com and other named reputable roots.
    parts = d.split(".")
    root = ".".join(parts[-2:]) if len(parts) >= 2 else d
    if d in REPUTABLE_DOMAINS or root in REPUTABLE_DOMAINS:
        return True

    # 3b) Famous-domain snapshot (Tranco top-1000, backend/data/): reputable
    #     independent of the RDAP age lookup, whose 429-neutrality left top
    #     sites unprotected under rate-limit load (eval FPs 2026-07-16:
    #     mail.ru, bbc.com, webex.com…). Runs AFTER the tenant checks above,
    #     so a tenant page on a popular platform is never whitewashed.
    if is_top_domain(d):
        return True

    # 3c) Established-domain snapshot (Tranco top-100k, offline, no network).
    #     Gated on include_established — see the docstring. full_scan's
    #     fetch-skip passes False so an established host is still INSPECTED.
    #     Audit finding 3 (2026-07-27): reputability rested on branch 4's RDAP
    #     age, and RDAP answers HTTP 429 under load — the circuit breaker then
    #     opens for the whole process, so `age` is None for every later scan.
    #     Measured: schneier.com, findagrave.com and sport.pl each flipped
    #     SAFE -> SUSPICIOUS on nothing but RDAP availability, because none is
    #     in the top-1000 list checked at 3b. On one shared cloud egress IP a
    #     throttled RDAP is the steady state, so reputability must not depend
    #     on it. This widens 3b's snapshot from top-1000 to the top-100k file
    #     already bundled at data/established_domains.txt — the same source
    #     typosquat.py uses — and needs no lookup at all.
    #
    #     An UNKNOWN age still grants nothing (test_rdap_unavailable_is_neutral):
    #     a brand-new domain must not become reputable just because RDAP is
    #     down. Runs AFTER the tenant checks, so a tenant page on an
    #     established platform is never whitewashed.
    if include_established:
        registrable, _ = _split_registrable(d)
        if is_established_registrable(registrable):
            return True

    # 4) Generic: valid HTTPS + domain older than ~1 year (per RDAP age).
    if ssl and "yr" in (who_res.get("age") or ""):
        return True
    return False


# ---------------------------------------------------------------------------
# Score helpers
# ---------------------------------------------------------------------------

def _google_reputation(url: str):
    """
    Google's threat corpus, through whichever API this build is licensed for.

    Safe Browsing v4 is "for non-commercial use only"; Web Risk is the
    commercial equivalent and its Lookup API is free for the first 100,000 calls
    a month. Same corpus, same {status, detail} shape, so everything downstream
    is unchanged — only the licence differs.
    """
    if _source_allowed("safe_browsing_v4"):
        return check_safe_browsing(url)
    return check_web_risk(url)


def _reputation_score(vt: dict, gsb: dict, urlhaus: dict,
                      feeds: dict | None = None) -> tuple:
    """
    Returns (rep_score 0-100, n_confirmed_flags, active).

    Reputation ONLY adds risk when a source actively flags the URL.  A
    'clean' / 'not listed' / 'unavailable' / 'disabled' result contributes
    nothing and must never lower the score — when no source flags, `active`
    is False and reputation is dropped from the blend entirely (see
    _weighted_score), rather than averaged in as a 0.

    Source weights (cap 100):
      VT flag=40  VT warn=20   (warn = VirusTotal>0 engines = an active hit)
      GSB flag=35
      Community blocklist, exact-URL match=35 — an OpenPhish /
        Phishing.Database URL listing is a confirmed hit, like a GSB flag
      URLHaus flag=25
      Community blocklist, bare-host match=20 — a weaker claim than the exact
        URL: those feeds also carry shared platforms and legitimate sites
        listed after a one-off compromise, so a host hit contributes real risk
        but never convicts alone (see the rep_strong derivation in full_scan)
    """
    score = 0
    n = 0
    if vt["status"] == "flag":
        score += 40
        n += 1
    elif vt["status"] == "warn":
        score += 20
        n += 1
    if gsb["status"] == "flag":
        score += 35
        n += 1
    if urlhaus["status"] == "flag":
        score += 25
        n += 1
    if feeds is not None and feeds["status"] == "flag":
        score += 20 if feeds.get("match") == "domain" else 35
        n += 1
    return min(score, 100), n, score > 0


def _weighted_score(h_score: int, ml_prob, rep_score: int, rep_active: bool,
                    content_prob=None) -> int:
    """
    Blend only the signals that are actually available, renormalising the
    weights so an absent source is NEUTRAL (never averaged in as a 0):

      ML 0.35 (when available) + heuristic 0.25 (always) +
      reputation 0.40 (only when a source actively flags) +
      content model 0.30 (M2 — only when the fetched page casts a real vote,
      i.e. probability >= CONTENT_ACTIVE_PROB; pass None otherwise).
    """
    parts = [(0.25, float(h_score))]                     # heuristic: always available
    if ml_prob is not None:
        parts.append((0.35, float(ml_prob) * 100.0))
    if rep_active:
        parts.append((0.40, float(rep_score)))
    if content_prob is not None:
        parts.append((0.30, float(content_prob) * 100.0))
    total_w = sum(w for w, _ in parts)
    raw = sum(w * v for w, v in parts) / total_w
    return max(0, min(100, int(round(raw))))


# Verdict band boundaries. Named so every rule that must sit relative to a band
# edge can reference it instead of repeating a literal — see
# _cap_weak_heuristic_only, whose cap has to track SUSPICIOUS_MIN exactly.
MALICIOUS_MIN = 70
SUSPICIOUS_MIN = 40


def _cap_weak_heuristic_only(score: int, *, weak_signal_capped: bool,
                             rep_active: bool, content_voted: bool,
                             strong_flags: int) -> int:
    """
    Keep a reputable, wholly-quiet host below SUSPICIOUS.

    Invariant this enforces: recognising a host as reputable must never RAISE
    its score. It can, via a subtlety in the renormalising blend — being
    reputable makes a host weak_signal_capped, which DROPS the uncorroborated
    lexical ML from the blend, and _weighted_score then renormalises over
    whatever parts remain. With reputation silent and no content vote, the only
    part left is the heuristic, so its 25% weight carries 100% of the verdict
    and the blended score becomes h_score exactly.

    Measured 2026-07-27: nine legitimate domains (beget.ru, nic.xyz,
    smotrim.ru, yandex-team.ru, stocrm.ru, xbox-dns.ru, joinserver.xyz,
    vseinstrumenti.ru, bysex.click) went from ~20 to EXACTLY 40 that way —
    40 being h_score for a lone "Suspicious domain extension" flag. A national
    TLD like .ru carries millions of legitimate sites and cannot convict alone.

    A reputable host with NO active reputation hit, NO content vote and NO
    strong flag has nothing against it but weak lexical noise, which is the
    definition of "not enough to flag" — so it is held below the SUSPICIOUS
    threshold. Every escape hatch stays open: a page that actually votes
    (a compromised established site serving a kit), any strong flag, or an
    active reputation hit all bypass this cap entirely.

    Only ever lowers a score.

    The cap is SUSPICIOUS_MIN - 1, not a literal 39: 15 legitimate domains in
    the 216-URL corpus land exactly ON it, so a future threshold change that
    left the cap behind would convert all 15 into false positives in one step
    (FP 1 -> 16, FPR 0.46% -> 7.41%). Tying them together makes that impossible.
    """
    if (weak_signal_capped and not rep_active and not content_voted
            and strong_flags <= 0):
        return min(score, SUSPICIOUS_MIN - 1)
    return score


def _verdict(score: int) -> str:
    if score >= MALICIOUS_MIN:
        return "MALICIOUS"
    if score >= SUSPICIOUS_MIN:
        return "SUSPICIOUS"
    return "SAFE"


# A VirusTotal detection by FEWER than this many engines is a WEAK, low-confidence
# hit: on its own it floors the verdict at SUSPICIOUS, not MALICIOUS (a single AV
# engine flagging a URL is frequently a false positive). Other blocklists
# (Safe Browsing / URLHaus / an exact-URL community-blocklist listing) and a VT
# detection by >= this many engines remain STRONG hits that escalate to
# MALICIOUS. Override via NEXGUARD_VT_MIN_ENGINES.
import os as _os
try:
    VT_MIN_ENGINES_FOR_MALICIOUS = max(1, int(_os.getenv("NEXGUARD_VT_MIN_ENGINES", "2")))
except Exception:
    VT_MIN_ENGINES_FOR_MALICIOUS = 2
# Where a weak (single-engine VT) hit floors the score — solidly SUSPICIOUS.
WEAK_REP_SUSPICIOUS_FLOOR = 60

# The lexical ML may not convict a domain ON ITS OWN at ANY confidence
# (reputation silent, no corroborating strong flag, heuristics quiet).
# Originally a 0.5-0.75 mid-band rule (2026-07-16, "a lone mid-band ML never
# convicts"); the M1 retrain on fresh feed data sharpened the same lexical
# shape (ordinary hyphenated multi-word .com domains) to 0.97+, so the band
# no longer contains the failure mode — the corroboration REQUIREMENT is the
# real rule, exactly as the tenant / reputable-host / keyword gates already
# apply it. Corroborated or loud-heuristic scans keep the full ML channel,
# including its >= 0.85 escalation floors.


def _escalate(score: int, rep_strong, rep_weak: bool, ml_prob,
              strong_flags: int, typo_conf: int) -> int:
    """
    Raise the blended score into the correct band when a decisive signal is
    present.  Escalation only ever floors the score upward — it never lowers it.

      * a STRONG reputation hit (GSB/URLHaus/an exact-URL community-blocklist
        listing, a blocklisted redirect hop, or VT flagged by
        >= VT_MIN_ENGINES_FOR_MALICIOUS engines)
                                                     -> MALICIOUS (>= 90);
        TWO OR MORE independent confirmed sources    -> full 100
        (`rep_strong` is the confirmed-source count; bool True == 1 source.
        User report 2026-07-19: confirmed-risky links used to stop at 80.)
      * a WEAK reputation hit (a single-engine VT detection, nothing else)
                                                     -> SUSPICIOUS (>= 60, NOT malicious)
      * ML phishing prob >= 0.85 + strong heuristics -> MALICIOUS (>= 78)
      * ML phishing prob >= 0.85 alone             -> SUSPICIOUS (>= 69, NOT malicious)
      * high-confidence typosquatting / homoglyph  -> >= 70
        (medium confidence -> SUSPICIOUS floor of 55)

    MALICIOUS requires a strong/confirmed signal — a single AV engine or a high ML
    probability ALONE caps at SUSPICIOUS to cut false positives, and only
    CONFIRMED sources can push the score to 90/100 (probability paths cannot).
    """
    if rep_strong:
        score = max(score, 100 if int(rep_strong) >= 2 else 90)
    elif rep_weak:
        score = max(score, WEAK_REP_SUSPICIOUS_FLOOR)

    if ml_prob is not None and ml_prob >= 0.85:
        score = max(score, 78 if strong_flags >= 1 else 69)

    if typo_conf >= 80:
        score = max(score, 70)
    elif typo_conf >= 66:
        score = max(score, 55)

    return max(0, min(100, score))


# Confidence cost of each reputation source that could not be reached. Four
# sources exist, so a completely blind scan loses 40 points — enough to read as
# "do not lean on this" without pretending the URL is dangerous.
CONFIDENCE_PENALTY_PER_MISSING_SOURCE = 10


def _confidence(h_score: int, ml_prob, vt: dict, gsb: dict, urlhaus: dict,
                feeds: dict | None, verdict: str, content_risk: int = 0,
                content_voted: bool = False) -> int:
    """
    How strongly the AVAILABLE signals agree with the final verdict (0-100).

    Confidence is agreement across whichever signals are actually present (ML,
    reputation, heuristic, content) — never a fixed number when signals exist.
    Reputation sources only cast a vote when they ACTIVELY flag the URL; absence
    from a blocklist (clean / not listed / unavailable / disabled) is neutral and
    excluded, mirroring the scoring rules. This prevents a not-yet-listed
    brand-new phishing URL from reading as "low confidence".
    """
    is_threat = verdict in ("MALICIOUS", "SUSPICIOUS")
    opinions = []

    # Heuristic + ML always vote (when available).
    opinions.append(h_score >= 35)
    if ml_prob is not None:
        opinions.append(ml_prob >= 0.5)

    # Content analysis votes only when the page was actually inspected.
    if content_voted:
        opinions.append(content_risk >= 45)

    # Reputation: only an active hit is a meaningful vote (always "threat").
    if vt["status"] in ("flag", "warn"):
        opinions.append(True)
    if gsb["status"] == "flag":
        opinions.append(True)
    if urlhaus["status"] == "flag":
        opinions.append(True)
    if feeds is not None and feeds["status"] == "flag":
        opinions.append(True)

    if not opinions:
        return 50

    agreeing = sum(1 for o in opinions if o == is_threat)
    score = int(round(agreeing / len(opinions) * 100))

    # A verdict resting on fewer sources cannot be as confident as the same
    # verdict backed by all of them. Sources that returned "unavailable" never
    # ran at all — no key, a rate limit, an open breaker — so each one costs
    # confidence. Only applied to a SAFE verdict: when something DID flag the
    # URL, the missing sources could not have changed the outcome.
    #
    # This does not touch the risk score. An absent source is neutral evidence,
    # not evidence of risk; the honest response to "we could not check" is less
    # certainty, never more alarm.
    if not is_threat:
        missing = sum(1 for src in (vt, gsb, urlhaus, feeds)
                      if (src or {}).get("status") == "unavailable")
        if missing:
            score = max(0, score - CONFIDENCE_PENALTY_PER_MISSING_SOURCE * missing)
    return score


def _dedupe(items):
    seen = set()
    out = []
    for item in items:
        if item and item not in seen:
            out.append(item)
            seen.add(item)
    return out


_FB_SRC = {"status": "unavailable", "detail": "unavailable"}
# The community blocklist carries a third key: which layer matched.
_FB_FEED = {"status": "unavailable", "detail": "unavailable", "match": None}
_FB_HEU = {"score": 0, "flags": [], "ml_prob": None}
_FB_URLSCAN = {
    "screenshot_url": None,
    "page_title": None,
    "final_url": None,
    "malicious": False,
    "score": 0,
}
_FB_GEO = {"ip_location": None, "ip_country": None, "asn": None, "hosting": None}
_FB_WHOIS = {"registrar": None, "created": None, "age": None, "country": None,
             "age_days": None}
_FB_SSL = {
    "has_cert": False, "issuer": None, "is_free_ca": False, "issued": None,
    "expires": None, "cert_age_days": None, "days_to_expiry": None,
    "san_count": None, "subject_cn": None, "detail": "unavailable",
}
# A domain registered within this many days counts as "new" (higher risk).
NEW_DOMAIN_DAYS = 90
# A TLS cert minted within this many days is "brand-new".
NEW_CERT_DAYS = 21
_FB_TYPO = {"is_typosquat": False, "impersonated_brand": None, "technique": None, "confidence": 0}
_FB_CONTENT = {
    "has_password_field": False, "has_login_form": False,
    "external_form_action": False, "brand_mismatch": False,
    "title_brand_mismatch": False, "favicon_brand_mismatch": False,
    "js_redirect": False, "login_keywords_near_form": False,
    "external_resource_count": 0,
    "suspicious_signals": [], "content_risk": 0, "fetched": False,
}


def _plain_summary(verdict: str, n_flagged: int) -> str:
    """One-line, human-readable sentence describing the verdict."""
    if verdict == "MALICIOUS":
        if n_flagged >= 1:
            return "Confirmed phishing — do not enter login or payment details."
        return "Dangerous site — do not enter login or payment details."
    if verdict == "SUSPICIOUS":
        return "Looks suspicious — proceed with caution and avoid sharing personal info."
    if verdict == "ERROR":
        return "Could not complete the scan — treat this link with caution."
    return "Looks safe."


def _unwrap(val, fallback: dict) -> dict:
    """Return fallback if val is an exception (from gather return_exceptions=True)."""
    return fallback if isinstance(val, BaseException) else val


def _reputation_all_unavailable(*source_results: dict) -> bool:
    """True when EVERY reputation source given came back 'unavailable'.

    A source falls back to ``detail == "unavailable"`` on any transient failure
    (rate-limit, network blip, cold start, missing key).  When *all* of them do,
    the scan's "all clean" reputation is not a real verdict — it just reflects a
    momentary outage.  Persisting that into the 1-hour full-scan cache would keep
    serving "all APIs unavailable" long after the sources recover, so we refuse
    to cache it.  Mirrors the per-source ``url_cache`` rule ("only store
    definitive results, never 'unavailable'").

    A source counts as unavailable by its status as well as its detail: a
    rate-limited VirusTotal keeps status "unavailable" but says so in the
    detail, and checking the detail alone let such scans into the cache
    (2026-10-09, tests/test_batch_unknown_recheck.py).
    """
    active = [r for r in source_results if r]
    return bool(active) and all(
        r.get("status") == "unavailable" or r.get("detail") == "unavailable"
        for r in active
    )


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def full_scan(url: str, save_fn=None, previews: bool = True) -> dict:
    """
    Parallel full-pipeline scan.

    Parameters
    ----------
    url      : raw URL string (will be cleaned internally)
    save_fn  : optional callable(module, result, target) to persist to the DB
               (pass main.save_scan from the FastAPI app)
    previews : False skips the urlscan.io screenshot and the ML explanation.
               Both are display only and never touch the verdict. A batch
               drops them anyway, and waiting for the screenshot made a
               100-URL batch take 49.9 s instead of 19.9 s
               (tests/test_batch_no_previews.py). Such a result is not cached,
               so a later single scan still gets its previews.
    """
    t0 = time.perf_counter()

    # ------------------------------------------------------------------
    # Payload-scheme gate (javascript:/data:/vbscript:/blob:) — checked on the
    # RAW input BEFORE _clean_url (which can prepend http:// and mask the
    # scheme). Such a "URL" is not a destination at all: the link itself IS an
    # executable/script payload, the classic QR-code / pasted-link XSS vector,
    # and was previously reported SAFE at 100 confidence (verified at the live
    # /scan surface). Matched the way browsers parse it — percent-decoded,
    # whitespace/control characters stripped — so %6Aavascript: and
    # "java\tscript:" don't slip through. Floors at SUSPICIOUS, not MALICIOUS:
    # there is no reputation evidence, but no legitimate reason to scan one.
    # (Embedded-link extraction matches https?:// only, so mail/page scans
    # with javascript:void(0) hrefs never reach this path.)
    raw_head = re.sub(r"[\s\x00-\x1f]+", "", unquote((url or "").strip())[:64]).lower()
    _m_scheme = re.match(r"^([a-z][a-z0-9+.\-]*):", raw_head)
    if _m_scheme and _m_scheme.group(1) in ("javascript", "data", "vbscript", "blob"):
        scheme = _m_scheme.group(1)
        payload_flags = [
            f"Link uses the non-web scheme '{scheme}:' — it carries an "
            "executable/script payload, not a website address",
            "Script/data URIs are a common phishing and XSS delivery vector "
            "— do not open this link",
        ]
        result = {
            "url": url, "final_url": url, "domain": "", "resolved_ip": None,
            "verdict": "SUSPICIOUS", "risk_score": 60, "score": 60,
            "confidence": 85, "ml_probability": None, "content_probability": None,
            "ssl": False, "redirects": [], "redirect_chain": [url],
            "structural_flags": [], "cached": False,
            "scan_time_ms": int(round((time.perf_counter() - t0) * 1000)),
            "flags": payload_flags, "sources": [],
            "reasons": list(payload_flags),
            "ai_explanation": (
                f"This link does not lead to a website — its '{scheme}:' scheme "
                "embeds executable content directly in the link. Treat it as "
                "unsafe and do not open it."
            ),
            "plain_summary": _plain_summary("SUSPICIOUS", 0),
        }
        if save_fn:
            save_fn("URL Scanner", result, url)
        return result

    raw_input = url
    url = _clean_url(url)
    # Not a web address at all -> ERROR, never a verdict. On 2026-09-29 a
    # comment fragment ('https://rules and (if keys are set) ...') was graded
    # SAFE 0% because Safe Browsing answered "not listed" for it, and
    # 'https://www.apple.com    # expected: SAFE' failed DNS as a host with
    # spaces in it. Nothing about such input is safe or unsafe; it is invalid.
    if not url or not is_valid_scan_url(url):
        reason = "Empty URL" if not url else "Invalid URL format"
        result = {
            "url": url, "final_url": url, "domain": "", "resolved_ip": None,
            "verdict": "ERROR", "risk_score": 0, "score": 0,
            "confidence": 0, "ml_probability": None, "content_probability": None,
            "ssl": False, "redirects": [], "redirect_chain": [],
            "structural_flags": [], "cached": False,
            "scan_time_ms": int(round((time.perf_counter() - t0) * 1000)),
            "flags": [reason], "sources": [],
            "reasons": [reason],
            "ai_explanation": (
                "Empty URL." if not url else
                "This is not a valid web address, so it was not scanned. Check "
                "for spaces, a missing domain, or text pasted after the link."),
            "plain_summary": ("Not scanned — empty input." if not url else
                              "Not scanned — this is not a valid web address."),
        }
        if save_fn:
            save_fn("URL Scanner", result, raw_input)
        return result

    # ------------------------------------------------------------------
    # Result cache — repeat scans of the same normalised URL are instant.
    # ------------------------------------------------------------------
    cache_key = "scan:" + _normalise_url(url)
    cached = cache_get(cache_key)
    if cached is not None:
        # Deep copy so the caller (and strip_premium / QR/email post-processing)
        # can mutate freely without corrupting the cached entry.
        result = copy.deepcopy(cached)
        result["cached"] = True
        result["scan_time_ms"] = int(round((time.perf_counter() - t0) * 1000))
        if save_fn:
            save_fn("URL Scanner", result, url)
        return result

    # ------------------------------------------------------------------
    # Redirect-chain resolution FIRST — score the FINAL destination, not the
    # entered link. Shorteners (bit.ly, t.co, ...) expand implicitly; the
    # terminal HTML is captured for reuse by the content analyzer.
    # ------------------------------------------------------------------
    entered_domain = _domain_from_url(url)
    chain_info = await _budget(
        asyncio.to_thread(_resolve_chain, url),
        {"chain": [url], "final": url, "loop": False, "truncated": False,
         "html": None, "blocked_scheme": False},
        2.0,
    )
    scan_url = chain_info.get("final") or url
    prefetched_html = chain_info.get("html")
    chain = chain_info.get("chain") or [url]
    redirects = chain if len(chain) > 1 else []

    domain = _domain_from_url(scan_url)
    ssl = scan_url.startswith("https://")
    root = _root_of(domain)

    # Structural redirect risk (no extra network). A cross-domain landing and a
    # shortener expansion are EXPECTED/benign, so they're informational only — the
    # verdict comes from scanning the final destination. Genuinely sketchy chain
    # shapes (loops, excessive hops, non-web scheme) do add risk.
    entered_reg, _ = _split_registrable(entered_domain) if entered_domain else ("", "")
    final_reg, _ = _split_registrable(domain) if domain else ("", "")
    hop_count = max(0, len(chain) - 1)
    structural_flags: list = []
    structural_risk = 0
    if (entered_domain in SHORTENERS or _root_of(entered_domain) in SHORTENERS) and scan_url != url:
        structural_flags.append(f"Shortened link expanded to '{domain}'")
    if entered_reg and final_reg and entered_reg != final_reg:
        structural_flags.append(f"Redirect crosses domains: '{entered_reg}' -> '{final_reg}'")
    if hop_count >= 4:
        structural_flags.append(f"Long redirect chain ({hop_count} hops)")
        structural_risk = max(structural_risk, 30)
    if chain_info.get("loop"):
        structural_flags.append("Redirect loop detected")
        structural_risk = max(structural_risk, 45)
    if chain_info.get("blocked_scheme"):
        structural_flags.append("Redirect to a non-web scheme (data:/javascript:)")
        structural_risk = max(structural_risk, 45)
    # A redirect hop already known-bad in the WARM blocklist cache is a real hit
    # (zero new network: we only read the URLHaus cache populated by prior scans).
    hop_blocklisted = False
    for hop in chain:
        c = cache_get("uh:" + hop)
        if isinstance(c, dict) and c.get("status") == "flag":
            hop_blocklisted = True
            structural_flags.append("A redirect hop is on a blocklist")
            break

    # ------------------------------------------------------------------
    # Reputable fast-path: skip the heavy page render + urlscan for clearly
    # low-risk reputable domains (keeps p95 well under budget). whois is not yet
    # available here, so age-based reputable detection is deferred — the explicit
    # allowlists/suffixes cover the common reputable cases up front.
    # ------------------------------------------------------------------
    # include_established=False: a merely POPULAR domain must still have its page
    # inspected — it can be compromised and serving a kit. Only explicitly
    # trusted / provider / platform-apex hosts earn the fetch skip.
    fast_reputable = (
        domain in TRUSTED_DOMAINS or root in TRUSTED_DOMAINS
        or _is_reputable_host(domain, ssl, {}, include_established=False)
    )
    content_task = (
        _noop(_FB_CONTENT.copy()) if fast_reputable
        else asyncio.to_thread(analyze_page_content, scan_url, prefetched_html)
    )

    # ------------------------------------------------------------------
    # Verdict-critical sources — each capped (asyncio.wait_for) so one slow
    # source can never block the verdict; a timeout is treated as 'unavailable'
    # (neutral), consistent with the renormalising blend.
    # ------------------------------------------------------------------
    CRIT = CRIT_BUDGET_S
    # heuristic_scan is LOCAL CPU (no network); only the one-time cold ML-model
    # load is slow, so it gets a larger budget than the network sources. In the
    # running server the model is pre-warmed at startup and this returns in ms.
    # It runs on its own pool (_LOCAL_POOL) so network threads can never starve it.
    LOCAL = LOCAL_BUDGET_S
    crit = await asyncio.gather(
        _budget(_local(heuristic_scan, scan_url),               _FB_HEU.copy(),     LOCAL),
        # Reputation lookups run on their own threads (apis.intel_pool): on the
        # default pool they queued behind slow page/enrichment work and were
        # cancelled before they started (tests/test_intel_pool.py).
        _budget(intel_pool.run(check_virustotal, scan_url),     _FB_SRC.copy(),     CRIT),
        _budget(_google_reputation(scan_url),                   _FB_SRC.copy(),     CRIT),
        _budget(check_urlhaus(scan_url),                        _FB_SRC.copy(),     CRIT),
        # Community blocklist membership: in-memory snapshot lookup after the
        # first fetch. A cold fetch can outlive the budget — it still completes
        # in its thread, so the snapshot is warm for every later scan.
        _budget(check_phish_feeds(scan_url),                    _FB_FEED.copy(),    CRIT),
        _budget(_local(check_typosquatting, domain),            _FB_TYPO.copy(),    CRIT),
        _budget(asyncio.to_thread(_resolve_ip, domain),         None,              CRIT),
        _budget(content_task,                                   _FB_CONTENT.copy(), CRIT),
    )
    (h_res, vt_res, gsb_res, uh_res, feed_res, typo_res, resolved_ip,
     content_res) = crit

    # ------------------------------------------------------------------
    # Enrichment sources — NEVER gate the verdict. Started concurrently and
    # awaited briefly; whatever hasn't returned is cancelled and falls back to a
    # neutral value so the response is always complete.
    # ------------------------------------------------------------------
    enrich_tasks = {
        "whois": asyncio.ensure_future(check_whois(domain)),
        "geo": asyncio.ensure_future(check_geo(domain)),
    }
    if previews:
        enrich_tasks["explain"] = asyncio.ensure_future(asyncio.to_thread(_explain_url, scan_url))
    # TLS certificate inspection — only meaningful for HTTPS endpoints.
    if ssl:
        enrich_tasks["sslcert"] = asyncio.ensure_future(check_ssl_cert(domain))
    if previews and not fast_reputable:
        enrich_tasks["urlscan"] = asyncio.ensure_future(check_urlscan(scan_url))
    ENRICH = ENRICH_BUDGET_S
    _done, _pending = await asyncio.wait(set(enrich_tasks.values()), timeout=ENRICH)
    for _t in _pending:
        _t.cancel()

    def _enr(task, fallback):
        if task is None or task in _pending:
            return fallback
        try:
            res = task.result()
            return fallback if isinstance(res, BaseException) else res
        except Exception:
            return fallback

    who_res     = _enr(enrich_tasks.get("whois"),   _FB_WHOIS.copy())
    geo_res     = _enr(enrich_tasks.get("geo"),     _FB_GEO.copy())
    explain_res = _enr(enrich_tasks.get("explain"), None)
    us_res      = _enr(enrich_tasks.get("urlscan"), _FB_URLSCAN.copy())
    ssl_res     = _enr(enrich_tasks.get("sslcert"), _FB_SSL.copy())

    # ------------------------------------------------------------------
    # Score combination
    # ------------------------------------------------------------------
    h_score = h_res.get("score", 0)
    ml_prob = h_res.get("ml_prob")
    trusted = bool(h_res.get("trusted"))
    flags = list(h_res.get("flags", []))
    flags.extend(structural_flags)

    # Typosquatting / homoglyph impersonation is a strong heuristic signal:
    # fold a confidence-scaled bonus into the rule-based score before weighting.
    if typo_res.get("is_typosquat"):
        brand = typo_res.get("impersonated_brand")
        technique = typo_res.get("technique")
        conf = int(typo_res.get("confidence", 0) or 0)
        h_score = min(100, h_score + int(round(conf * 0.45)))
        flags.append(
            f"Typosquatting: impersonates '{brand}' via {technique} "
            f"({conf}% confidence)"
        )

    # Is this a tenant page on a shared-hosting platform (alice.github.io,
    # jxvtd.wasmer.app)? Such pages are NOT blanket-trusted — they're judged on
    # content + corroborated ML (see below), so fresh phishing kits can escalate.
    shared_tenant = _is_shared_hosting_tenant(domain)

    # High-reputation domains earn a pass on brand-mismatch: a brand mention is
    # not impersonation when the site has valid HTTPS, is over a year old, and
    # the ML model doesn't read it as phishing. Suppress the signal and back its
    # contribution out of content_risk so it can't nudge the verdict. NOT applied
    # to a shared-hosting tenant: the platform apex's age says nothing about the
    # tenant, so it must never whitewash a brand impersonation on a user subpage.
    domain_over_1yr = "yr" in (who_res.get("age") or "")
    low_ml = ml_prob is None or ml_prob < 0.30
    if (content_res.get("brand_mismatch") and ssl and domain_over_1yr and low_ml
            and not shared_tenant):
        removed = [
            s for s in content_res.get("suspicious_signals", [])
            if s.startswith("Page presents") or s.startswith("Page mentions")
        ]
        content_res["brand_mismatch"] = False
        content_res["suspicious_signals"] = [
            s for s in content_res.get("suspicious_signals", []) if s not in removed
        ]
        content_res["content_risk"] = max(
            0, int(content_res.get("content_risk", 0) or 0) - 30 - 10 * len(removed)
        )

    # Reputation first: we must know whether any source ACTIVELY flagged the URL
    # before deciding how much weight weak lexical/content signals may carry.
    rep_score, n_flagged, rep_active = _reputation_score(vt_res, gsb_res, uh_res, feed_res)
    # A redirect hop on the blocklist is a confirmed reputation hit on the chain.
    if hop_blocklisted:
        rep_active = True
        rep_score = max(rep_score, 60)

    # STRONG vs WEAK reputation. A single-engine VirusTotal detection (1 engine) is
    # a low-confidence hit that floors at SUSPICIOUS, not MALICIOUS — a lone AV
    # engine flagging a URL is frequently a false positive. Confirmed blocklists
    # (Safe Browsing / URLHaus / an exact-URL community-blocklist listing), a
    # blocklisted redirect hop, or VT flagged by >= VT_MIN_ENGINES_FOR_MALICIOUS
    # engines stay STRONG (MALICIOUS).
    #
    # A bare-HOST community-blocklist listing is deliberately NOT strong: the
    # domain feed carries shared platforms and legitimate sites listed after a
    # one-off compromise (73 Tranco top-100k registrables were on it on
    # 2026-07-27), so on its own it floors at SUSPICIOUS and waits for
    # corroboration. A feed result with no `match` key predates the two-layer
    # split and is treated as the exact-URL kind it used to be.
    vt_positives = int(vt_res.get("raw_positives", 0) or 0)
    feed_url_match = (feed_res.get("status") == "flag"
                      and feed_res.get("match") != "domain")
    # Count of INDEPENDENT confirmed sources — _escalate floors one confirmed
    # source at 90 and two-or-more at the full 100.
    rep_strong = sum([
        bool(hop_blocklisted),
        vt_positives >= VT_MIN_ENGINES_FOR_MALICIOUS,
        gsb_res.get("status") == "flag",
        uh_res.get("status") == "flag",
        feed_url_match,
    ])
    rep_weak = rep_active and not rep_strong   # e.g. a single-engine VT detection
    # A single stray VT engine as the ONLY active source on a provider-
    # allowlisted host is reputation noise, not a weak hit (live FP
    # 2026-07-14: dzen.ru floored at SUSPICIOUS 60 by one paranoid engine —
    # big platforms routinely collect one). A second engine, a second source,
    # or a blocklisted hop is still honoured via rep_strong above; the VT
    # detail stays in the flags for transparency.
    if (rep_weak and vt_positives == 1 and n_flagged == 1
            and is_provider_domain(domain)):
        rep_weak = False
        rep_active = False
    # Closed single-registrant brand TLDs (c.gle, domains.google, …): no third
    # party can publish content there, so a VT-only detection at or below the
    # strong-engine bar — every blocklist clean, no flagged redirect hop — is
    # engine noise on lexically random first-party URLs (live FP 2026-07-16:
    # a genuine Google-mail c.gle link at 2/92 engines pushed the email to
    # MALICIOUS). Bigger engine consensus or any confirmed blocklist still
    # escalates; the VT detail stays in the flags for transparency. User-
    # content platforms (dzen.ru) keep the ordinary 2-engine escalation.
    if (rep_active and not hop_blocklisted and n_flagged == 1
            and 0 < vt_positives <= VT_MIN_ENGINES_FOR_MALICIOUS
            and is_brand_tld_host(domain)):
        rep_strong = False
        rep_weak = False
        rep_active = False

    # --- reputable-host weak-signal cap (FIX 1) --------------------------------
    # On a reputable host with NO active reputation hit, keyword/content/ML-lexical
    # matches are WEAK: a page that merely CONTAINS security vocabulary, or whose
    # path tokenises to 'phishing'/'login', must never reach MALICIOUS. The ONLY
    # escalator allowed is REAL credential harvesting — a password field on a form
    # that POSTs to a DIFFERENT registrable domain TOGETHER WITH brand impersonation
    # (brand/title/favicon mismatch or typosquat). Mere keywords never clear this.
    reputable = _is_reputable_host(domain, ssl, who_res)
    strong_credential_harvest = bool(
        content_res.get("has_password_field")
        and content_res.get("external_form_action")
        and (content_res.get("brand_mismatch")
             or content_res.get("title_brand_mismatch")
             or content_res.get("favicon_brand_mismatch")
             or typo_res.get("is_typosquat"))
    )
    weak_signal_capped = reputable and not rep_active and not strong_credential_harvest

    # Corroborating phishing signals that are NOT mere lexical/keyword matches.
    # Computed here (from local signals only) because, on a shared-hosting tenant,
    # they decide whether the lexical ML may count at all. brand_impersonation and
    # the login+financial flag come from the heuristic engine / typosquat / static
    # content — none of them is "the URL string contains a scary word".
    typo_conf = int(typo_res.get("confidence", 0) or 0) if typo_res.get("is_typosquat") else 0
    ip_host = bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", domain))
    brand_impersonation = (
        bool(typo_res.get("is_typosquat"))
        or (content_res.get("brand_mismatch") and not trusted)
        or any(f.startswith("Possible impersonation") for f in flags)
    )
    strong_flags = sum([
        bool(typo_res.get("is_typosquat")),
        ip_host,
        bool(brand_impersonation),
        any(f.startswith("Login combined with financial terms") for f in flags),
        not ssl,
    ])
    # Hostname entropy (Phase 1a). A machine-generated hostname label is real,
    # NON-lexical evidence about who published the page: nobody registers
    # sp3ct-meslor-biz8-varnex-pisol by hand. It therefore joins `corroborated`
    # — and NOTHING else.
    #
    # Deliberately NOT in strong_flags: that list feeds _escalate() and the
    # _cap_weak_heuristic_only bypass, so an entry there RAISES scores on its
    # own. Entropy must not, because legitimate hosts do have random-looking
    # labels (CI preview deploys, CDN nodes — ci-7f3a9b.vercel.app). Sitting in
    # `corroborated` alone means it can only ever re-open the lexical ML and
    # keyword channels that the tenant/reputable gates closed; with nothing for
    # those channels to say, the score does not move at all.
    #
    # Measured on run 4's recorded misses (docs/Detection_Accuracy_Audit/):
    # 50 of the 52 pages.dev cluster hosts are separated, while the same
    # thresholds flag 12 of 99,599 Tranco labels (0.012%) and 0 of the 216-URL
    # legit corpus.
    host_random = hostname_randomness(domain)
    if host_random["random"]:
        flags.append(f"Suspicious hostname: {host_random['reason']}")
    # Real (non-lexical) corroboration that this page is phishing.
    corroborated = (strong_credential_harvest or strong_flags >= 1
                    or host_random["random"])
    # ...but a hostname is still only a NAME. When entropy is the sole thing
    # vouching for the page, everything that remains in the blend is lexical —
    # the label's shape, path keywords, and a URL-string ML — so the verdict is
    # held below MALICIOUS further down. See the cap for why that matters.
    entropy_only_corroboration = (
        host_random["random"] and not strong_credential_harvest and strong_flags < 1
    )

    # The lexical ML model keys off path tokens. On a reputable, reputation-clean
    # page that is not real credential harvesting it is uncorroborated and must
    # not drive the verdict — drop it from the blend (treated as a neutral,
    # unavailable source), exactly like the consistent-fusion rule for sources.
    #
    # SHARED-HOSTING RESOLUTION: a tenant page (alice.github.io) is NOT blanket-
    # capped, so content + ML CAN escalate it — but the subdomain/path is chosen
    # by whoever published the page, so the LEXICAL ML may only count when a real
    # phishing signal corroborates it (a credential-harvesting form, brand
    # impersonation, IP host, no-HTTPS, or login+financial terms). Without that,
    # the page "merely contains security vocabulary" (someone.github.io/
    # phishing-awareness) and the lexical ML is dropped, so it stays SAFE. Content
    # signals are purely structural (forms/brand in title/heading), so they always
    # count and remain the primary escalator for tenant phishing kits.
    tenant_lexical_uncorroborated = shared_tenant and not rep_active and not corroborated
    # Reputable analogue of the tenant rule (verified live FPs 2026-07-14:
    # kaspersky.com/…/threats/phishing and ncsc.gov.uk/guidance/phishing scored
    # SUSPICIOUS 60 on the 'phishing' keyword alone): on a weak-signal-capped
    # reputable host an uncorroborated keyword hit is the same weak lexical
    # evidence. Corroborated pages (login+financial combo, typosquat, IP host,
    # no-HTTPS, credential harvesting, active reputation) keep the channel.
    reputable_lexical_uncorroborated = weak_signal_capped and not corroborated
    lexical_uncorroborated = tenant_lexical_uncorroborated or reputable_lexical_uncorroborated
    # Solo guard: a lexical opinion never convicts by itself, at ANY
    # confidence. With reputation silent, nothing corroborating and the
    # heuristics quiet, the ML probability is dropped from the blend (neutral)
    # — the same consistent-fusion treatment as the tenant and reputable gates
    # above. The probability stays in the response for transparency.
    solo_ml_uncorroborated = (
        ml_prob is not None
        and not rep_active and not corroborated and h_score < 20
    )
    ml_for_score = None if (weak_signal_capped or tenant_lexical_uncorroborated
                            or solo_ml_uncorroborated) else ml_prob

    # The SAME corroboration gate applies to the KEYWORD channel of the heuristic
    # score (verified FP: octocat.github.io/phishing-awareness-login-guide reached
    # MALICIOUS 70 on 'login'+'phishing' path keywords alone — the ML was correctly
    # dropped, which renormalised the blend into a pure h_score passthrough). On an
    # uncorroborated tenant or reputable host a "Suspicious keyword" hit is the same
    # weak lexical evidence as the lexical ML, so its contribution is backed out of
    # the heuristic score before blending. The flags stay listed for transparency.
    # (If the raw heuristic total was clamped at 100 the subtraction can overshoot;
    # it floors at 0, acceptable because every co-present signal there is also
    # lexical.)
    if lexical_uncorroborated and h_score > 0:
        kw_penalty = sum(
            KEYWORD_WEIGHTS.get(f[len("Suspicious keyword: "):], 0)
            for f in flags if f.startswith("Suspicious keyword: ")
        )
        if kw_penalty:
            h_score = max(0, h_score - kw_penalty)

    # Content-based phishing analysis (static HTML inspection). M2: the page
    # features feed the content-signal MODEL, which joins the blend as its own
    # channel (replacing the old flat content_risk*0.4 fold into h_score).
    # Like reputation, the channel only votes when it has a real opinion
    # (probability >= CONTENT_ACTIVE_PROB): static parsing cannot execute JS,
    # so a bland-looking page is NEUTRAL, never exonerating. The content
    # floors below still guarantee SUSPICIOUS+ for strong page evidence.
    # Skipped for known-good domains AND for reputable weak-signal-capped hosts,
    # whose pages legitimately host login forms / reference other brands.
    suppress_content = trusted or weak_signal_capped
    content_risk = 0 if suppress_content else int(content_res.get("content_risk", 0) or 0)
    content_prob = None if suppress_content else content_phishing_probability(content_res)
    content_for_score = (
        content_prob if content_prob is not None and content_prob >= CONTENT_ACTIVE_PROB
        else None
    )
    if not suppress_content:
        if content_res.get("external_form_action"):
            flags.append("Login form posts credentials to a different domain")
        if content_res.get("brand_mismatch"):
            flags.append("Page impersonates a brand that does not match its domain")
        elif content_res.get("has_password_field"):
            flags.append("Page contains a password / login form")
        for sig in content_res.get("suspicious_signals", []):
            flags.append(f"Page content: {sig}")

    # Sketchy redirect-chain shape (loop / excessive hops / non-web scheme) folds
    # a small bonus into the rule-based score. Skipped for trusted/capped hosts.
    if structural_risk and not suppress_content:
        h_score = min(100, h_score + int(round(structural_risk * 0.3)))

    risk_score = _weighted_score(h_score, ml_for_score, rep_score, rep_active,
                                 content_prob=content_for_score)

    # Escalation floors (raise score only — never lower it) for decisive signals.
    # strong_flags / typo_conf / brand_impersonation were computed above (they also
    # gate the lexical ML on shared-hosting tenants). ml_for_score is already None
    # for an uncorroborated tenant, so a high ML prob alone cannot floor it here.
    risk_score = _escalate(risk_score, rep_strong, rep_weak, ml_for_score, strong_flags, typo_conf)

    # REAL credential harvesting (cross-domain password POST + brand impersonation)
    # is decisive on its own — escalate strongly toward MALICIOUS regardless of
    # external reputation. This is the only content path allowed to cross 70.
    if strong_credential_harvest:
        risk_score = max(risk_score, 78)
        flags.append(
            "Credential harvesting: password form posts cross-domain while "
            "impersonating a brand"
        )

    # ------------------------------------------------------------------
    # Threat-intelligence fusion: domain age (WHOIS/RDAP) + TLS certificate.
    # New domain + login form + brand mismatch is the classic phishing-kit
    # footprint and escalates strongly. All inputs fail NEUTRAL (None) when a
    # lookup is unavailable, so a missing RDAP/cert never changes the verdict.
    # Skipped for trusted / reputable / weak-signal-capped hosts (FP-safe).
    # ------------------------------------------------------------------
    # FIX 2 — RDAP/WHOIS timeout is NEUTRAL, never risk. A timeout, HTTP 429
    # rate-limit, or an OPEN circuit breaker all return age_days=None (see
    # apis/whois_geo._whois_sync + circuit_breaker.guarded). Domain-age may
    # therefore add risk ONLY when we have a real, parsed integer age — an unknown
    # age is treated exactly like a domain of unremarkable age (no escalation),
    # so RDAP rate-limit sensitivity can no longer manufacture a false positive.
    domain_age_days = who_res.get("age_days")
    whois_age_known = isinstance(domain_age_days, int)
    is_new_domain = whois_age_known and domain_age_days <= NEW_DOMAIN_DAYS
    cert_age_days = ssl_res.get("cert_age_days")
    is_new_cert = isinstance(cert_age_days, int) and cert_age_days <= NEW_CERT_DAYS
    free_cert = bool(ssl_res.get("is_free_ca"))
    has_login = bool(content_res.get("has_login_form") or content_res.get("has_password_field"))
    ti_escalated = False
    if not (trusted or reputable or weak_signal_capped):
        if is_new_domain:
            flags.append(f"Newly registered domain ({domain_age_days} days old)")
        if is_new_domain and has_login and brand_impersonation:
            # Strongest fused tell — newly-stood-up brand-impersonating login page.
            risk_score = max(risk_score, 80)
            ti_escalated = True
            flags.append(
                f"Escalated: {domain_age_days}-day-old domain hosts a login form while "
                "impersonating a brand (new-domain + login + brand mismatch)"
            )
        elif is_new_domain and (free_cert or is_new_cert) and brand_impersonation:
            # Brand-new free cert on a brand-impersonating new domain.
            risk_score = max(risk_score, 78)
            ti_escalated = True
            tell = "brand-new" if is_new_cert else "free"
            flags.append(
                f"Escalated: {tell} TLS cert on a {domain_age_days}-day-old "
                "brand-impersonating domain"
            )
        elif is_new_domain and has_login:
            # New domain asking for credentials — suspicious even without a brand.
            risk_score = max(risk_score, 55)
            flags.append(
                f"New domain ({domain_age_days} days) is requesting login credentials"
            )

    # Other strong page content is a SUSPICIOUS+ floor (never MALICIOUS by itself).
    # Skipped for known-good / reputable-capped domains so a stray brand mention or
    # login form can't push them out of SAFE.
    if not suppress_content:
        if content_res.get("external_form_action") or content_risk >= 70:
            risk_score = max(risk_score, 65)
        elif content_risk >= 45:
            risk_score = max(risk_score, 45)
        # A genuinely sketchy chain shape floors at SUSPICIOUS.
        if structural_risk >= 45:
            risk_score = max(risk_score, 50)

    # FIX 1 cap: on a reputable, reputation-clean host weak signals alone can
    # never exceed SUSPICIOUS. (Real credential harvesting clears the gate above
    # by setting weak_signal_capped = False.)
    if weak_signal_capped and risk_score > 69:
        risk_score = 69
        flags.append(
            "Capped at SUSPICIOUS — reputable host, clean reputation, "
            "no credential-harvesting (weak keyword/ML signals only)"
        )

    # Tenant analogue of the FIX 1 cap: with the lexical ML and keyword channels
    # gated above, no remaining weak signal on an UNCORROBORATED shared-hosting
    # tenant may cross into MALICIOUS. Real tenant phishing kits clear this gate
    # by definition — credential harvesting, brand impersonation, an IP host,
    # no-HTTPS, or an active reputation hit all set corroborated/rep_active.
    if tenant_lexical_uncorroborated and risk_score > 69:
        risk_score = 69
        flags.append(
            "Capped at SUSPICIOUS — shared-hosting tenant, clean reputation, "
            "no corroborating phishing signal (weak lexical signals only)"
        )

    # Entropy-only corroboration caps at SUSPICIOUS (Phase 1a). A
    # machine-generated hostname re-opens the lexical ML and keyword channels,
    # which is the point — it takes the recorded pages.dev cluster from 34 to
    # the SUSPICIOUS band, and every one of those 52 URLs is a bare root path,
    # so the name is the only evidence they carry. But the reopened channels
    # are themselves lexical, and the URL ML is SATURATED on this shape:
    # measured 2026-07-28, it returns 0.9999 for
    # ci-7f3a9b.vercel.app/secure-login-verify-account — a LEGITIMATE CI
    # preview host. A probability that high on a legitimate URL is not an
    # independent second opinion, so it must never carry a verdict to
    # MALICIOUS by itself; uncapped, the DGA host above blends to 86.
    #
    # Escape hatches, all intact: a voting page, any strong flag, credential
    # harvesting or an active reputation hit means entropy is no longer the
    # only corroboration and this cap does not apply.
    if (entropy_only_corroboration and not rep_active
            and content_for_score is None and risk_score > 69):
        risk_score = 69
        flags.append(
            "Capped at SUSPICIOUS — machine-generated hostname corroborates "
            "only lexical signals (no page vote, reputation or brand evidence)"
        )

    # A reputable host with nothing but weak lexical noise against it stays
    # below SUSPICIOUS — see _cap_weak_heuristic_only. Placed after the caps
    # above and before the allowlist net; it only ever lowers the score.
    risk_score = _cap_weak_heuristic_only(
        risk_score,
        weak_signal_capped=weak_signal_capped,
        rep_active=rep_active,
        content_voted=content_for_score is not None,
        strong_flags=strong_flags,
    )

    # Safety net: a top global allowlisted domain is never MALICIOUS without an
    # ACTIVE reputation hit (cuts catastrophic false positives on big brands).
    # A shared-hosting/object-store TENANT never inherits this from its
    # platform root: bucket content on storage.googleapis.com (root
    # googleapis.com is provider-reputable) is customer-controlled and must be
    # allowed to reach MALICIOUS on real content evidence — same rule that
    # keeps github.io out of REPUTABLE_DOMAINS.
    allowlisted = not shared_tenant and (
        domain in TRUSTED_DOMAINS or root in TRUSTED_DOMAINS
        or domain in REPUTABLE_DOMAINS or root in REPUTABLE_DOMAINS
    )
    if allowlisted and not rep_active and risk_score >= 70:
        risk_score = 69
        flags.append(
            "Allowlisted global domain — not marked malicious without a reputation hit"
        )

    verdict = _verdict(risk_score)

    # ------------------------------------------------------------------
    # "Not checked" is not "safe" (2026-07-30).
    #
    # A 200-URL batch of known-malicious domains reported 125 of them SAFE at
    # 0%. Nothing was wrong with the scoring: VirusTotal's free tier allows 4
    # requests a minute, the batch runs 8 concurrent scans, so it collected
    # HTTP 429s, tripped the breaker, and every scan after that had no
    # reputation source at all. One of those rows —
    # vivek.howtowpguide.info — came back MALICIOUS 100 when scanned on its own
    # minutes later, with both VirusTotal and Safe Browsing flagging it.
    #
    # The missed detection is a quota problem. The word SAFE is a correctness
    # problem, and the worse of the two: a user acts on it.
    #
    # So when NOT ONE reputation source answered and nothing local objected,
    # the verdict is UNKNOWN. The score stays low — this is an absence of
    # information, not evidence of risk — and any single source answering, or
    # any local evidence, still produces a normal verdict.
    # ------------------------------------------------------------------
    # Only PRIMARY coverage clears a URL. The first version of this rule
    # accepted any source that answered, and the local community blocklist
    # ALWAYS answers — it is an in-memory lookup — so its "clean" suppressed
    # UNKNOWN for every URL in the replayed batch: 168 still read SAFE and
    # UNKNOWN fired zero times. Measured coverage of the narrow sources over the
    # same corpora: community blocklist flagged 1 of 60, URLHaus 0 of 180. Their
    # FLAG is decisive; their "clean" carries almost no information, and cannot
    # stand in for a reputation check.
    if verdict == "SAFE":
        _primary = (vt_res, gsb_res)
        if not any((res or {}).get("status") not in (None, "unavailable")
                   for res in _primary):
            verdict = "UNKNOWN"
            flags.append(
                "NOT CHECKED — no threat-intelligence source could be reached, "
                "so this URL has not been cleared. Treat it as unverified, not "
                "as safe."
            )

    confidence = _confidence(
        h_score, ml_for_score, vt_res, gsb_res, uh_res, feed_res, verdict,
        content_risk=int(content_res.get("content_risk", 0) or 0),
        content_voted=bool(content_res.get("fetched")) and not suppress_content,
    )

    # ------------------------------------------------------------------
    # Human-readable flags from reputation sources
    # ------------------------------------------------------------------
    if vt_res["status"] in ("flag", "warn"):
        flags.append(f"VirusTotal: {vt_res['detail']}")
    if gsb_res["status"] == "flag":
        flags.append(f"Safe Browsing: {gsb_res['detail']}")
    if uh_res["status"] == "flag":
        flags.append(f"URLHaus: {uh_res['detail']}")
    if feed_res["status"] == "flag":
        flags.append(f"Community blocklist: {feed_res['detail']}")

    # Reachability note — if the host never resolved AND no page could be fetched,
    # say so plainly instead of returning a silent SAFE with an empty flag list.
    # ------------------------------------------------------------------
    # Incomplete threat intelligence (2026-07-28).
    #
    # VirusTotal's free tier allows 4 requests/minute. Scanning a file of links
    # exhausts that in seconds, the circuit breaker opens, and every scan after
    # it runs with no VirusTotal and no Safe Browsing. Measured on a random
    # sample of 60 domains from a known-malicious corpus: VT was unavailable
    # for 41 of them, and ALL TEN live-but-SAFE results were in that group.
    #
    # A SAFE verdict that no reputation source stood behind is not the same
    # claim as one three sources agreed with, and the user has no way to tell
    # them apart from the verdict alone. So say it, name the sources, and lower
    # the confidence — the score itself does not move, because an absent source
    # is still neutral evidence, not evidence of risk.
    # ------------------------------------------------------------------
    _intel = [("VirusTotal", vt_res), ("Safe Browsing", gsb_res),
              ("URLHaus", uh_res), ("Community Blocklist", feed_res)]
    intel_unavailable = [name for name, res in _intel
                         if (res or {}).get("status") == "unavailable"]
    intel_complete = not intel_unavailable
    if intel_unavailable and not rep_active:
        flags.append(
            "Threat intelligence incomplete — "
            + ", ".join(intel_unavailable)
            + " could not be checked (no API key, rate limit, or the source was "
              "down). This verdict rests on local analysis only."
        )

    unreachable = resolved_ip is None and not content_res.get("fetched")
    if unreachable and not rep_active:
        flags.append(
            "Could not reach the site (host did not resolve) — it may be offline, "
            "blocking scanners, or newly taken down. Verdict is based on URL "
            "structure and reputation only."
        )

    flags = _dedupe(flags)

    sources = [
        {"name": "VirusTotal",    "status": vt_res["status"],  "detail": vt_res["detail"]},
        {"name": "Safe Browsing", "status": gsb_res["status"], "detail": gsb_res["detail"]},
        {"name": "URLHaus",       "status": uh_res["status"],  "detail": uh_res["detail"]},
        # OpenPhish + Phishing.Database. This row replaced "PhishTank", which
        # had been a stub returning 'clean' for every URL since PhishTank
        # closed new API-key registration — the table must only name checks
        # that actually ran.
        {"name": "Community Blocklist",
         "status": feed_res["status"], "detail": feed_res["detail"]},
    ]

    scan_time_ms = int(round((time.perf_counter() - t0) * 1000))

    result = {
        # Full contract
        "url": url,
        "final_url": scan_url,
        "domain": domain,
        "resolved_ip": resolved_ip,
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence": confidence,
        # Machine-readable form of the flag above, for the extension, batch
        # jobs and the eval harness — which need to know how much of the stack
        # actually ran, not to parse prose to find out.
        "intel_complete": intel_complete,
        "intel_unavailable": intel_unavailable,
        "ml_probability": round(ml_prob, 4) if ml_prob is not None else None,
        "content_probability": content_prob,
        "ssl": ssl,
        "redirects": redirects,
        "redirect_chain": chain,
        "structural_flags": structural_flags,
        "cached": False,
        "scan_time_ms": scan_time_ms,
        "flags": flags,
        "sources": sources,
        # Live page-preview + sandbox intel (urlscan.io)
        "screenshot_url": us_res.get("screenshot_url"),
        "page_title": us_res.get("page_title"),
        # Forensic enrichment — IP geolocation + ASN/hosting + WHOIS/RDAP
        "ip_location": geo_res.get("ip_location"),
        "ip_country": geo_res.get("ip_country"),
        "asn": geo_res.get("asn"),
        "hosting": geo_res.get("hosting"),
        "whois": {
            "registrar": who_res.get("registrar"),
            "age": who_res.get("age"),
            "age_days": who_res.get("age_days"),
            "created": who_res.get("created"),
            "country": who_res.get("country"),
        },
        # SSL/TLS certificate forensics (issuer, age, free-CA flag)
        "ssl_cert": ssl_res,
        # Consolidated threat-intelligence signals fed into fusion
        "threat_intel": {
            "domain_age_days": domain_age_days,
            "is_new_domain": is_new_domain,
            "registrar": who_res.get("registrar"),
            "asn": geo_res.get("asn"),
            "hosting": geo_res.get("hosting"),
            "cert_issuer": ssl_res.get("issuer"),
            "cert_age_days": ssl_res.get("cert_age_days"),
            "free_ca_cert": free_cert,
            "brand_impersonation": bool(brand_impersonation),
            "has_login_form": has_login,
            "escalated": ti_escalated,
        },
        # Typosquatting / homoglyph impersonation intel
        "typosquat": typo_res,
        # Content-based phishing forensics (premium/forensic — gated for free tier)
        "content_analysis": content_res,
        # Per-feature "why" explanation of the ML phishing probability
        # (premium/forensic — gated for free tier). See ml/explain.py.
        "explainability": explain_res,
        # Plain-English, one-line verdict summary
        "plain_summary": _plain_summary(verdict, n_flagged),
        # Backward-compat (history DB, QR/email callers that read these keys)
        "score": risk_score,
        "reasons": flags,
        "ai_explanation": "; ".join(flags) if flags else "No significant threats detected.",
    }

    # Cache definitive verdicts only (never ERROR) so the next identical scan is
    # instant and fully reputation-aware even if this run capped a slow source.
    # Store a pristine deep copy so later caller/strip_premium mutations of the
    # returned dict can't corrupt the cached entry.
    #
    # NEVER cache a scan whose reputation sources were ALL unavailable: that
    # "all clean" result reflects a transient outage, not a real verdict, and
    # caching it would freeze "all APIs unavailable" for the whole TTL and keep
    # serving it long after the sources recover (mirrors the per-source
    # url_cache rule — see _reputation_all_unavailable).
    #
    # UNKNOWN is never cached either: it means the primary sources did not
    # answer in time, which is a fact about this moment, not about the URL.
    # Cached, it was replayed for an hour — including to the batch re-check
    # that exists to replace it (main._run_batch).
    degraded = _reputation_all_unavailable(vt_res, gsb_res, uh_res)
    if (previews and result.get("verdict") not in ("ERROR", "UNKNOWN")
            and not degraded):
        cache_put(cache_key, copy.deepcopy(result))

    if save_fn:
        save_fn("URL Scanner", result, url)

    return result


# ---------------------------------------------------------------------------
# Embedded-link helpers — used by email / screenshot / voice endpoints
# ---------------------------------------------------------------------------

_SCHEME_RE = re.compile(r'https?://', re.IGNORECASE)
# A TLD boundary: a dot followed by 2-24 letters then a terminator (:/?# or end).
_TLD_RE = re.compile(r'\.[a-z]{2,24}(?:[:/?#]|$)', re.IGNORECASE)
# URL-ish token: only characters that legitimately appear inside a URL.
_URLISH_RE = re.compile(r'^[\w.~%/?#&=+:@!$*,;()\[\]-]+$')
_MAX_JOINS = 6  # safety cap on how many OCR fragments we glue into one URL

# Common TLDs (incl. the cheap ones phishing favours) — lets us recognise a
# bare TLD fragment ("xyz", "tk") when OCR has dropped/mangled the leading dot.
_KNOWN_TLDS = {
    "com", "net", "org", "io", "co", "info", "biz", "xyz", "top", "tk", "ml",
    "ga", "cf", "gq", "ru", "click", "online", "site", "club", "app", "dev",
    "live", "shop", "vip", "icu", "work", "link", "fun", "cn", "in", "uk",
    "us", "de", "br", "pro", "page", "store", "win", "gdn", "zip",
}
_LEAD_ALPHA_RE = re.compile(r'^[a-z]{2,24}', re.IGNORECASE)


def _continuation(buf: str, nxt: str) -> str | None:
    """
    If the whitespace-separated token *nxt* is the continuation of a URL that
    OCR split apart, return the text to glue on (normalised); else None.

    Handles the common OCR break points:
      * before the TLD dot     "host"      + ".xyz/path"
      * after a trailing dot   "host."     + "xyz/path"
      * before/within the path "host.xyz"  + "/account"
      * mid-host hyphen        "host-"     + "secure-login.xyz"
      * dropped/misread dot    "host"      + "-xyz/path"  ('.' read as '-')
    """
    if not nxt or not _URLISH_RE.match(nxt):
        return None
    # Path / query / fragment continuation.
    if nxt[0] in "/?#&=":
        return nxt
    # Explicit TLD/path continuation that already carries its own dot.
    if nxt[0] == ".":
        return nxt
    # Buffer ends mid-token (path separator or a pending dot/hyphen) -> glue on.
    if buf[-1] in "/?#&=.-":
        return nxt

    has_tld = bool(_TLD_RE.search(buf))
    if not has_tld:
        # Host has no TLD yet: this fragment should supply it.
        if "." in nxt:
            return nxt  # fragment carries its own dotted TLD
        # OCR may have dropped or mangled the boundary dot (".xyz" -> "-xyz"):
        # strip a single misread separator and recover a "tld[/path]" fragment.
        core = nxt.lstrip(".,-_~|")
        m = _LEAD_ALPHA_RE.match(core)
        if m:
            after = core[m.end():m.end() + 1]
            tld = core[:m.end()].lower()
            if after in ("/", ":", "?", "#", ".") or (after == "" and tld in _KNOWN_TLDS):
                return "." + core  # synthesise the lost boundary dot
    return None


def _reassemble_urls(text: str) -> list[str]:
    """
    Walk whitespace tokens, rebuilding URLs that OCR fragmented across spaces
    and newlines. Returns raw URL strings (scheme onward), order preserved.
    """
    tokens = (text or "").split()
    out: list[str] = []
    i, n = 0, len(tokens)
    while i < n:
        m = _SCHEME_RE.search(tokens[i])
        if not m:
            i += 1
            continue
        buf = tokens[i][m.start():]  # take from the scheme onward
        i += 1
        joins = 0
        while i < n and joins < _MAX_JOINS:
            piece = _continuation(buf, tokens[i])
            if piece is None:
                break
            buf += piece
            i += 1
            joins += 1
        out.append(buf)
    return out


def extract_urls(text: str) -> list[str]:
    """
    Return unique http/https URLs found in text (order preserved).

    URLs that OCR split across spaces/newlines are reassembled first so the
    full domain + TLD + path is recovered before scanning (a truncated host
    like 'http://paypal-secure-login-verify' would otherwise score SAFE).
    """
    seen: set[str] = set()
    out: list[str] = []
    for url in _reassemble_urls(text):
        url = url.rstrip(".,;!?)")  # strip common trailing punctuation
        if url and url not in seen:
            seen.add(url)
            out.append(url)
    return out


_VERDICT_RANK = {"SAFE": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}


async def scan_embedded_links(text: str) -> dict:
    """
    Scan up to the first 5 URLs found in *text* using the full aggregator
    pipeline (VirusTotal / Safe Browsing / URLHaus + ML).  Results are
    gathered in parallel and the per-URL cache is reused automatically.

    Returns
    -------
    {
      "links_found":   int,          # total unique URLs extracted
      "scanned_links": list[dict],   # [{url, verdict, risk_score, sources, screenshot_url, page_title}]
      "worst_score":   int,          # highest risk_score across all scanned URLs
      "worst_verdict": str | None,   # corresponding worst verdict
    }
    """
    urls = extract_urls(text)[:5]
    if not urls:
        return {"links_found": 0, "scanned_links": [], "worst_score": 0, "worst_verdict": None}

    raw = await asyncio.gather(*[full_scan(u) for u in urls], return_exceptions=True)

    scanned: list[dict] = []
    worst_score = 0
    worst_verdict: str = "SAFE"

    for url, res in zip(urls, raw):
        if isinstance(res, BaseException):
            scanned.append({"url": url, "verdict": "ERROR", "risk_score": 0, "sources": []})
            continue
        entry = {
            "url":            res.get("url", url),
            "verdict":        res.get("verdict", "SAFE"),
            "risk_score":     res.get("risk_score", 0),
            "sources":        res.get("sources", []),
            "screenshot_url": res.get("screenshot_url"),
            "page_title":     res.get("page_title"),
        }
        scanned.append(entry)
        if entry["risk_score"] > worst_score:
            worst_score = entry["risk_score"]
        if _VERDICT_RANK.get(entry["verdict"], 0) > _VERDICT_RANK.get(worst_verdict, 0):
            worst_verdict = entry["verdict"]

    return {
        "links_found":   len(urls),
        "scanned_links": scanned,
        "worst_score":   worst_score,
        "worst_verdict": worst_verdict,
    }
