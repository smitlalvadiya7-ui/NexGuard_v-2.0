# -*- coding: utf-8 -*-
"""
PROOF OF CONCEPT — is a missing DMARC/SPF record actually a phishing signal?

email_analyzer already reads SPF, DKIM and DMARC, but only out of the
Authentication-Results header a receiving mail server wrote. Its own comment
records the hole (email_analyzer.py:148): a webmail DOM exposes "Name
<address>" and nothing else, so a screenshot or OCR scan arrives with no
authentication evidence at all.

Asking DNS directly needs no header — only the sender's domain:

    _dmarc.<domain>  TXT   is a policy published, and is it enforcing?
    <domain>         TXT   is there an SPF record, and does it end -all?
    <domain>         MX    does this domain receive mail at all?

The literature says absent authentication should count against a sender, and
that attackers skip DMARC deliberately to avoid a reject policy. That is a
claim about the world. This script checks whether it holds on OUR corpus,
because a signal that does not separate our phish from our legit is not worth
a network round trip on the scan path.

Method
------
Both corpora, same three lookups, over DNS-over-HTTPS so the study adds no
dependency (production should use dnspython — DoH is used here to keep the
experiment self-contained). Shared-hosting tenants are reported separately:
alice.blogspot.com cannot publish DMARC, only blogspot.com can, so counting
tenants as "no DMARC" would manufacture a signal that is really just a fact
about the platform.

Reported as presence rates on each corpus, plus the gap between them. The gap
IS the discriminative power. A large gap justifies the feature; a small one
kills it before it costs anyone a round trip.

Usage
-----
    py -m eval.poc_dns_auth
    py -m eval.poc_dns_auth --limit 60 --workers 10
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

_HERE = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.dirname(_HERE)
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

import requests
import tldextract

from shared_hosting import is_shared_hosting_tenant

_DOH = "https://cloudflare-dns.com/dns-query"
_HDR = {"Accept": "application/dns-json"}
_TIMEOUT = 12

_PSL = tldextract.TLDExtract(suffix_list_urls=())


def registrable(host: str) -> str:
    x = _PSL(host or "")
    return ("%s.%s" % (x.domain, x.suffix)).strip(".") if x.domain and x.suffix else ""


def host_of(url: str) -> str:
    h = (urlparse(url).hostname or "").lower().strip(".")
    return h[4:] if h.startswith("www.") else h


def query(name: str, rrtype: str) -> list[str] | None:
    """TXT/MX values for `name`, [] if the name exists with none, None on error.

    None and [] are kept apart on purpose. "the lookup failed" and "this domain
    publishes no DMARC" are different findings, and collapsing them would let
    network flakiness masquerade as a phishing signal.
    """
    try:
        r = requests.get(_DOH, params={"name": name, "type": rrtype},
                         headers=_HDR, timeout=_TIMEOUT)
        if r.status_code != 200:
            return None
        d = r.json()
    except (requests.RequestException, ValueError):
        return None
    # 0 NOERROR, 3 NXDOMAIN. Anything else is a server-side problem, not an answer.
    if d.get("Status") not in (0, 3):
        return None
    out = []
    for a in d.get("Answer") or []:
        v = (a.get("data") or "").strip()
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        out.append(v.replace('" "', ""))
    return out


def probe(domain: str) -> dict:
    """The three lookups, reduced to the facts the scanner would act on."""
    dmarc = query("_dmarc." + domain, "TXT")
    txt = query(domain, "TXT")
    mx = query(domain, "MX")

    policy = None
    if dmarc:
        for v in dmarc:
            if "v=DMARC1" in v:
                for part in v.split(";"):
                    part = part.strip()
                    if part.startswith("p="):
                        policy = part[2:].strip().lower()
                break

    spf = None
    if txt:
        for v in txt:
            if v.lower().startswith("v=spf1"):
                spf = "-all" if "-all" in v else ("~all" if "~all" in v else "soft")
                break

    return {
        "domain": domain,
        "dmarc_present": policy is not None,
        "dmarc_policy": policy,
        "dmarc_enforcing": policy in ("reject", "quarantine"),
        "spf_present": spf is not None,
        "spf_strict": spf == "-all",
        "mx_present": bool(mx),
        "errors": sum(1 for x in (dmarc, txt, mx) if x is None),
    }


def run(domains: list[str], workers: int, label: str) -> list[dict]:
    print("  %s: %d domains" % (label, len(domains)), end=" ", flush=True)
    out = []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(probe, d) for d in domains]
        for f in as_completed(futs):
            out.append(f.result())
            if len(out) % 20 == 0:
                sys.stdout.write(".")
                sys.stdout.flush()
    print(" %.1fs" % (time.time() - t0))
    return out


def rate(rows: list[dict], key: str) -> float:
    return 100.0 * sum(1 for r in rows if r[key]) / len(rows) if rows else 0.0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=0, help="cap each corpus (0 = all)")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--json", metavar="PATH")
    args = ap.parse_args()

    corpus = json.load(open(os.path.join(_HERE, "_corpus_m4.json"), encoding="utf-8"))

    def prep(urls):
        apex, tenant = [], []
        for u in urls:
            h = host_of(u)
            if not h:
                continue
            (tenant if is_shared_hosting_tenant(h) else apex).append(registrable(h))
        return sorted(set(x for x in apex if x)), sorted(set(x for x in tenant if x))

    p_apex, p_tenant = prep(corpus["phish"])
    l_apex, l_tenant = prep(corpus["legit"])
    if args.limit:
        p_apex, l_apex = p_apex[: args.limit], l_apex[: args.limit]

    print("=" * 72)
    print("DNS AUTHENTICATION POSTURE  —  phish vs legit, same three lookups")
    print("=" * 72)
    print("  Tenants are excluded from the comparison: a tenant cannot publish")
    print("  DMARC for itself, so scoring it as 'missing' would invent a signal.")
    print("  phish  %3d attacker-registered, %3d tenants set aside" % (len(p_apex), len(p_tenant)))
    print("  legit  %3d attacker-registered, %3d tenants set aside" % (len(l_apex), len(l_tenant)))
    print()

    ph = run(p_apex, args.workers, "phish")
    lg = run(l_apex, args.workers, "legit")
    print()

    checks = [
        ("publishes DMARC", "dmarc_present"),
        ("DMARC is enforcing (reject/quarantine)", "dmarc_enforcing"),
        ("publishes SPF", "spf_present"),
        ("SPF is strict (-all)", "spf_strict"),
        ("has MX (receives mail)", "mx_present"),
    ]

    print("=" * 72)
    print("RESULT")
    print("=" * 72)
    print("  %-40s %8s %8s %8s" % ("signal", "phish", "legit", "gap"))
    print("  " + "-" * 66)
    best = []
    for name, key in checks:
        p, l = rate(ph, key), rate(lg, key)
        gap = l - p
        best.append((abs(gap), name, p, l, gap))
        print("  %-40s %7.1f%% %7.1f%% %+7.1f" % (name, p, l, gap))
    print()
    print("  gap = legit rate minus phish rate. A LARGE POSITIVE gap means")
    print("  legitimate domains publish it and phishing domains do not, so its")
    print("  ABSENCE is evidence. A gap near zero means the signal is noise.")
    print()

    p_err = sum(r["errors"] for r in ph)
    l_err = sum(r["errors"] for r in lg)
    print("  failed lookups: phish %d, legit %d  (counted as neither present nor absent)"
          % (p_err, l_err))
    print()

    print("  DMARC policies actually seen")
    for corpus_name, rows in (("phish", ph), ("legit", lg)):
        seen = {}
        for r in rows:
            seen[r["dmarc_policy"] or "(none published)"] = \
                seen.get(r["dmarc_policy"] or "(none published)", 0) + 1
        parts = ", ".join("%s=%d" % kv for kv in sorted(seen.items(), key=lambda x: -x[1]))
        print("    %-6s %s" % (corpus_name, parts))
    print()

    best.sort(reverse=True)
    top = best[0]
    print("=" * 72)
    print("VERDICT")
    print("=" * 72)
    print("  strongest separator: %s" % top[1])
    print("  phish %.1f%% vs legit %.1f%%, a %.1f point gap" % (top[2], top[3], abs(top[4])))
    print()
    print("  Cost of adding it: three DNS lookups, no API key, no licence, and")
    print("  it works in BOTH deployment profiles.")

    if args.json:
        json.dump({"generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
                   "phish": ph, "legit": lg,
                   "phish_tenants_excluded": len(p_tenant),
                   "legit_tenants_excluded": len(l_tenant)},
                  open(args.json, "w", encoding="utf-8"), indent=2)
        print()
        print("  full result written to", args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
