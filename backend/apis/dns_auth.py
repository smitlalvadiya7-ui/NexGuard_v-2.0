"""
Sender-domain DNS posture — does this domain publish mail authentication?

Why this exists
---------------
email_analyzer reads SPF, DKIM and DMARC out of the Authentication-Results
header a receiving mail server wrote. Its own comment records the hole
(email_analyzer.py:148): a webmail DOM exposes "Name <address>" and nothing
else, so an email arriving by screenshot, OCR or paste carries no
authentication evidence at all, and verify_sender_origin falls through to
"unknown".

DNS answers without any header. Three lookups against the sender's domain:

    _dmarc.<domain>  TXT   is a policy published, and does it enforce?
    <domain>         TXT   is there an SPF record, and does it end -all?
    <domain>         MX    does this domain receive mail at all?

Measured on eval/_corpus_m4.json (2026-09-08, see eval/poc_dns_auth.py):

    signal              phish   legit    gap
    publishes DMARC      7.8%   70.1%   +62.3
    publishes SPF       15.6%   75.9%   +60.2
    has MX              15.6%   70.7%   +55.1

59 of 64 attacker-registered phishing domains published nothing at all.

Scope, deliberately narrow
--------------------------
This is for the EMAIL path, where the sender domain is by definition claiming
to send mail. The same PoC run showed why it must not go on the generic URL
path: of 31 legitimate domains it flagged there, nearly all were CDN and
telemetry hosts — apple-dns.net, cloudflarestorage.com, line-scdn.net,
zillowstatic.com — which publish no mail records because they send no mail.
That is not a phishing signal, and provider_domains caught only 1 of the 31.

Absent evidence is not evidence of absence
------------------------------------------
A failed lookup returns status "unknown" and scores ZERO. It is never folded
into "publishes nothing". A domain is only called unauthenticated when all
three lookups ANSWERED and all three came back empty — which is the same rule
deployment_profile applies to a blocked source, for the same reason.

Public surface
--------------
    async check_dns_auth(domain)  -> posture dict
    dns_posture_sync(domain)      -> posture dict (blocking; the tested core)
    posture_risk(posture)         -> int, risk points to add
"""

from __future__ import annotations

import asyncio

import requests

from apis.circuit_breaker import guarded, SourceUnavailable
from apis.url_cache import cache_get, cache_put
from shared_hosting import is_shared_hosting_tenant

_KEY = "dnsauth:"

# Cloudflare's DoH endpoint. Chosen over a system resolver so the lookup keeps
# the same timeout, retry and circuit-breaker treatment as every other source
# on the scan path, and so no new dependency is added for one feature.
_DOH = "https://cloudflare-dns.com/dns-query"
_HDR = {"Accept": "application/dns-json"}
_TIMEOUT = 6

# Risk added when a sender domain that ought to send mail publishes nothing.
# Deliberately below the SUSPICIOUS floor: the PoC measured 63% precision for
# this signal alone, which corroborates a verdict but must never carry one.
_UNAUTHENTICATED_RISK = 18

_NOT_APPLICABLE = {
    "status": "not_applicable", "available": True,
    "dmarc_policy": None, "dmarc_enforcing": False,
    "spf": None, "mx": False,
    "detail": "Domain cannot publish its own mail policy.",
}

_UNKNOWN = {
    "status": "unknown", "available": False,
    "dmarc_policy": None, "dmarc_enforcing": False,
    "spf": None, "mx": False,
    "detail": "DNS did not answer — mail authentication could not be checked.",
}


def _query(name: str, rrtype: str) -> list[str] | None:
    """Record values for `name`, [] when the name answers with none, None on
    failure.

    None and [] must stay distinct all the way up. Collapsing them would let a
    dropped packet read as "this bank publishes no DMARC".
    """
    resp = requests.get(_DOH, params={"name": name, "type": rrtype},
                        headers=_HDR, timeout=_TIMEOUT)
    if resp.status_code in (429, 500, 502, 503, 504):
        raise SourceUnavailable("DoH HTTP %d" % resp.status_code)
    if resp.status_code != 200:
        return None
    try:
        data = resp.json()
    except ValueError:
        return None
    # 0 NOERROR, 3 NXDOMAIN — both are real answers. Anything else is the
    # resolver reporting its own trouble, not a fact about the domain.
    if data.get("Status") not in (0, 3):
        return None

    out = []
    for ans in data.get("Answer") or []:
        val = (ans.get("data") or "").strip()
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1]
        out.append(val.replace('" "', ""))
    return out


def _dmarc_policy(records: list[str]) -> str | None:
    """The p= value of the first real DMARC record, or None."""
    for rec in records:
        if "v=DMARC1" not in rec:
            continue
        for part in rec.split(";"):
            part = part.strip()
            if part.lower().startswith("p="):
                return part[2:].strip().lower() or None
    return None


def _spf_strength(records: list[str]) -> str | None:
    """'strict' for -all, 'soft' for anything weaker, None if no SPF."""
    for rec in records:
        if rec.lower().startswith("v=spf1"):
            return "strict" if "-all" in rec else "soft"
    return None


def dns_posture_sync(domain: str) -> dict:
    """The three lookups, reduced to the fact the scorer acts on."""
    d = (domain or "").lower().strip().rstrip(".")
    if not d or is_shared_hosting_tenant(d):
        return dict(_NOT_APPLICABLE)

    cached = cache_get(_KEY + d)
    if cached is not None:
        return cached

    def _call() -> dict:
        dmarc = _query("_dmarc." + d, "TXT")
        txt = _query(d, "TXT")
        mx = _query(d, "MX")

        # One failed lookup is enough to withhold the verdict. Two thirds of an
        # answer cannot support "publishes nothing".
        if dmarc is None or txt is None or mx is None:
            return dict(_UNKNOWN)

        policy = _dmarc_policy(dmarc)
        spf = _spf_strength(txt)
        has_mx = bool(mx)
        enforcing = policy in ("reject", "quarantine")

        if enforcing:
            status = "protected"
            detail = ("Publishes an enforcing DMARC policy (p=%s); "
                      "the domain is hard to spoof." % policy)
        elif policy or spf or has_mx:
            status = "partial"
            bits = []
            if policy:
                bits.append("DMARC p=%s (not enforcing)" % policy)
            if spf:
                bits.append("SPF (%s)" % spf)
            if has_mx:
                bits.append("MX")
            detail = "Publishes " + ", ".join(bits) + ", but no enforcing DMARC policy."
        else:
            status = "unauthenticated"
            detail = ("Publishes no DMARC, no SPF and no MX — a domain that "
                      "sends mail but claims no mail identity.")

        result = {"status": status, "available": True,
                  "dmarc_policy": policy, "dmarc_enforcing": enforcing,
                  "spf": spf, "mx": has_mx, "detail": detail}
        cache_put(_KEY + d, result)
        return result

    return guarded("dns_auth", _call, fallback=dict(_UNKNOWN))


def posture_risk(posture: dict) -> int:
    """Risk points this posture contributes.

    Only "unauthenticated" scores. "unknown" scores zero by design: the source
    failed, and a failed source is not evidence.
    """
    if not posture or not posture.get("available"):
        return 0
    return _UNAUTHENTICATED_RISK if posture.get("status") == "unauthenticated" else 0


async def check_dns_auth(domain: str) -> dict:
    """Non-blocking entry point — DNS mail-authentication posture."""
    return await asyncio.to_thread(dns_posture_sync, domain)
