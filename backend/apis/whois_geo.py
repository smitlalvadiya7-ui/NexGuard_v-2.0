"""
WHOIS + IP geolocation enrichment for the URL scanner.

Public surface
--------------
  async check_geo(domain)   -> {"ip_location": str|None, "ip_country": str|None}
  async check_whois(domain) -> {"registrar": str|None, "created": str|None,
                                "age": str|None, "country": str|None}

Both use keyless, free services so they work out of the box:
  * geo   — ip-api.com (resolves the hostname itself, no API key)
  * whois — RDAP via rdap.org (structured JSON; replaces legacy port-43 WHOIS)

The blocking HTTP work runs in a thread-pool via asyncio.to_thread() so it
never blocks the FastAPI event loop.  Any error / timeout degrades gracefully
to null fields, and definitive results are cached by domain via url_cache.
"""

import asyncio
from datetime import datetime, timezone

import requests

from apis.url_cache import cache_get, cache_put
from apis.circuit_breaker import guarded, SourceUnavailable

_GEO_KEY = "geo:"
_WHOIS_KEY = "whois:"

# asn  — autonomous-system number/name (e.g. "AS13335 Cloudflare, Inc.")
# hosting — the hosting/ISP org serving the IP (bulletproof/free hosts are a tell)
_FB_GEO = {"ip_location": None, "ip_country": None, "asn": None, "hosting": None}
_FB_WHOIS = {"registrar": None, "created": None, "age": None, "country": None,
             "age_days": None}

# Request ASN + ISP/org alongside geo in the SAME free ip-api call (no extra key).
_GEO_URL = ("http://ip-api.com/json/{domain}"
            "?fields=status,country,regionName,city,query,as,asname,isp,org")
_RDAP_URL = "https://rdap.org/domain/{domain}"


# ---------------------------------------------------------------------------
# Geo
# ---------------------------------------------------------------------------

def _geo_sync(domain: str) -> dict:
    if not domain:
        return _FB_GEO.copy()

    cached = cache_get(_GEO_KEY + domain)
    if cached is not None:
        return cached

    def _call() -> dict:
        resp = requests.get(_GEO_URL.format(domain=domain), timeout=5)
        if resp.status_code in (429, 500, 502, 503, 504):
            raise SourceUnavailable(f"ip-api HTTP {resp.status_code}")
        if resp.status_code != 200:
            return _FB_GEO.copy()
        data = resp.json()
        if data.get("status") != "success":
            # private/reserved/unknown IP — definitive, not a source failure.
            return _FB_GEO.copy()

        country = data.get("country")
        parts = [data.get("city"), data.get("regionName"), country]
        location = ", ".join(p for p in parts if p) or None

        # ASN string ("AS13335 Cloudflare") and the hosting org / ISP.
        asn = data.get("as") or (
            f"{data.get('asname')}".strip() if data.get("asname") else None
        )
        hosting = data.get("org") or data.get("isp") or None

        result = {"ip_location": location, "ip_country": country,
                  "asn": asn or None, "hosting": hosting}
        cache_put(_GEO_KEY + domain, result)
        return result

    return guarded("ip_geo", _call, fallback=_FB_GEO.copy())


async def check_geo(domain: str) -> dict:
    """Non-blocking entry point — IP geolocation for a domain."""
    return await asyncio.to_thread(_geo_sync, domain)


# ---------------------------------------------------------------------------
# Geo point (lat/lng) — used by the /analytics threat map
# ---------------------------------------------------------------------------

_GEO_PT_KEY = "geopt:"
_GEO_PT_URL = "http://ip-api.com/json/{domain}?fields=status,country,lat,lon,query"
_FB_GEO_PT = {"country": None, "lat": None, "lng": None}


def _geo_point_sync(domain: str) -> dict:
    if not domain:
        return _FB_GEO_PT.copy()

    cached = cache_get(_GEO_PT_KEY + domain)
    if cached is not None:
        return cached

    try:
        resp = requests.get(_GEO_PT_URL.format(domain=domain), timeout=5)
        if resp.status_code != 200:
            return _FB_GEO_PT.copy()
        data = resp.json()
        if data.get("status") != "success":
            return _FB_GEO_PT.copy()

        result = {
            "country": data.get("country"),
            "lat": data.get("lat"),
            "lng": data.get("lon"),
        }
        if result["lat"] is not None:
            cache_put(_GEO_PT_KEY + domain, result)
        return result
    except Exception:
        return _FB_GEO_PT.copy()


async def geo_point(domain: str) -> dict:
    """Non-blocking entry point — {country, lat, lng} for a domain."""
    return await asyncio.to_thread(_geo_point_sync, domain)


# ---------------------------------------------------------------------------
# WHOIS (via RDAP)
# ---------------------------------------------------------------------------

def _vcard_value(entity: dict, field: str):
    """Pull a value (e.g. 'fn') out of an RDAP entity's jCard/vcardArray."""
    try:
        for item in entity["vcardArray"][1]:
            if item[0] == field:
                return item[3]
    except Exception:
        pass
    return None


def _vcard_country(entity: dict):
    """Country is the last element of a jCard 'adr' structured value."""
    try:
        for item in entity["vcardArray"][1]:
            if item[0] == "adr":
                adr = item[3]
                if isinstance(adr, list) and adr:
                    last = adr[-1]
                    return last or None
    except Exception:
        pass
    return None


def _age_days(created_iso: str):
    """Whole days since registration, or None if unparseable / in the future."""
    try:
        dt = datetime.fromisoformat(created_iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        days = (datetime.now(timezone.utc) - dt).days
        return days if days >= 0 else None
    except Exception:
        return None


def _human_age(created_iso: str):
    """Turn an ISO registration date into a human age like '12 yr 3 mo'."""
    days = _age_days(created_iso)
    if days is None:
        return None
    years, rem = divmod(days, 365)
    months = rem // 30
    if years and months:
        return f"{years} yr {months} mo"
    if years:
        return f"{years} yr"
    if months:
        return f"{months} mo"
    return f"{days} d"


def _whois_sync(domain: str) -> dict:
    if not domain:
        return _FB_WHOIS.copy()

    cached = cache_get(_WHOIS_KEY + domain)
    if cached is not None:
        return cached

    def _call() -> dict:
        resp = requests.get(
            _RDAP_URL.format(domain=domain),
            headers={"Accept": "application/rdap+json"},
            timeout=8,
        )
        if resp.status_code in (429, 500, 502, 503, 504):
            raise SourceUnavailable(f"RDAP HTTP {resp.status_code}")
        if resp.status_code != 200:
            # 404 = domain not in this RDAP server; definitive, not a failure.
            return _FB_WHOIS.copy()
        data = resp.json()

        entities = data.get("entities", []) or []

        # registrar name + (best-effort) country
        registrar = None
        country = None
        for ent in entities:
            roles = ent.get("roles", []) or []
            if "registrar" in roles and not registrar:
                registrar = _vcard_value(ent, "fn")
            if "registrant" in roles and not country:
                country = _vcard_country(ent)

        # registration date -> age
        created = None
        for ev in data.get("events", []) or []:
            if ev.get("eventAction") == "registration":
                created = ev.get("eventDate")
                break

        result = {
            "registrar": registrar,
            "created": created,
            "age": _human_age(created) if created else None,
            "age_days": _age_days(created) if created else None,
            "country": country,
        }
        # only cache if we actually learned something
        if any(v is not None for v in result.values()):
            cache_put(_WHOIS_KEY + domain, result)
        return result

    return guarded("rdap_whois", _call, fallback=_FB_WHOIS.copy())


async def check_whois(domain: str) -> dict:
    """Non-blocking entry point — RDAP/WHOIS lookup for a domain."""
    return await asyncio.to_thread(_whois_sync, domain)


# ---------------------------------------------------------------------------
# Self-test  (python -m apis.whois_geo <domain>)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"

    async def _run():
        geo, who = await asyncio.gather(check_geo(target), check_whois(target))
        print("geo  :", geo)
        print("whois:", who)

    asyncio.run(_run())
