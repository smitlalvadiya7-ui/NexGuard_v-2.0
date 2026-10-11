"""
Typosquatting & homoglyph detection for the URL scanner.

Public surface
--------------
  check_typosquatting(domain) -> {
      "is_typosquat":       bool,
      "impersonated_brand": str | None,   # e.g. "paypal"
      "technique":          str | None,   # homoglyph | char_swap | lookalike | edit_distance | brand_embedded
      "confidence":         int,          # 0-100
  }

No network I/O — pure local analysis, safe to call via asyncio.to_thread().

Techniques detected
-------------------
  (a) homoglyph substitution — Unicode confusables normalise back to a brand
      (e.g. 'аpple.com' with a Cyrillic 'а', 'gооgle.com').
  (b) edit-distance lookalike — Levenshtein distance 1-2 to a known brand on a
      domain that is NOT the brand's official domain (e.g. 'paypai.com').
  (c) brand embedded in a longer suspicious domain
      (e.g. 'paypal-secure-login.xyz').
  (d) character swaps / leetspeak — rn->m, vv->w, 1->l, 0->o, 5->s …
      (e.g. 'paypa1-login.xyz', 'rnicrosoft.com').
"""

import tldextract
from confusable_homoglyphs import confusables
from rapidfuzz.distance import Levenshtein

from provider_domains import is_provider_domain
from shared_hosting import is_shared_hosting_tenant
from top_domains import is_established_registrable, is_top_registrable

# Bundled-snapshot PSL only (suffix_list_urls=()): no network fetch, no cache
# writes, fully deterministic. Private domains included so a tenant label
# (alice in alice.github.io) is the SLD, never the platform name.
_tld_extract = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
# ICANN-only view for platform-membership questions: the PRIVATE registrable of
# storage.googleapis.com is storage.googleapis.com (tenant-aware), but "is this
# host part of googleapis.com?" needs the ICANN registrable googleapis.com.
_tld_icann = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=False)

# ---------------------------------------------------------------------------
# ~30 commonly impersonated brands -> their official registrable domains.
# A domain whose registrable form is in this set is, by definition, NOT a
# typosquat of that brand.
# ---------------------------------------------------------------------------
BRANDS: dict[str, set[str]] = {
    "paypal":      {"paypal.com"},
    # googleapis.com / amazonaws.com are official infra roots: a GCS or S3
    # tenant URL (bucket.storage.googleapis.com, x.s3.amazonaws.com) is NOT a
    # brand_embedded typosquat of google/amazon — only the exact registrable
    # is exempt, so amaz0naws.com / g00gleapis.com still flag.
    "google":      {"google.com", "gmail.com", "googleapis.com"},
    "apple":       {"apple.com", "icloud.com"},
    "microsoft":   {"microsoft.com", "office.com", "live.com", "outlook.com"},
    "amazon":      {"amazon.com", "amazon.co.uk", "aws.amazon.com", "amazonaws.com"},
    "netflix":     {"netflix.com"},
    "roblox":      {"roblox.com"},
    "facebook":    {"facebook.com", "fb.com"},
    "instagram":   {"instagram.com"},
    "whatsapp":    {"whatsapp.com"},
    "linkedin":    {"linkedin.com"},
    "twitter":     {"twitter.com", "x.com"},
    "youtube":     {"youtube.com"},
    "yahoo":       {"yahoo.com"},
    "dropbox":     {"dropbox.com"},
    "adobe":       {"adobe.com"},
    "spotify":     {"spotify.com"},
    "steam":       {"steampowered.com", "steamcommunity.com"},
    "ebay":        {"ebay.com", "ebay.co.uk"},
    "walmart":     {"walmart.com"},
    "coinbase":    {"coinbase.com"},
    "binance":     {"binance.com"},
    "chase":       {"chase.com"},
    "wellsfargo":  {"wellsfargo.com"},
    "citibank":    {"citibank.com", "citi.com"},
    "hsbc":        {"hsbc.com", "hsbc.co.uk"},
    "barclays":    {"barclays.co.uk", "barclays.com"},
    "lloyds":      {"lloydsbank.com"},
    "santander":   {"santander.com", "santander.co.uk"},
    "natwest":     {"natwest.com"},
    "dhl":         {"dhl.com"},
    "fedex":       {"fedex.com"},
    "ups":         {"ups.com"},

    # ---- Audit 2026-07-27 additions -------------------------------------
    # Every brand below was impersonated by a URL in the live phishing corpus
    # that scored 0 because the brand was simply not listed. raiffiesen.social
    # is one letter off Raiffeisen; swisscomlei.com embeds Swisscom;
    # helptrezor-suite.wasmer.app, robinhood-logint.gitbook.io and
    # garena.vercel.app are tenant-label impersonations (see finding 5).
    "raiffeisen":  {"raiffeisen.ch", "raiffeisen.at", "raiffeisen.ru"},
    "swisscom":    {"swisscom.ch", "swisscom.com"},
    "robinhood":   {"robinhood.com"},
    "trezor":      {"trezor.io"},
    "ledger":      {"ledger.com"},
    "metamask":    {"metamask.io"},
    "garena":      {"garena.com", "garena.sg"},
    "kraken":      {"kraken.com"},
    "revolut":     {"revolut.com"},
    "wise":        {"wise.com"},
    "bankofamerica": {"bankofamerica.com"},
    "americanexpress": {"americanexpress.com", "amex.com"},

    # ---- India-facing coverage ------------------------------------------
    # The brands this product actually defends. Impersonation of Indian banks,
    # wallets and government portals is the core scam family (lottery, digital
    # arrest, KYC, refund), and none of it was represented in the list.
    "sbi":         {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"},
    "hdfc":        {"hdfcbank.com", "hdfc.com"},
    "icici":       {"icicibank.com"},
    "axisbank":    {"axisbank.com"},
    "kotak":       {"kotak.com"},
    "punjabnationalbank": {"pnbindia.in"},
    "bankofbaroda": {"bankofbaroda.in", "bankofbaroda.com"},
    "canarabank":  {"canarabank.com", "canarabank.in"},
    "yesbank":     {"yesbank.in"},
    "indusind":    {"indusind.com"},
    "paytm":       {"paytm.com", "paytmbank.com"},
    "phonepe":     {"phonepe.com"},
    "razorpay":    {"razorpay.com"},
    "bhimupi":     {"bhimupi.org.in"},
    "npci":        {"npci.org.in"},
    "aadhaar":     {"uidai.gov.in"},
    "incometax":   {"incometax.gov.in", "incometaxindia.gov.in"},
    "epfindia":    {"epfindia.gov.in"},
    "irctc":       {"irctc.co.in"},
    "flipkart":    {"flipkart.com"},
    "myntra":      {"myntra.com"},
    "jio":         {"jio.com", "jiofiber.com"},
    "airtel":      {"airtel.in", "airtel.com"},
    "zerodha":     {"zerodha.com"},
    "groww":       {"groww.in"},
    "upstox":      {"upstox.com"},
}

# Leetspeak / character-swap normalisation.
_MULTI_SWAPS = (("rn", "m"), ("vv", "w"), ("nn", "m"))
_LEET_TABLE = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "7": "t", "$": "s", "@": "a", "8": "b",
})

_FALLBACK = {
    "is_typosquat": False,
    "impersonated_brand": None,
    "technique": None,
    "confidence": 0,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clean_domain(domain: str) -> str:
    d = (domain or "").strip().lower()
    d = d.split("//")[-1]            # strip any scheme
    d = d.split("/")[0]             # strip any path
    d = d.split("@")[-1]           # strip any userinfo
    d = d.split(":")[0]            # strip any port
    if d.startswith("www."):
        d = d[4:]
    return d


def _split_registrable(domain: str) -> tuple[str, str]:
    """
    Return (registrable_domain, sld_label), per the Public Suffix List.

    'paypal-secure-login.xyz' -> ('paypal-secure-login.xyz', 'paypal-secure-login')
    'foo.barclays.co.uk'      -> ('barclays.co.uk', 'barclays')
    'www.robiox.com.py'       -> ('robiox.com.py', 'robiox')

    The previous last-two-labels split made every multi-part ccTLD outside a
    small hand list typosquat-blind: www.robiox.com.py (live Roblox-clone FN,
    2026-07-14) yielded registrable 'com.py', so 'robiox' was never compared
    against any brand.
    """
    ext = _tld_extract(domain)
    if not ext.suffix or not ext.domain:
        # No recognised public suffix (localhost, raw IP, garbage): previous
        # last-two-labels behaviour.
        parts = domain.split(".")
        if len(parts) < 2:
            return domain, domain
        return ".".join(parts[-2:]), parts[-2]
    return f"{ext.domain}.{ext.suffix}", ext.domain


def _icann_registrable(domain: str) -> str:
    """Registrable per the ICANN section only (tenant suffixes ignored):
    storage.googleapis.com -> googleapis.com, alice.github.io -> github.io."""
    ext = _tld_icann(domain)
    if not ext.suffix or not ext.domain:
        parts = domain.split(".")
        return domain if len(parts) < 2 else ".".join(parts[-2:])
    return f"{ext.domain}.{ext.suffix}"


def _homoglyph_normalize(s: str) -> str:
    """Replace Unicode confusables with their Latin look-alike (skeleton)."""
    try:
        res = confusables.is_confusable(s, greedy=True, preferred_aliases=["latin"])
    except Exception:
        return s
    if not res:
        return s
    out = s
    for item in res:
        homs = item.get("homoglyphs") or []
        if homs:
            out = out.replace(item["character"], homs[0]["c"])
    return out


def _deleet(s: str) -> str:
    """Undo common character swaps so 'paypa1' -> 'paypal', 'rnicrosoft' -> 'microsoft'."""
    out = s
    for a, b in _MULTI_SWAPS:
        out = out.replace(a, b)
    return out.translate(_LEET_TABLE)


def _find_embedded_brand(text: str) -> str | None:
    """Longest brand name that appears as a substring of text (len>=4)."""
    best = None
    for brand in BRANDS:
        if len(brand) >= 4 and brand in text:
            if best is None or len(brand) > len(best):
                best = brand
    return best


def _closest_brand(label: str) -> tuple[str | None, int]:
    """Brand with the smallest Levenshtein distance to label (and that distance)."""
    best_brand, best_dist = None, 99
    for brand in BRANDS:
        if len(brand) < 4:
            continue
        if abs(len(brand) - len(label)) > 2:
            continue
        d = Levenshtein.distance(label, brand)
        if d < best_dist:
            best_brand, best_dist = brand, d
    return best_brand, best_dist


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def check_typosquatting(domain: str) -> dict:
    domain = _clean_domain(domain)
    if not domain or "." not in domain:
        return _FALLBACK.copy()

    registrable, _ = _split_registrable(domain)
    # Platform-membership uses the ICANN registrable: a tenant label under an
    # official/provider suffix (storage.googleapis.com, kits.s3.amazonaws.com)
    # collapses to the platform root, which is exempt — tenant stores are
    # judged on content, never on the platform's own brand name.
    platform_root = _icann_registrable(domain)

    # The ORIGINAL (un-normalised) registrable form decides whether this is the
    # genuine domain. A homoglyph look-alike has a registrable form that is
    # byte-for-byte different from the real one, so it never short-circuits here.
    for officials in BRANDS.values():
        if registrable in officials or platform_root in officials:
            return _FALLBACK.copy()

    # A provider's OWN registrable domain (googletagmanager.com,
    # microsoftonline.com, apple-dns.net, domains.google, …) is by definition
    # not a typosquat of its own brand — matched on the exact registrable, same
    # semantics as the officials check above, so leet/homoglyph VARIANTS
    # (g00glevideo.com) still flag.
    if is_provider_domain(registrable) or is_provider_domain(platform_root):
        return _FALLBACK.copy()

    # Famous-domain exemption (eval FPs 2026-07-16: bbc.com read as a
    # 'typosquat of hsbc', shopify.com as 'spotify'): a Tranco-top-1000
    # registrable IS the real site. Exact registrable only — the PSL private
    # section keeps tenant labels (alice.blogspot.com), so tenant pages on
    # popular platforms still get judged, as do lookalike variants.
    if is_top_registrable(registrable):
        return _FALLBACK.copy()

    # Normalise away Unicode confusables, then split again on the skeleton.
    # Confusables map to a canonical target that may be UPPERCASE (digit '0'
    # normalises to 'O'), while every later comparison is lowercase — without
    # the lower(), g00glevideo.com normalised to gOOglevideo.com and sailed
    # through every technique.
    normalized = _homoglyph_normalize(domain).lower()
    had_homoglyph = normalized != domain
    norm_registrable, norm_sld = _split_registrable(normalized)
    norm_host = normalized

    def hit(brand, technique, confidence):
        return {
            "is_typosquat": True,
            "impersonated_brand": brand,
            "technique": technique,
            "confidence": confidence,
        }

    # (a) Homoglyph substitution — confusables normalise back onto a brand.
    if had_homoglyph:
        if norm_sld in BRANDS:
            return hit(norm_sld, "homoglyph", 95)
        embedded = _find_embedded_brand(norm_host)
        if embedded:
            return hit(embedded, "homoglyph", 90)

    # (d) Character swaps / leetspeak — de-leet reveals a brand that wasn't there.
    deleeted = _deleet(norm_host)
    if deleeted != norm_host:
        _, deleet_sld = _split_registrable(deleeted)
        if deleet_sld in BRANDS:
            return hit(deleet_sld, "char_swap", 90)
        before = _find_embedded_brand(norm_host)
        after = _find_embedded_brand(deleeted)
        if after and after != before:
            return hit(after, "char_swap", 85)

    # BUG-4 (honest benchmark 2026-07-18): an ESTABLISHED registrable (Tranco
    # top-100k snapshot) is exonerated from the remaining NON-deception
    # techniques — dhl.de IS DHL (convicted 'lookalike of dhl' 88 -> MALICIOUS
    # 70), google.lt / google.com.gt are Google's own country domains, casa.it
    # is not an edit of chase.com, microsoftazuread-sso.com is Microsoft's
    # real SSO infra. Placed AFTER homoglyph/char_swap: deliberate character
    # deception flags even on a ranked domain, and an unestablished dhl.gq
    # (same lexical shape as dhl.de, no real traffic) still convicts below.
    #
    #    Audit finding 5 (2026-07-27): this exemption must NOT reach a
    #    shared-hosting TENANT. _split_registrable uses the PSL private
    #    section, and platform coverage there is inconsistent — gitbook.io and
    #    wasmer.app are absent, so `paypal-logint.gitbook.io` collapsed to the
    #    registrable `gitbook.io`, which IS Tranco-established, and every brand
    #    check below was skipped. The identical label on pages.dev (present in
    #    PSL private) flagged at 72. Measured misses: robinhood-logint.gitbook.io
    #    and helptrezor-suite.wasmer.app both scored 0. The tenant's own label is
    #    attacker-chosen, so an established PLATFORM never exonerates it — while
    #    the platform APEX itself (gitbook.io) still gets the exemption.
    if (not had_homoglyph
            and is_established_registrable(registrable)
            and not is_shared_hosting_tenant(domain)):
        return _FALLBACK.copy()

    # Exact brand label on a NON-official domain (lookalike / wrong TLD).
    if norm_sld in BRANDS:
        return hit(norm_sld, "lookalike", 88)

    # (b) Small edit-distance to a known brand.
    brand, dist = _closest_brand(norm_sld)
    if brand and 1 <= dist <= 2:
        return hit(brand, "edit_distance", 80 if dist == 1 else 66)

    # (c) Brand embedded in a longer, non-official domain.
    embedded = _find_embedded_brand(norm_host)
    if embedded and norm_sld != embedded:
        return hit(embedded, "brand_embedded", 72)

    return _FALLBACK.copy()


# ---------------------------------------------------------------------------
# Self-test  (python -m apis.typosquat <domain> ...)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    tests = sys.argv[1:] or [
        "paypa1-login.xyz",
        "аpple.com",            # Cyrillic 'а'
        "paypal-secure-login.xyz",
        "rnicrosoft.com",
        "paypai.com",
        "google.com",                # legit
        "apple.com",                 # legit
        "amazon.co.uk",              # legit
    ]
    for t in tests:
        out = check_typosquatting(t)
        print(f"{t!r:40} -> {out}")
