"""
Content-based phishing analysis for the URL scanner.

Public surface
--------------
  analyze_page_content(url, html=None) -> {
      "has_password_field":   bool,
      "has_login_form":       bool,
      "external_form_action": bool,
      "brand_mismatch":       bool,
      "suspicious_signals":   list[str],
      "content_risk":         int,   # 0-100
      "fetched":              bool,  # whether HTML was actually obtained
  }

The page HTML is parsed statically with BeautifulSoup — JavaScript is NEVER
executed. The HTML is taken from (in order):
  1. a pre-fetched `html` string (e.g. reused from the urlscan.io sandbox), or
  2. a single safe requests.get() with a short timeout, a browser-like
     User-Agent, capped response size, and only text/html content accepted.

Everything fails safe: any error, timeout, or non-HTML response returns the
null fallback with content_risk = 0.
"""

import hashlib
import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from apis.net_guard import safe_get
from apis.typosquat import BRANDS, _clean_domain, _split_registrable

_TIMEOUT = 6
_MAX_BYTES = 2_000_000  # 2 MB cap — phishing kits are tiny; this guards against abuse
_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml",
}

# Markers of obfuscated / packed JavaScript commonly used by phishing kits.
_OBFUSCATION_RE = re.compile(
    r"\b(eval|unescape|atob|fromcharcode|document\.write)\s*\(",
    re.IGNORECASE,
)
_LONG_HEX_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2}){12,}")        # \x68\x65... blobs
_LONG_B64_RE = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")          # long base64 payloads

# Client-side (JavaScript) redirect markers — complements the static meta-refresh
# check. We never execute JS; we only string-match common redirect idioms.
_JS_REDIRECT_RE = re.compile(
    r"(?:window|document)\.location(?:\.(?:href|replace|assign))?\s*[=(]"
    r"|location\.(?:href\s*=|replace\s*\(|assign\s*\()",
    re.IGNORECASE,
)

# Credential-harvesting vocabulary, only counted when it appears IN/AROUND a login
# form (not anywhere in body copy — legit sites use these words too).
_LOGIN_KEYWORD_RE = re.compile(
    r"\b(verify your (?:account|identity)|confirm your (?:password|identity|account)"
    r"|sign in to continue|account (?:suspended|locked|will be closed)"
    r"|enter your (?:password|pin|otp|credentials)|update your (?:password|billing)"
    r"|re-?enter your password|validate your account)\b",
    re.IGNORECASE,
)

# Favicon comparison (best-effort, budget-bound). Map brand -> known-good favicon
# md5 hashes. Seeded empty by default: when empty the check never fires (fail
# neutral). Operators can populate this to catch favicon spoofing of a brand.
_FAVICON_TIMEOUT = 2
_FAVICON_MAX_BYTES = 200_000
_BRAND_FAVICON_HASHES: dict[str, set[str]] = {}

# A cross-origin form action is only CREDENTIAL HARVESTING when the form
# actually carries a password field. Audit finding 4 (2026-07-27):
# schneier.com scored content_risk 60 and was reported as "posting credentials
# to a different domain" purely because its DuckDuckGo *search* box submits
# cross-origin — has_password_field and has_login_form were both False. An
# external search box, a Mailchimp newsletter field or a Google CSE is ordinary
# web design; charging it +35 produced false positives on legitimate sites AND
# a user-facing claim that was factually untrue. Matches the aggregator's
# strong_credential_harvest rule, which already requires has_password_field.
_EXTERNAL_CREDENTIALS_SIGNAL = "credentials to external domain"


def _score_content_signals(*, has_password_field: bool, has_login_form: bool,
                           external_form_action: bool, brand_mismatch: bool,
                           title_brand_mismatch: bool, favicon_brand_mismatch: bool,
                           js_redirect: bool, login_keywords_near_form: bool,
                           external_resource_count: int, signals: list) -> dict:
    """
    Pure risk scoring over the DOM facts already extracted from a page.

    Separated from the fetch/parse path so the scoring rules are testable
    without a network round-trip (see tests/test_audit_fixes.py).

    `external_form_action` arrives as "some form on this page posts
    cross-origin" and is DOWNGRADED here to "a credential form posts
    cross-origin" — see _EXTERNAL_CREDENTIALS_SIGNAL above. When the page has
    no password field the flag is cleared and any signal claiming credentials
    are submitted is dropped, so neither the score nor the user-facing text
    asserts something untrue.
    """
    external_credential_post = bool(external_form_action and has_password_field)

    kept = list(signals or [])
    if not external_credential_post:
        kept = [s for s in kept if _EXTERNAL_CREDENTIALS_SIGNAL not in s]

    risk = 0
    if has_password_field:
        risk += 25
    if has_login_form:
        risk += 15
    if external_credential_post:
        risk += 35
    if brand_mismatch:
        risk += 30
    if title_brand_mismatch:
        risk += 20
    if favicon_brand_mismatch:
        risk += 15
    if js_redirect:
        risk += 10
    if login_keywords_near_form:
        risk += 10
    # External-resource fan-out: weak, scaled, capped at +15.
    if external_resource_count >= 3:
        risk += min(15, 3 * (external_resource_count - 2))

    # de-duplicate signals, preserving order
    seen, uniq = set(), []
    for s in kept:
        if s not in seen:
            uniq.append(s)
            seen.add(s)
    risk += 10 * len(uniq)

    return {
        "has_password_field": has_password_field,
        "has_login_form": has_login_form,
        "external_form_action": external_credential_post,
        "brand_mismatch": brand_mismatch,
        "title_brand_mismatch": title_brand_mismatch,
        "favicon_brand_mismatch": favicon_brand_mismatch,
        "js_redirect": js_redirect,
        "login_keywords_near_form": login_keywords_near_form,
        "external_resource_count": external_resource_count,
        "suspicious_signals": uniq,
        "content_risk": max(0, min(100, risk)),
        "fetched": False,
    }


_FALLBACK = {
    "has_password_field": False,
    "has_login_form": False,
    "external_form_action": False,
    "brand_mismatch": False,
    "title_brand_mismatch": False,
    "favicon_brand_mismatch": False,
    "js_redirect": False,
    "login_keywords_near_form": False,
    "external_resource_count": 0,
    "suspicious_signals": [],
    "content_risk": 0,
    "fetched": False,
}

# Small allowlist of major, high-reputation domains. A brand mention on one of
# these (e.g. github.com linking to its Instagram) is never impersonation, so
# brand-mismatch detection is skipped for them outright. Reputation-gated
# domains (valid HTTPS + age > 1yr + low ML prob) get the same pass in the
# aggregator; this list just covers the well-known non-brand cases up front.
_MAJOR_DOMAINS = {
    "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
    "wikipedia.org", "mozilla.org", "cloudflare.com", "reddit.com",
    "medium.com", "wordpress.com", "atlassian.com", "slack.com",
    "zoom.us", "salesforce.com", "shopify.com", "godaddy.com",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fetch_html(url: str) -> str | None:
    """
    Single safe GET. Returns HTML text or None. Never raises.

    Goes through net_guard.safe_get, which refuses internal/metadata addresses
    and re-checks every redirect hop (SSRF — OWASP A10). A blocked URL raises
    BlockedURLError, which the except below turns into the usual None.
    """
    try:
        resp = safe_get(
            url,
            headers=_HEADERS,
            timeout=_TIMEOUT,
            stream=True,
        )
        ctype = resp.headers.get("Content-Type", "").lower()
        if "html" not in ctype and "xml" not in ctype:
            resp.close()
            return None
        # Read at most _MAX_BYTES so a hostile server can't exhaust memory.
        raw = resp.raw.read(_MAX_BYTES, decode_content=True)
        resp.close()
        encoding = resp.encoding or "utf-8"
        return raw.decode(encoding, errors="replace")
    except Exception:
        return None


def _action_domain(action: str, page_domain: str) -> str | None:
    """Registrable domain a form posts to, or None for same-origin/relative."""
    action = (action or "").strip()
    if not action or action.startswith(("#", "javascript:", "mailto:", "?", "/")):
        return None
    if action.startswith("//"):
        action = "https:" + action
    if "://" not in action:
        return None  # relative path -> same origin
    dom = _clean_domain(action)
    if not dom:
        return None
    reg, _ = _split_registrable(dom)
    return reg


def _domain_brands(registrable: str) -> set[str]:
    """
    Brands this page may legitimately present: any brand whose official domain
    equals the registrable, plus a brand whose NAME is the registrable's own
    label (BUG-4: DHL branding on dhl.de is not a MISmatch — the domain is
    literally named dhl; whether dhl.de is DHL's real domain is the typosquat/
    reputation channels' establishment-aware question, and dhl.gq still
    convicts there).
    """
    own = {b for b, officials in BRANDS.items() if registrable in officials}
    label = registrable.split(".", 1)[0]
    if label in BRANDS:
        own.add(label)
    return own


def _resource_registrable(src: str, page_url: str) -> str | None:
    """
    Registrable domain a sub-resource (script/img/link/iframe) is loaded from,
    or None for same-origin / relative / non-http references. Used to count how
    many resources fan out to OTHER registrable domains.
    """
    src = (src or "").strip()
    if not src or src.startswith(("#", "data:", "javascript:", "mailto:", "blob:")):
        return None
    if src.startswith("//"):
        src = "https:" + src
    if "://" not in src:
        return None  # relative path -> same origin
    dom = _clean_domain(src)
    if not dom:
        return None
    reg, _ = _split_registrable(dom)
    return reg or None


def _favicon_hash(page_url: str, soup: "BeautifulSoup") -> str | None:
    """
    md5 of the page favicon bytes, or None. Budget-bound (short timeout, byte
    cap) and fully fail-safe so it never blows the content budget or raises.

    The href comes from attacker-controlled page HTML, so this fetch is guarded
    the same way as the page fetch itself.
    """
    try:
        href = None
        for link in soup.find_all("link"):
            rels = " ".join(link.get("rel") or []).lower()
            if "icon" in rels and link.get("href"):
                href = link.get("href")
                break
        target = urljoin(page_url, href) if href else urljoin(page_url, "/favicon.ico")
        resp = safe_get(target, headers=_HEADERS, timeout=_FAVICON_TIMEOUT, stream=True)
        raw = resp.raw.read(_FAVICON_MAX_BYTES, decode_content=True)
        resp.close()
        return hashlib.md5(raw).hexdigest() if raw else None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyze_page_content(url: str, html: str | None = None) -> dict:
    try:
        if html is None:
            html = _fetch_html(url)
        if not html:
            return _FALLBACK.copy()

        page_domain = _clean_domain(url)
        page_registrable, _ = _split_registrable(page_domain)

        soup = BeautifulSoup(html, "html.parser")
        signals: list[str] = []

        # --- credential inputs ------------------------------------------------
        password_inputs = soup.find_all("input", attrs={"type": "password"})
        has_password_field = len(password_inputs) > 0

        forms = soup.find_all("form")
        has_login_form = False
        external_form_action = False
        login_context_parts: list[str] = []  # text in/around credential forms
        for form in forms:
            inputs = form.find_all("input")
            types = {(i.get("type") or "text").lower() for i in inputs}
            names = " ".join(
                (i.get("name") or "") + " " + (i.get("id") or "") for i in inputs
            ).lower()
            looks_like_login = (
                "password" in types
                or bool(re.search(r"user|email|login|account|passwd", names))
            )
            if looks_like_login and ("password" in types or "email" in types or "text" in types):
                has_login_form = True
                # Capture the brand-bearing context of a credential form: its own
                # text plus the input placeholders / aria-labels users actually see.
                login_context_parts.append(form.get_text(" ", strip=True))
                for i in inputs:
                    login_context_parts.append(
                        f"{i.get('placeholder') or ''} {i.get('aria-label') or ''}"
                    )

            # Form action posting to a DIFFERENT registrable domain.
            act_dom = _action_domain(form.get("action", ""), page_domain)
            if act_dom and act_dom != page_registrable:
                external_form_action = True
                signals.append(f"Form submits credentials to external domain '{act_dom}'")

        # --- brand mismatch ---------------------------------------------------
        # Only treat a brand as impersonated when it appears in a HIGH-SIGNAL
        # location: the page <title>, a main heading (h1/h2), or in/around a
        # login form. A brand name buried in body copy, a footer, or a social
        # link is NOT impersonation — legit sites reference other brands there
        # all the time. (Reputation-gated allowlisting happens in the aggregator.)
        title = (soup.title.string if soup.title and soup.title.string else "") or ""
        heading_text = " ".join(
            h.get_text(" ", strip=True) for h in soup.find_all(["h1", "h2"])
        )
        # Drop script/style so they can't leak into headings on re-parse.
        for tag in soup(["script", "style", "noscript"]):
            tag.extract()
        high_signal_text = " ".join(
            [title, heading_text] + login_context_parts
        )[:20000].lower()

        title_lower = title.lower()
        own_brands = _domain_brands(page_registrable)
        brand_mismatch = False
        title_brand_mismatch = False
        mismatch_brand: str | None = None
        if page_registrable not in _MAJOR_DOMAINS:
            for brand in BRANDS:
                if brand in own_brands:
                    continue  # this IS the brand's official site
                # require a word-ish boundary to avoid 'ups' inside 'groups' etc.
                if re.search(rf"\b{re.escape(brand)}\b", high_signal_text):
                    brand_mismatch = True
                    mismatch_brand = brand
                    # A brand name in the <title> specifically is a stronger spoof
                    # signal than one merely near the login form.
                    if re.search(rf"\b{re.escape(brand)}\b", title_lower):
                        title_brand_mismatch = True
                    signals.append(
                        f"Page presents '{brand}' branding in its title/heading/login "
                        f"form but is served from '{page_registrable}'"
                    )
                    break

        # --- external sub-resource fan-out ------------------------------------
        # Count script/img/link/iframe resources loaded from a DIFFERENT
        # registrable domain. A high count alongside a credential form is a weak
        # corroborating signal (kits hot-link the real brand's assets). Parsed
        # fresh because script/style tags were extract()-ed from `soup` above.
        res_soup = BeautifulSoup(html, "html.parser")
        external_resource_count = 0
        for tag, attr in (("script", "src"), ("img", "src"),
                          ("link", "href"), ("iframe", "src")):
            for el in res_soup.find_all(tag):
                reg = _resource_registrable(el.get(attr, ""), url)
                if reg and reg != page_registrable:
                    external_resource_count += 1

        # --- credential keywords IN/AROUND the login form ---------------------
        login_blob = " ".join(login_context_parts).lower()
        login_keywords_near_form = bool(has_login_form and _LOGIN_KEYWORD_RE.search(login_blob))
        if login_keywords_near_form:
            signals.append("Credential-harvesting wording in/around the login form")

        # --- favicon spoofing (best-effort, only when a brand is claimed) ------
        favicon_brand_mismatch = False
        if mismatch_brand and mismatch_brand in _BRAND_FAVICON_HASHES:
            fh = _favicon_hash(url, soup)
            if fh and fh not in _BRAND_FAVICON_HASHES[mismatch_brand]:
                favicon_brand_mismatch = True
                signals.append(
                    f"Favicon does not match the '{mismatch_brand}' brand it presents"
                )

        # --- obfuscated / suspicious scripts ----------------------------------
        scripts_blob = " ".join(s.get_text() for s in BeautifulSoup(html, "html.parser")("script"))
        if _OBFUSCATION_RE.search(scripts_blob):
            signals.append("Obfuscated JavaScript (eval/atob/fromCharCode/document.write)")
        if _LONG_HEX_RE.search(scripts_blob):
            signals.append("Long hex-encoded script blob")
        if _LONG_B64_RE.search(scripts_blob):
            signals.append("Long base64-encoded payload in script")

        # Client-side (JavaScript) redirect — no JS executed, just string match.
        js_redirect = bool(_JS_REDIRECT_RE.search(scripts_blob))
        if js_redirect:
            signals.append("JavaScript redirect (window/document.location)")

        # Hidden iframes & auto-refresh redirects are classic kit behaviours.
        for ifr in soup.find_all("iframe"):
            style = (ifr.get("style") or "").lower()
            if ifr.get("hidden") is not None or "display:none" in style or "visibility:hidden" in style:
                signals.append("Hidden iframe")
                break
        meta_refresh = soup.find("meta", attrs={"http-equiv": re.compile("refresh", re.I)})
        if meta_refresh and "url=" in (meta_refresh.get("content") or "").lower():
            signals.append("Meta-refresh redirect")

        if has_password_field and url.lower().startswith("http://"):
            signals.append("Password field served over insecure HTTP")

        scored = _score_content_signals(
            has_password_field=has_password_field,
            has_login_form=has_login_form,
            external_form_action=external_form_action,
            brand_mismatch=brand_mismatch,
            title_brand_mismatch=title_brand_mismatch,
            favicon_brand_mismatch=favicon_brand_mismatch,
            js_redirect=js_redirect,
            login_keywords_near_form=login_keywords_near_form,
            external_resource_count=external_resource_count,
            signals=signals,
        )
        scored["fetched"] = True
        return scored

    except Exception:
        return _FALLBACK.copy()


# ---------------------------------------------------------------------------
# Self-test  (python -m apis.page_content <url|->)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) > 1 and sys.argv[1] != "-":
        out = analyze_page_content(sys.argv[1])
    else:
        # Read HTML from stdin for offline testing against a phishing sample.
        sample = sys.stdin.read()
        out = analyze_page_content("http://paypal-secure-login.xyz/login", html=sample)
    print(json.dumps(out, indent=2))
