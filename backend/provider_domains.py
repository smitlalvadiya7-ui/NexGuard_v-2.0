"""
Maintained allowlist of first-party CDN / API / infrastructure provider
domains, shared by aggregator (reputable-host detection), ai_engine (brand
impersonation) and apis.typosquat (self-impersonation exemption).

Leaf module: imports nothing from the project, so any module may import it
without creating a cycle (aggregator imports both ai_engine and apis.typosquat).

Real-world false positives cluster on major CDN / API / infrastructure apex
domains whose names tokenise to "phishing-like" lexical features (lots of
digits/hyphens/subdomains), embed their own brand name (googletagmanager.com
is NOT a typosquat of google), or legitimately serve security vocabulary.
These providers — and ALL their subdomains — are reputable in their own right
and must never be pushed past SUSPICIOUS by weak lexical/keyword/ML signals
alone. This is a MAINTAINED list: add new providers here as they surface.

Deliberately NOT here: tenant-content stores (amazonaws.com, cloudfront.net,
storage.googleapis.com, …) — anything serving customer-controlled content
belongs in aggregator's SHARED_HOSTING_SUFFIXES / TENANT_CONTENT_APEXES.
"""

PROVIDER_REPUTABLE_DOMAINS = {
    # Google
    "google.com", "googleapis.com", "gstatic.com", "googletagmanager.com",
    "googleusercontent.com", "googlevideo.com", "google-analytics.com",
    "googlesyndication.com", "doubleclick.net", "ggpht.com", "ytimg.com",
    "youtube.com", "youtu.be", "recaptcha.net", "withgoogle.com",
    "googledomains.com",
    # Microsoft
    "microsoft.com", "microsoftonline.com", "msftauth.net", "msauth.net",
    "windows.net", "windowsupdate.com", "azure.com", "cloud.microsoft",
    "office.com", "office365.com", "live.com", "outlook.com", "msn.com",
    "sharepoint.com", "bing.com", "skype.com", "microsoftstore.com",
    # Apple
    "apple.com", "apple-dns.net", "icloud.com", "mzstatic.com", "cdn-apple.com",
    # Amazon / AWS — first-party asset domains only. Tenant-content stores
    # (amazonaws.com / cloudfront.net) live in SHARED_HOSTING_SUFFIXES, since
    # a bucket / distribution can host arbitrary customer (phishing) pages.
    "amazon.com", "awsstatic.com", "media-amazon.com", "ssl-images-amazon.com",
    # Cloudflare / Akamai edge infra. The customer-content edges (fastly.net,
    # akamaized.net, akamaihd.net) are shared-hosting, not blanket-safe.
    "cloudflare.com", "cloudflare.net", "cloudflareinsights.com",
    "akamai.net", "akamaiedge.net",
    # Meta
    "facebook.com", "fbcdn.net", "fb.com", "instagram.com", "cdninstagram.com",
    "whatsapp.com", "whatsapp.net",
    # Popular JS / asset CDNs
    "jsdelivr.net", "unpkg.com", "jquery.com", "bootstrapcdn.com",
    # Other major global platforms observed as false positives
    "dzen.ru", "yandex.ru", "yandex.net", "ya.ru",
}


# Closed single-registrant brand TLDs (ICANN Spec 13): only the brand itself
# can register names under these, so EVERY hostname there is first-party
# (domains.google — the googledomains.com redirect target and a live FP
# 2026-07-14 — learn.microsoft, support.apple; c.gle — Google's notification
# redirector whose long random tokens read as phishy lexical features, the
# BUG 1 email FP of 2026-07-16).
BRAND_TLDS = ("google", "microsoft", "apple", "gle")


def is_brand_tld_host(host: str) -> bool:
    """True when host sits under a closed single-registrant brand TLD
    (.google/.microsoft/.apple/.gle) — first-party by definition: no third
    party can register or publish content there."""
    d = (host or "").lower().strip().rstrip(".")
    if not d:
        return False
    return any(d == t or d.endswith("." + t) for t in BRAND_TLDS)


def is_provider_domain(host: str) -> bool:
    """True when host IS, or is a subdomain of, a provider domain — including
    anything under a closed brand TLD."""
    d = (host or "").lower().strip().rstrip(".")
    if not d:
        return False
    if any(d == t or d.endswith("." + t) for t in BRAND_TLDS):
        return True
    return any(d == n or d.endswith("." + n) for n in PROVIDER_REPUTABLE_DOMAINS)
