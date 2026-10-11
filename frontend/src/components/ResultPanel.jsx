import { VerdictBadge } from "./VerdictBadge.jsx";
import { RiskMeter } from "./RiskMeter.jsx";
import { FlagList } from "./FlagList.jsx";
import { LockOverlay } from "./LockOverlay.jsx";

/*
 * Single result renderer used by every scan surface (URL/QR/email/batch/...).
 *
 * Field names below mirror the documented contract in backend/aggregator.py
 * (~lines 1-27 and the assembled `result` dict ~1156-1218) and the premium
 * gating list `_PREMIUM_FIELDS` in backend/main.py (~302-306), which is what
 * populates `result.tier_locked` via `strip_premium()` for free/anonymous
 * viewers (main.py /scan, ~1087-1111). When a field is locked, the backend
 * has already nulled its value server-side — LockOverlay just needs to know
 * *that* a section is gated; it doesn't depend on the (absent) data to do so.
 *
 *   resolved IP     -> result.resolved_ip                    (locked: "resolved_ip")
 *   geolocation     -> result.ip_location/ip_country/asn/hosting (locked: "ip_location")
 *   WHOIS/domain age -> result.whois {registrar, age, age_days, created, country} (locked: "whois")
 *   SSL certificate -> result.ssl_cert {has_cert, issuer, is_free_ca, issued, expires, subject_cn, ...} (locked: "ssl_cert")
 *   redirect chain  -> result.redirects ONLY                                (locked: "redirects")
 *   page preview    -> result.screenshot_url / result.page_title            (locked: "screenshot_url")
 *
 * ("redirects" is the name _PREMIUM_FIELDS strips and, per aggregator.py:695,
 * is [] or the full >=2-hop chain. "redirect_chain" is an always-present,
 * never-stripped duplicate and is intentionally NOT read at all: as a locked
 * fallback it leaked real hops under the blur, and as an unlocked fallback
 * the two fields could disagree and hide real hops.)
 */

// Confidence -> a plain High/Medium/Low label (with the % when numeric), so
// the verdict carries a clear "how sure are we" signal (WORK_PLAN Task 6).
function confidenceLabel(confidence) {
  if (confidence === null || confidence === undefined || confidence === "") return null;
  if (typeof confidence === "number") {
    const level = confidence >= 75 ? "High" : confidence >= 45 ? "Medium" : "Low";
    return { level, text: `${level} confidence · ${Math.round(confidence)}%` };
  }
  const s = String(confidence);
  return { level: s, text: `${s} confidence` };
}

// Friendly, plain-language names for the ML feature keys (WORK_PLAN Task 6).
// n-gram buckets (ng_###) are opaque hashes, so they collapse to one honest
// "text pattern in the URL" label. Anything unmapped is title-cased.
const FEATURE_LABELS = {
  tld_risk: "Risky top-level domain",
  suspicious_tld: "Suspicious domain ending",
  length_url: "Very long web address",
  length_hostname: "Long host name",
  nb_dots: "Many dots in the address",
  nb_hyphens: "Many hyphens in the address",
  nb_subdomains: "Many subdomains",
  nb_at: "'@' in the address",
  has_ip: "IP address used as the domain",
  has_https: "Uses HTTPS",
  is_shortener: "Link shortener",
  has_punycode: "Punycode (look-alike) characters",
  domain_entropy: "Random-looking domain",
  nb_phish_hints: "Phishing words in the address",
  brand_in_subdomain_or_path: "Brand name in an odd place",
  ratio_digits_url: "Lots of digits in the address",
  nb_digits: "Many digits in the address",
  max_digit_run: "Long run of digits",
  nb_path_segments: "Deep path",
  length_path: "Long path",
  length_query: "Long query string",
  nb_percent: "Encoded characters in the address",
  prefix_suffix: "Hyphen in the domain",
  longest_word_host: "Long word in the host",
  tld_in_path: "Domain ending appears in the path",
};

function featureLabel(name) {
  if (!name) return "";
  if (name.startsWith("ng_")) {
    // Char-model factors carry the real URL text (ng_login-); legacy hashed
    // buckets (ng_042) are opaque and keep the generic label.
    const text = name.slice(3);
    if (text && !/^\d+$/.test(text)) return `Suspicious text "${text}" in the address`;
    return "Suspicious text pattern in the URL";
  }
  if (FEATURE_LABELS[name]) return FEATURE_LABELS[name];
  return name.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

const SOURCE_STATUS_CLASS = {
  flag: "text-danger",
  warn: "text-warn",
  clean: "text-safe",
};

function DataRow({ label, value }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div className="flex items-baseline justify-between gap-3 py-0.5 text-sm">
      <span className="text-muted">{label}</span>
      <span className="break-all text-right font-medium text-text">{String(value)}</span>
    </div>
  );
}

function IntelSection({ title, locked, hasData, children }) {
  if (!locked && !hasData) return null;
  return (
    <div className="rounded-lg border border-border bg-panel p-4">
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">{title}</h3>
      <LockOverlay locked={locked}>{children}</LockOverlay>
    </div>
  );
}

export function ResultPanel({ result }) {
  if (!result || typeof result !== "object") return null;

  const lockedFields = Array.isArray(result.tier_locked) ? result.tier_locked : [];
  const isLocked = (field) => lockedFields.includes(field);

  const whois = result.whois || {};
  const sslCert = result.ssl_cert || {};
  // "redirects" is the ONLY redirect source the UI reads. It is the field
  // strip_premium() nulls when locked, and in production (aggregator.py:695)
  // it is either [] (no hops) or the FULL chain of >=2 URLs. The duplicate
  // "redirect_chain" is never stripped server-side, so consulting it either
  // leaks real hops under a locked blur or (as a fallback) disagrees with
  // the gated field — it is deliberately not read at all.
  const chain = Array.isArray(result.redirects) ? result.redirects : [];

  const confidence = confidenceLabel(result.confidence);
  const target = result.url || result.domain || "Unknown target";
  const showDomainLine = result.domain && result.url && result.domain !== result.url;

  const topFeatures = Array.isArray(result.explainability?.top_features)
    ? result.explainability.top_features.filter((f) => (f.contribution ?? 0) > 0).slice(0, 5)
    : [];
  const sources = Array.isArray(result.sources) ? result.sources : [];
  const hasWhy = Boolean(result.plain_summary) || topFeatures.length > 0;

  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-start justify-between gap-4 rounded-lg border border-border bg-panel p-4">
        <div className="min-w-0 space-y-2">
          <div className="flex flex-wrap items-center gap-3">
            <VerdictBadge verdict={result.verdict} />
            {confidence && (
              <span
                className={`rounded-full bg-panel-2 px-2 py-0.5 text-[11px] font-semibold ${
                  confidence.level === "High"
                    ? "text-text"
                    : confidence.level === "Low"
                      ? "text-muted"
                      : "text-muted"
                }`}
              >
                {confidence.text}
              </span>
            )}
          </div>
          <p className="truncate text-sm font-medium text-text" title={target}>
            {target}
          </p>
          {showDomainLine && <p className="truncate text-xs text-muted">{result.domain}</p>}
        </div>
        <div className="w-full max-w-xs shrink-0 sm:w-56">
          <RiskMeter score={result.risk_score ?? result.score ?? 0} />
        </div>
      </header>

      {hasWhy && (
        <div className="rounded-lg border border-border bg-panel p-4">
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">
            Why this verdict
          </h3>
          {result.plain_summary && <p className="text-sm text-text">{result.plain_summary}</p>}
          {topFeatures.length > 0 && (
            <div className="mt-2">
              <p className="mb-1 text-[11px] font-medium uppercase tracking-wide text-muted">
                Top factors the model weighed
              </p>
              <ul className="space-y-1">
                {topFeatures.map((f, i) => (
                  <li key={`${i}-${f.feature}`} className="flex items-center justify-between gap-3 text-sm">
                    <span className="text-text">{featureLabel(f.feature)}</span>
                    <span className="shrink-0 font-mono text-xs text-muted">
                      +{Math.round((f.contribution ?? 0) * 100)}%
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      <FlagList flags={result.flags} />

      {sources.length > 0 && (
        <div className="rounded-lg border border-border bg-panel p-4">
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">
            Threat intelligence sources
          </h3>
          <ul className="grid grid-cols-1 gap-1.5 sm:grid-cols-2">
            {sources.map((s) => {
              const flagged = s.status === "flag" || s.status === "warn";
              return (
                <li key={s.name} className="flex items-baseline justify-between gap-3 text-sm">
                  <span className="text-text">{s.name}</span>
                  <span className={`text-right text-xs ${SOURCE_STATUS_CLASS[s.status] || "text-muted"}`}>
                    {flagged ? s.detail || "flagged" : s.detail || "clean"}
                  </span>
                </li>
              );
            })}
          </ul>
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <IntelSection
          title="Resolved IP"
          locked={isLocked("resolved_ip")}
          hasData={Boolean(result.resolved_ip)}
        >
          <DataRow label="IP address" value={result.resolved_ip} />
        </IntelSection>

        <IntelSection
          title="Geolocation"
          locked={isLocked("ip_location")}
          hasData={Boolean(result.ip_location || result.ip_country || result.asn || result.hosting)}
        >
          <DataRow label="Location" value={result.ip_location} />
          <DataRow label="Country" value={result.ip_country} />
          <DataRow label="ASN" value={result.asn} />
          <DataRow label="Hosting" value={result.hosting} />
        </IntelSection>

        <IntelSection
          title="WHOIS / domain age"
          locked={isLocked("whois")}
          hasData={Boolean(whois.registrar || whois.age || whois.age_days || whois.created || whois.country)}
        >
          <DataRow label="Registrar" value={whois.registrar} />
          <DataRow label="Age" value={whois.age} />
          <DataRow label="Registered" value={whois.created} />
          <DataRow label="Country" value={whois.country} />
        </IntelSection>

        <IntelSection
          title="SSL certificate"
          locked={isLocked("ssl_cert")}
          hasData={Boolean(sslCert.has_cert || sslCert.issuer || sslCert.subject_cn)}
        >
          <DataRow label="Issuer" value={sslCert.issuer} />
          <DataRow label="Subject" value={sslCert.subject_cn} />
          <DataRow label="Issued" value={sslCert.issued} />
          <DataRow label="Expires" value={sslCert.expires} />
          <DataRow label="Free CA" value={sslCert.is_free_ca ? "Yes" : null} />
        </IntelSection>

        <IntelSection title="Redirect chain" locked={isLocked("redirects")} hasData={chain.length > 0}>
          <ol className="space-y-1 text-xs text-text">
            {chain.map((hop, i) => (
              <li key={`${i}-${hop}`} className="truncate break-all">
                {i + 1}. {hop}
              </li>
            ))}
          </ol>
        </IntelSection>

        <IntelSection
          title="Page preview"
          locked={isLocked("screenshot_url")}
          hasData={Boolean(result.screenshot_url)}
        >
          {result.screenshot_url ? (
            <img
              src={result.screenshot_url}
              alt={result.page_title || "Scanned page preview"}
              className="w-full rounded-md border border-border"
            />
          ) : (
            <div className="flex h-24 items-center justify-center rounded-md bg-panel-2 text-xs text-muted">
              No preview available
            </div>
          )}
        </IntelSection>
      </div>
    </div>
  );
}
