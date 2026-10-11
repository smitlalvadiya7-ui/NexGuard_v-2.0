/*
 * Compact verdict pill shared by every scan panel (URL/QR/email/batch/etc.).
 * Tinted-background + solid-colored-text, per the design-token author's note:
 * dark-mode verdict colors are tuned bright for text-on-dark, so a solid
 * fill + white text would wash out — a low-opacity tint keeps it readable
 * (and matching) in both themes.
 */

const VERDICT_STYLES = {
  SAFE: "bg-safe/15 text-safe",
  SUSPICIOUS: "bg-warn/15 text-warn",
  MALICIOUS: "bg-danger/15 text-danger",
  // "We could not check this", which is NOT the same as safe. Deliberately
  // neutral rather than green: a 200-URL batch once reported 125 known-malicious
  // domains as SAFE 0% because every reputation source had been rate-limited
  // away, and the green badge is what made that dangerous rather than merely
  // wrong. Never render an unverified URL in the same colour as a cleared one.
  UNKNOWN: "bg-muted/15 text-muted",
};

// Anything unrecognized (backend's own "ERROR" verdict, a scan still in
// flight, or a shape we've never seen) collapses to the same neutral badge
// rather than guessing — never silently mislabel an unknown state as safe.
const FALLBACK_CLASS = "bg-muted/15 text-muted";

export function VerdictBadge({ verdict }) {
  const key = typeof verdict === "string" ? verdict.toUpperCase() : "";
  const className = VERDICT_STYLES[key];
  const label = className ? key : "ERROR";

  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold uppercase tracking-wide ${
        className || FALLBACK_CLASS
      }`}
    >
      {label}
    </span>
  );
}
