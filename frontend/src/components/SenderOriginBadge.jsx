/*
 * Sender origin verdict (WORK_PLAN Task 9) — renders the backend's
 * result.sender_origin {status, claimed_brand, sender_domain, detail} plus
 * the genuine_ratio. Statuses: verified / mismatch / spoof_suspected /
 * authenticated / unknown (unknown renders only the ratio chip, no noise).
 */
const STATUS_STYLES = {
  verified: {
    icon: "✔",
    label: "Verified sender",
    box: "border-safe/50 bg-safe/10",
    text: "text-safe",
  },
  mismatch: {
    icon: "✘",
    label: "Sender impersonation",
    box: "border-danger/50 bg-danger/10",
    text: "text-danger",
  },
  spoof_suspected: {
    icon: "✘",
    label: "Possible spoofed sender",
    box: "border-danger/50 bg-danger/10",
    text: "text-danger",
  },
  authenticated: {
    icon: "✓",
    label: "Sender authenticated",
    box: "border-border bg-panel-2",
    text: "text-muted",
  },
};

function ratioClass(ratio) {
  if (ratio >= 70) return "text-safe";
  if (ratio >= 40) return "text-warn";
  return "text-danger";
}

export default function SenderOriginBadge({ origin, ratio }) {
  const hasRatio = typeof ratio === "number" && !Number.isNaN(ratio);
  const style = origin?.status ? STATUS_STYLES[origin.status] : null;
  if (!style && !hasRatio) return null;

  if (!style) {
    return (
      <p className={`text-xs font-semibold ${ratioClass(ratio)}`}>{ratio}% genuine</p>
    );
  }

  return (
    <div className={`space-y-1 rounded-lg border p-3 ${style.box}`}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <p className={`text-sm font-semibold ${style.text}`}>
          <span aria-hidden="true">{style.icon}</span> {style.label}
        </p>
        {hasRatio && (
          <span className={`text-xs font-semibold ${ratioClass(ratio)}`}>
            {ratio}% genuine
          </span>
        )}
      </div>
      {origin.detail && <p className="text-xs text-muted">{origin.detail}</p>}
    </div>
  );
}
