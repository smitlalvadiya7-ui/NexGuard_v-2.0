/*
 * 0-100 horizontal risk bar. Color follows the same thresholds the backend
 * uses for the verdict itself (aggregator.py: >=70 MALICIOUS | 40-69
 * SUSPICIOUS | <40 SAFE), so the bar always agrees with the badge next to it
 * even if a caller only has the score (no verdict string) to hand.
 */

function riskClass(score) {
  if (score >= 70) return "bg-danger";
  if (score >= 40) return "bg-warn";
  return "bg-safe";
}

function riskTextClass(score) {
  if (score >= 70) return "text-danger";
  if (score >= 40) return "text-warn";
  return "text-safe";
}

export function RiskMeter({ score }) {
  const n = Math.max(0, Math.min(100, Math.round(Number(score) || 0)));
  const fill = riskClass(n);

  return (
    <div className="flex items-center gap-3">
      <div
        role="progressbar"
        aria-valuenow={n}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label="Risk score"
        className="h-2 min-w-24 flex-1 overflow-hidden rounded-full bg-panel-2"
      >
        <div className={`h-full rounded-full transition-[width] ${fill}`} style={{ width: `${n}%` }} />
      </div>
      <span className={`text-sm font-semibold tabular-nums ${riskTextClass(n)}`}>{n}</span>
    </div>
  );
}
