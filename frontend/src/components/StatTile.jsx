/*
 * Hero-number stat tile (dashboard + model page). Locale formatting is pinned
 * to en-US so tests and UI agree regardless of the host locale; null/undefined
 * values render an em dash instead of a fake zero.
 *
 * Task 7 polish: `loading` shows a skeleton instead of an empty flash; `trend`
 * ({dir: "up"|"down"|"flat", label}) shows a small ▲▼ vs a previous period.
 */
const TREND = {
  up: { arrow: "▲", cls: "text-safe" },
  down: { arrow: "▼", cls: "text-danger" },
  flat: { arrow: "▪", cls: "text-muted" },
};

export default function StatTile({ label, value, suffix, loading = false, trend = null }) {
  const display =
    value === null || value === undefined
      ? "—"
      : typeof value === "number"
        ? Math.round(value).toLocaleString("en-US")
        : String(value);

  const t = trend && TREND[trend.dir];

  return (
    <div className="rounded-lg border border-border bg-panel p-4">
      <p className="text-xs font-semibold uppercase tracking-wide text-muted">{label}</p>
      {loading ? (
        <div className="mt-2 h-7 w-20 animate-pulse rounded bg-panel-2" aria-hidden="true" />
      ) : (
        <>
          <p className="mt-1 flex items-baseline gap-1">
            <span className="text-2xl font-semibold tabular-nums text-text">{display}</span>
            {suffix && display !== "—" && (
              <span className="text-sm font-medium text-muted">{suffix}</span>
            )}
          </p>
          {t && (
            <p className={`mt-1 flex items-center gap-1 text-xs ${t.cls}`}>
              <span aria-hidden="true">{t.arrow}</span>
              <span className="text-muted">{trend.label}</span>
            </p>
          )}
        </>
      )}
    </div>
  );
}
