import { Link } from "react-router-dom";

/*
 * Shared "you've hit today's free scan cap" card. Every scan panel renders
 * this INSTEAD OF a result when apiFetch rejects with FreeLimitError; `info`
 * is that error's `.info` (the parsed 429 JSON body).
 *
 * Verified against backend/main.py `_free_limit_response()` (~line 323) and
 * `enforce_scan_quota()` (~line 333): the 429 body is only ever
 * `{error: "free_limit", message: "..."}` — there is no numeric used/limit
 * pair on the wire today (the old index.html UI doesn't get one either; its
 * usage meter is a separate authenticated-only widget fed by /auth/me's
 * `daily_scan_count`, not the 429 body). So the meter below reads `info.used`
 * / `info.limit` when a future backend revision adds them, and otherwise
 * paints full/exhausted — which is accurate either way, since reaching this
 * card at all means the daily quota is spent.
 */
export default function FreeLimitCard({ info }) {
  const used = typeof info?.used === "number" ? info.used : null;
  const limit = typeof info?.limit === "number" ? info.limit : null;
  const hasCounts = used !== null && limit !== null && limit > 0;

  const pct = hasCounts ? Math.min(100, Math.round((used / limit) * 100)) : 100;
  const meterLabel = hasCounts
    ? `${used} / ${limit} free scans used today`
    : "Free daily limit reached";

  const message =
    (info && info.message) ||
    "Daily free scan limit reached. Upgrade to Premium for unlimited scans.";

  return (
    <div className="space-y-4 rounded-lg border border-border bg-panel p-6 text-center">
      <p className="text-base font-semibold text-text">Daily free limit reached</p>

      <div className="mx-auto max-w-xs space-y-1.5">
        <div
          role="progressbar"
          aria-valuenow={pct}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label="Daily free scan usage"
          className="h-2 w-full overflow-hidden rounded-full bg-panel-2"
        >
          <div className="h-full rounded-full bg-danger transition-[width]" style={{ width: `${pct}%` }} />
        </div>
        <p className="text-xs text-muted">{meterLabel}</p>
      </div>

      <p className="mx-auto max-w-sm text-sm text-muted">{message}</p>

      <Link
        to="/settings"
        className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full bg-accent px-4 py-2 text-sm font-semibold text-bg shadow-sm transition-opacity hover:opacity-90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        ⭐ Upgrade to Premium
      </Link>
    </div>
  );
}
