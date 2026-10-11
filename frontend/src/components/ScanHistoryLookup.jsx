import { useEffect, useState } from "react";
import { apiFetch } from "../api.js";
import { VerdictBadge } from "./VerdictBadge.jsx";

/*
 * Prior-scan history for the just-scanned target (WORK_PLAN Task 6).
 * Fetches GET /history/lookup?target= and shows how many times this
 * domain was seen before and its recent verdicts. Renders nothing until
 * there is real history (the current scan itself counts, so >1 means a
 * genuine repeat). Silent on error — it is a bonus panel, never blocking.
 */
export default function ScanHistoryLookup({ target }) {
  const [data, setData] = useState(null);

  useEffect(() => {
    let alive = true;
    if (!target) {
      setData(null);
      return undefined;
    }
    (async () => {
      try {
        const res = await apiFetch(`/history/lookup?target=${encodeURIComponent(target)}`);
        if (alive) setData(res);
      } catch {
        if (alive) setData(null);
      }
    })();
    return () => {
      alive = false;
    };
  }, [target]);

  // Only worth showing once there is more than the scan we just did.
  if (!data || (data.count ?? 0) <= 1) return null;

  const { count, verdicts = {}, recent = [], domain } = data;
  const priorThreats = (verdicts.MALICIOUS || 0) + (verdicts.SUSPICIOUS || 0);

  return (
    <div className="rounded-lg border border-border bg-panel p-4">
      <div className="mb-2 flex items-baseline justify-between gap-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">Scan history</h3>
        <span className="text-xs text-muted">{domain}</span>
      </div>
      <p className="text-sm text-text">
        Scanned <span className="font-semibold">{count}</span> time{count === 1 ? "" : "s"} before
        {priorThreats > 0 && (
          <>
            {" "}
            — flagged <span className="font-semibold text-danger">{priorThreats}</span> time
            {priorThreats === 1 ? "" : "s"}
          </>
        )}
        .
      </p>
      {recent.length > 0 && (
        <ul className="mt-2 divide-y divide-border">
          {recent.map((r, i) => (
            <li key={`${i}-${r.time}`} className="flex items-center justify-between gap-3 py-1.5 text-xs">
              <span className="min-w-0 flex-1 truncate text-muted">
                {r.module} · {String(r.time || "").replace("T", " ")}
              </span>
              <VerdictBadge verdict={r.verdict} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
