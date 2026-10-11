import { useEffect, useState } from "react";
import { apiFetch } from "../../api.js";
import StatTile from "../../components/StatTile.jsx";

/*
 * Platform-wide totals. GET /admin/stats (backend/main.py:1031) →
 * {total_users, users_by_role, users_by_tier, users_by_status, total_scans,
 * threats_detected, pending_requests}.
 */
function BreakdownRow({ title, counts }) {
  const entries = Object.entries(counts || {});
  if (entries.length === 0) return null;
  return (
    <div className="rounded-lg border border-border bg-panel p-4">
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">{title}</h3>
      <div className="flex flex-wrap gap-2">
        {entries.map(([name, count]) => (
          <span key={name} className="rounded-md bg-panel-2 px-2.5 py-1 text-xs text-text">
            <span className="capitalize">{name}</span>{" "}
            <span className="font-semibold tabular-nums">{count}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

export default function Stats() {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    let alive = true;
    apiFetch("/admin/stats")
      .then((data) => alive && setStats(data))
      .catch(() => alive && setStats(null));
    return () => {
      alive = false;
    };
  }, []);

  if (!stats) {
    return <p className="py-8 text-center text-sm text-muted">Loading platform stats…</p>;
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile label="Total users" value={stats.total_users} />
        <StatTile label="Total scans" value={stats.total_scans} />
        <StatTile label="Threats detected" value={stats.threats_detected} />
        <StatTile label="Pending requests" value={stats.pending_requests} />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <BreakdownRow title="Users by role" counts={stats.users_by_role} />
        <BreakdownRow title="Users by tier" counts={stats.users_by_tier} />
        <BreakdownRow title="Users by status" counts={stats.users_by_status} />
      </div>
    </div>
  );
}
