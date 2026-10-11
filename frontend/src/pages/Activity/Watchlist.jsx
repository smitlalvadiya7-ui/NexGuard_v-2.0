import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "../../api.js";
import { useToast } from "../../components/Toast.jsx";
import { VerdictBadge } from "../../components/VerdictBadge.jsx";
import DataTable from "../../components/DataTable.jsx";

/*
 * Watchlist (Premium) — parity target index.html #watchlistPage. Endpoints
 * (backend/main.py:1525-1638, all require_premium): GET/POST /watchlist,
 * DELETE /watchlist/{id}, POST /watchlist/rescan (returns {checked,
 * new_threats, results}; newly-detected threats also raise live alerts).
 * Rows: {id, target, created_at, last_checked, last_verdict, last_score}.
 */
function fmtTime(value) {
  return value ? String(value).replace("T", " ") : "—";
}

export default function Watchlist() {
  const { push } = useToast();
  const [rows, setRows] = useState([]);
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [rescanning, setRescanning] = useState(false);

  const load = useCallback(async () => {
    try {
      const data = await apiFetch("/watchlist");
      setRows(Array.isArray(data) ? data : []);
    } catch (err) {
      push("error", err.message || "Could not load the watchlist.");
    }
  }, [push]);

  useEffect(() => {
    load();
  }, [load]);

  async function add() {
    const trimmed = target.trim();
    if (!trimmed) return;
    setBusy(true);
    try {
      await apiFetch("/watchlist", { method: "POST", body: { target: trimmed } });
      setTarget("");
      push("success", `Added ${trimmed} to the watchlist.`);
      load();
    } catch (err) {
      push("error", err.message || "Could not add the target.");
    } finally {
      setBusy(false);
    }
  }

  async function remove(row) {
    try {
      await apiFetch(`/watchlist/${row.id}`, { method: "DELETE" });
      setRows((prev) => prev.filter((r) => r.id !== row.id));
    } catch (err) {
      push("error", err.message || "Could not remove the target.");
    }
  }

  async function rescanAll() {
    setRescanning(true);
    try {
      const res = await apiFetch("/watchlist/rescan", { method: "POST" });
      const threats = res.new_threats?.length || 0;
      push(
        threats > 0 ? "error" : "success",
        threats > 0
          ? `${threats} newly-detected threat${threats > 1 ? "s" : ""} on your watchlist!`
          : `Re-scanned ${res.checked ?? 0} target${res.checked === 1 ? "" : "s"} — no new threats.`
      );
      load();
    } catch (err) {
      push("error", err.message || "Watchlist re-scan failed.");
    } finally {
      setRescanning(false);
    }
  }

  const columns = [
    { key: "target", label: "Target" },
    {
      key: "last_verdict",
      label: "Last Verdict",
      render: (r) =>
        r.last_verdict ? <VerdictBadge verdict={r.last_verdict} /> : <span className="text-xs text-muted">not checked</span>,
    },
    { key: "last_score", label: "Risk", render: (r) => r.last_score ?? "—" },
    { key: "last_checked", label: "Last Checked", render: (r) => <span className="text-xs text-muted">{fmtTime(r.last_checked)}</span> },
    { key: "created_at", label: "Added", render: (r) => <span className="text-xs text-muted">{fmtTime(r.created_at)}</span> },
    {
      key: "actions",
      label: "",
      sortable: false,
      render: (r) => (
        <button
          type="button"
          onClick={() => remove(r)}
          className="rounded-md border border-border bg-panel-2 px-2 py-1 text-xs font-medium text-danger transition-opacity hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          ✕ Remove
        </button>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">
        Monitor domains for newly-detected threats. Re-scan on demand — new threats raise live
        alerts.
      </p>

      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-panel p-3">
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && add()}
          placeholder="example-domain.com"
          aria-label="Domain or URL to watch"
          className="min-w-48 flex-1 rounded-lg border border-border bg-bg px-3 py-1.5 text-sm text-text outline-none focus-visible:ring-2 focus-visible:ring-accent"
        />
        <button
          type="button"
          onClick={add}
          disabled={busy || !target.trim()}
          className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-bg transition-opacity hover:opacity-90 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          Add to Watchlist
        </button>
        <button
          type="button"
          onClick={rescanAll}
          disabled={rescanning || rows.length === 0}
          className="rounded-lg bg-warn px-3 py-1.5 text-sm font-medium text-bg transition-opacity hover:opacity-90 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {rescanning ? "Re-scanning…" : "🔄 Re-scan All"}
        </button>
      </div>

      {rows.length === 0 ? (
        <p className="py-10 text-center text-sm text-muted">
          Nothing watched yet. Add a domain above to start monitoring it.
        </p>
      ) : (
        <DataTable columns={columns} rows={rows} rowKey={(r) => r.id} />
      )}
    </div>
  );
}
