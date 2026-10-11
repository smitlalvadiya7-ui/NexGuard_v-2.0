import { useCallback, useEffect, useState } from "react";
import { apiFetch, API_BASE } from "../../api.js";
import { useAuth } from "../../auth/AuthContext.jsx";
import { useToast } from "../../components/Toast.jsx";
import DataTable from "../../components/DataTable.jsx";

/*
 * Developer API keys — parity target index.html #apiKeysPage. Endpoints
 * (backend/main.py): POST /api-keys (1698, response carries the raw `key`
 * ONCE — only its hash is stored), GET /api-keys (1726), POST
 * /api-keys/{id}/revoke (1742). Rows: {id, label, prefix, tier, active,
 * created_at, last_used, request_count}.
 */
export default function ApiKeys() {
  const { user } = useAuth();
  const { push } = useToast();
  const [rows, setRows] = useState([]);
  const [label, setLabel] = useState("");
  const [revealed, setRevealed] = useState(null); // {key, label} — once per creation
  const [busy, setBusy] = useState(false);

  const loggedIn = user && user !== "anonymous";

  const load = useCallback(async () => {
    try {
      const data = await apiFetch("/api-keys");
      setRows(Array.isArray(data) ? data : []);
    } catch (err) {
      push("error", err.message || "Could not load API keys.");
    }
  }, [push]);

  useEffect(() => {
    if (loggedIn) load();
  }, [loggedIn, load]);

  async function createKey() {
    setBusy(true);
    try {
      const created = await apiFetch("/api-keys", {
        method: "POST",
        body: { label: label.trim() },
      });
      setRevealed({ key: created.key, label: created.label });
      setLabel("");
      load();
    } catch (err) {
      push("error", err.message || "Could not create the key.");
    } finally {
      setBusy(false);
    }
  }

  async function copyKey() {
    try {
      await navigator.clipboard.writeText(revealed.key);
      push("success", "API key copied to the clipboard.");
    } catch {
      push("error", "Copy failed — select and copy the key manually.");
    }
  }

  async function revoke(row) {
    try {
      await apiFetch(`/api-keys/${row.id}/revoke`, { method: "POST" });
      push("success", `Key "${row.label || row.prefix}" revoked.`);
      load();
    } catch (err) {
      push("error", err.message || "Could not revoke the key.");
    }
  }

  const columns = [
    { key: "label", label: "Label", render: (r) => r.label || "—" },
    {
      key: "prefix",
      label: "Key",
      render: (r) => <code className="font-mono text-xs">{r.prefix}…</code>,
    },
    { key: "tier", label: "Tier" },
    {
      key: "active",
      label: "Status",
      render: (r) =>
        r.active ? (
          <span className="text-xs font-medium text-safe">active</span>
        ) : (
          <span className="text-xs font-medium text-muted">revoked</span>
        ),
    },
    { key: "request_count", label: "Requests" },
    {
      key: "last_used",
      label: "Last Used",
      render: (r) => (
        <span className="text-xs text-muted">
          {r.last_used ? String(r.last_used).replace("T", " ") : "never"}
        </span>
      ),
    },
    {
      key: "actions",
      label: "",
      sortable: false,
      render: (r) =>
        r.active ? (
          <button
            type="button"
            onClick={() => revoke(r)}
            className="rounded-md border border-border bg-panel-2 px-2 py-1 text-xs font-medium text-danger transition-opacity hover:opacity-80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            Revoke
          </button>
        ) : null,
    },
  ];

  if (!loggedIn) {
    return (
      <div className="rounded-lg border border-border bg-panel p-4 text-sm text-muted">
        Log in to create developer API keys.
      </div>
    );
  }

  const curlExample = `curl -X POST ${API_BASE || "https://your-server"}/api/v1/scan \\
  -H "X-API-Key: ngk_..." \\
  -H "Content-Type: application/json" \\
  -d '{"url": "https://example.com"}'`;

  return (
    <div className="space-y-4">
      <div className="space-y-3 rounded-lg border border-border bg-panel p-4">
        <h2 className="text-xs font-semibold uppercase tracking-wide text-muted">Create a key</h2>
        <div className="flex flex-wrap gap-2">
          <input
            type="text"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !busy && createKey()}
            placeholder="Label (e.g. my-bot, production)"
            aria-label="API key label"
            className="min-w-56 flex-1 rounded-lg border border-border bg-bg px-3 py-1.5 text-sm text-text outline-none focus-visible:ring-2 focus-visible:ring-accent"
          />
          <button
            type="button"
            onClick={createKey}
            disabled={busy}
            className="rounded-lg bg-accent px-4 py-1.5 text-sm font-medium text-bg transition-opacity hover:opacity-90 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            {busy ? "Generating…" : "Generate Key"}
          </button>
        </div>

        {revealed && (
          <div className="space-y-2 rounded-lg border border-warn/40 bg-warn/5 p-3">
            <p className="text-xs font-semibold text-warn">
              Copy this key now — it won't be shown again.
            </p>
            <div className="flex flex-wrap items-center gap-2">
              <code className="break-all rounded-md bg-panel-2 px-2 py-1 font-mono text-xs text-text">
                {revealed.key}
              </code>
              <button
                type="button"
                onClick={copyKey}
                className="rounded-md border border-border bg-panel-2 px-2 py-1 text-xs font-medium text-text transition-colors hover:text-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                📋 Copy
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="rounded-lg border border-border bg-panel p-4">
        <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted">Your keys</h2>
        {rows.length === 0 ? (
          <p className="py-6 text-center text-sm text-muted">No API keys yet.</p>
        ) : (
          <DataTable columns={columns} rows={rows} rowKey={(r) => r.id} />
        )}
      </div>

      <div className="space-y-2 rounded-lg border border-border bg-panel p-4 text-sm text-muted">
        <h2 className="text-xs font-semibold uppercase tracking-wide text-muted">Usage</h2>
        <p>
          Send a <b>POST</b> to <code className="font-mono text-xs">/api/v1/scan</code> with your
          key in the <code className="font-mono text-xs">X-API-Key</code> header. Free keys allow
          100 requests/day (10/min) with tier-limited fields; premium keys allow 10,000/day
          (60/min) with full forensic detail.
        </p>
        <pre className="overflow-x-auto rounded-lg bg-panel-2 p-3 font-mono text-xs leading-relaxed text-text">
          {curlExample}
        </pre>
      </div>
    </div>
  );
}
