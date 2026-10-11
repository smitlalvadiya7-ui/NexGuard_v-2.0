import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "../../api.js";
import { useToast } from "../../components/Toast.jsx";
import DataTable from "../../components/DataTable.jsx";

/*
 * Approval requests. GET /admin/requests?status= (backend/main.py:780,
 * default pending, rows carry requester_email); decisions POST
 * /requests/{id}/approve | /reject (834/840). Reject uses an inline confirm
 * step per the plan (destructive), approve is single-click.
 */
const STATUSES = ["pending", "approved", "rejected", "all"];

export default function Requests() {
  const { push } = useToast();
  const [rows, setRows] = useState([]);
  const [status, setStatus] = useState("pending");
  const [confirmingId, setConfirmingId] = useState(null);

  const load = useCallback(
    async (which = status) => {
      try {
        const data = await apiFetch(`/admin/requests?status=${which}`);
        setRows(Array.isArray(data) ? data : []);
      } catch (err) {
        push("error", err.message || "Could not load requests.");
      }
    },
    [push, status]
  );

  useEffect(() => {
    load();
  }, [load]);

  async function decide(row, decision) {
    try {
      await apiFetch(`/requests/${row.id}/${decision}`, { method: "POST", body: {} });
      push(decision === "approve" ? "success" : "info", `Request #${row.id} ${decision}d.`);
      setConfirmingId(null);
      load();
    } catch (err) {
      push("error", err.message || "Decision failed.");
    }
  }

  function smallBtn(extra = "") {
    return `rounded-md border border-border bg-panel-2 px-2 py-1 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${extra}`;
  }

  const columns = [
    { key: "id", label: "ID" },
    { key: "type", label: "Type" },
    { key: "requester_email", label: "Requester", render: (r) => r.requester_email || `user #${r.requester_user_id}` },
    { key: "note", label: "Note", render: (r) => r.note || "—" },
    {
      key: "created_at",
      label: "Created",
      render: (r) => <span className="text-xs text-muted">{String(r.created_at || "").replace("T", " ")}</span>,
    },
    { key: "status", label: "Status" },
    {
      key: "actions",
      label: "Actions",
      sortable: false,
      render: (r) => {
        if (r.status !== "pending") return <span className="text-xs text-muted">—</span>;
        const confirming = confirmingId === r.id;
        return (
          <span className="flex flex-wrap gap-1.5">
            <button
              type="button"
              onClick={() => decide(r, "approve")}
              className={smallBtn("text-safe")}
            >
              ✓ Approve
            </button>
            {confirming ? (
              <>
                <button
                  type="button"
                  onClick={() => decide(r, "reject")}
                  className={smallBtn("border-danger/40 text-danger")}
                >
                  Confirm reject
                </button>
                <button type="button" onClick={() => setConfirmingId(null)} className={smallBtn("text-muted")}>
                  Cancel
                </button>
              </>
            ) : (
              <button type="button" onClick={() => setConfirmingId(r.id)} className={smallBtn("text-danger")}>
                ✕ Reject
              </button>
            )}
          </span>
        );
      },
    },
  ];

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <label htmlFor="request-status" className="text-xs text-muted">
          Status
        </label>
        <select
          id="request-status"
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          className="rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-text outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>

      {rows.length === 0 ? (
        <p className="py-8 text-center text-sm text-muted">No {status === "all" ? "" : status + " "}requests.</p>
      ) : (
        <DataTable columns={columns} rows={rows} rowKey={(r) => r.id} />
      )}
    </div>
  );
}
