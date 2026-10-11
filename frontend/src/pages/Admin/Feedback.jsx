import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "../../api.js";
import { useToast } from "../../components/Toast.jsx";
import { VerdictBadge } from "../../components/VerdictBadge.jsx";
import DataTable from "../../components/DataTable.jsx";

/*
 * Verdict-feedback review. GET /admin/feedback?status= (backend/main.py:892,
 * rows carry reporter_email); POST /admin/feedback/{id}/review with
 * {decision: "accepted" | "rejected"} (912). Accepted rows feed the
 * active-learning retrain set, so rejecting gets an inline confirm.
 */
const STATUSES = ["pending", "accepted", "rejected", "all"];

export default function Feedback() {
  const { push } = useToast();
  const [rows, setRows] = useState([]);
  const [status, setStatus] = useState("pending");
  const [confirmingId, setConfirmingId] = useState(null);

  const load = useCallback(
    async (which = status) => {
      try {
        const data = await apiFetch(`/admin/feedback?status=${which}`);
        setRows(Array.isArray(data) ? data : []);
      } catch (err) {
        push("error", err.message || "Could not load feedback.");
      }
    },
    [push, status]
  );

  useEffect(() => {
    load();
  }, [load]);

  async function review(row, decision) {
    try {
      await apiFetch(`/admin/feedback/${row.id}/review`, {
        method: "POST",
        body: { decision },
      });
      push(decision === "accepted" ? "success" : "info", `Feedback #${row.id} ${decision}.`);
      setConfirmingId(null);
      load();
    } catch (err) {
      push("error", err.message || "Review failed.");
    }
  }

  function smallBtn(extra = "") {
    return `rounded-md border border-border bg-panel-2 px-2 py-1 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${extra}`;
  }

  const columns = [
    { key: "id", label: "ID" },
    { key: "url", label: "URL" },
    {
      key: "predicted_verdict",
      label: "Predicted",
      render: (r) => (
        <span className="flex items-center gap-1.5">
          <VerdictBadge verdict={r.predicted_verdict} />
          <span className="text-xs text-muted">{r.predicted_score}</span>
        </span>
      ),
    },
    {
      key: "user_label",
      label: "User says",
      render: (r) => (
        <span className={`text-xs font-semibold uppercase ${r.user_label === "malicious" ? "text-danger" : "text-safe"}`}>
          {r.user_label}
        </span>
      ),
    },
    { key: "reporter_email", label: "Reporter" },
    {
      key: "created_at",
      label: "Reported",
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
            <button type="button" onClick={() => review(r, "accepted")} className={smallBtn("text-safe")}>
              ✓ Accept
            </button>
            {confirming ? (
              <>
                <button
                  type="button"
                  onClick={() => review(r, "rejected")}
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
        <label htmlFor="feedback-status" className="text-xs text-muted">
          Status
        </label>
        <select
          id="feedback-status"
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
        <p className="py-8 text-center text-sm text-muted">No {status === "all" ? "" : status + " "}feedback.</p>
      ) : (
        <DataTable columns={columns} rows={rows} rowKey={(r) => r.id} />
      )}
    </div>
  );
}
