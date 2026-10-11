import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "../../api.js";
import { useToast } from "../../components/Toast.jsx";

/*
 * Admin Support inbox (WORK_PLAN Task 12). GET /admin/support/tickets?status=
 * lists contact tickets; POST /admin/support/tickets/{id}/reply sends a reply
 * and moves status open -> answered -> resolved. The reply shows up for the
 * user on their Support page.
 */
const STATUSES = ["open", "answered", "resolved", "all"];

const STATUS_CLASS = {
  open: "text-warn",
  answered: "text-accent",
  resolved: "text-safe",
};

const CATEGORY_LABEL = {
  question: "Question",
  problem: "Problem",
  wrong_info: "Wrong info",
  other: "Other",
};

export default function AdminSupport() {
  const { push } = useToast();
  const [rows, setRows] = useState([]);
  const [status, setStatus] = useState("open");
  const [drafts, setDrafts] = useState({});

  const load = useCallback(
    async (which = status) => {
      try {
        const data = await apiFetch(`/admin/support/tickets?status=${which}`);
        setRows(Array.isArray(data) ? data : []);
      } catch (err) {
        push("error", err.message || "Could not load tickets.");
      }
    },
    [push, status]
  );

  useEffect(() => {
    load();
  }, [load]);

  async function reply(row, newStatus) {
    const text = drafts[row.id] ?? row.admin_reply ?? "";
    try {
      await apiFetch(`/admin/support/tickets/${row.id}/reply`, {
        method: "POST",
        body: { reply: text, status: newStatus },
      });
      push("success", `Ticket #${row.id} → ${newStatus}.`);
      setDrafts((d) => ({ ...d, [row.id]: undefined }));
      load();
    } catch (err) {
      push("error", err.message || "Reply failed.");
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <label htmlFor="ticket-status" className="text-xs text-muted">
          Status
        </label>
        <select
          id="ticket-status"
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
        <p className="py-8 text-center text-sm text-muted">
          No {status === "all" ? "" : status + " "}tickets.
        </p>
      ) : (
        <ul className="space-y-3">
          {rows.map((t) => (
            <li key={t.id} className="space-y-2 rounded-lg border border-border bg-panel p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="min-w-0">
                  <span className="text-sm font-medium text-text">
                    #{t.id} · {t.subject || "(no subject)"}
                  </span>
                  <span className="ml-2 rounded-md bg-panel-2 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted">
                    {CATEGORY_LABEL[t.category] || t.category}
                  </span>
                </div>
                <span className={`text-xs font-semibold uppercase ${STATUS_CLASS[t.status] || "text-muted"}`}>
                  {t.status}
                </span>
              </div>

              <p className="text-xs text-muted">
                From {t.email} · {t.reporter_account} ·{" "}
                {String(t.created_at || "").replace("T", " ")}
              </p>

              <p className="whitespace-pre-wrap rounded-md bg-panel-2/50 p-2 text-sm text-text">
                {t.message}
              </p>

              {t.admin_reply && (
                <div className="rounded-md border-l-2 border-accent bg-panel-2/40 px-3 py-2">
                  <p className="text-[10px] font-semibold uppercase tracking-wide text-accent">
                    Your reply
                  </p>
                  <p className="text-sm text-text">{t.admin_reply}</p>
                </div>
              )}

              <textarea
                aria-label={`Reply to ticket ${t.id}`}
                rows={3}
                value={drafts[t.id] ?? t.admin_reply ?? ""}
                onChange={(e) => setDrafts((d) => ({ ...d, [t.id]: e.target.value }))}
                placeholder="Write a reply…"
                className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text outline-none focus-visible:ring-2 focus-visible:ring-accent"
              />

              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => reply(t, "answered")}
                  className="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-bg transition-opacity hover:opacity-90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  Send reply
                </button>
                <button
                  type="button"
                  onClick={() => reply(t, "resolved")}
                  className="rounded-md border border-border bg-panel-2 px-3 py-1.5 text-xs font-medium text-safe transition-colors hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  Reply &amp; resolve
                </button>
                {t.status !== "open" && (
                  <button
                    type="button"
                    onClick={() => reply(t, "open")}
                    className="rounded-md border border-border bg-panel-2 px-3 py-1.5 text-xs font-medium text-muted transition-colors hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  >
                    Reopen
                  </button>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
