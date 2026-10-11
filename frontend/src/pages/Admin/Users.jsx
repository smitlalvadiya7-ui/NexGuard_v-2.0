import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "../../api.js";
import { useAuth } from "../../auth/AuthContext.jsx";
import { useToast } from "../../components/Toast.jsx";
import DataTable from "../../components/DataTable.jsx";

/*
 * User management. GET /admin/users (backend/main.py:1012); actions POST
 * /admin/users/{id}/tier (960, admin+), /role (939, SUPERADMIN only — the
 * button set is hidden for plain admins to match), /suspend (978) with an
 * inline confirm step (never window.confirm), /activate (996). Superadmin
 * rows get no destructive controls — the backend 403s them anyway.
 */
export default function Users() {
  const { user: viewer } = useAuth();
  const { push } = useToast();
  const [rows, setRows] = useState([]);
  const [confirmingId, setConfirmingId] = useState(null);

  const isSuperadmin = viewer && viewer !== "anonymous" && viewer.role === "superadmin";

  const load = useCallback(async () => {
    try {
      const data = await apiFetch("/admin/users");
      setRows(Array.isArray(data) ? data : []);
    } catch (err) {
      push("error", err.message || "Could not load users.");
    }
  }, [push]);

  useEffect(() => {
    load();
  }, [load]);

  async function action(path, body, okMessage) {
    try {
      await apiFetch(path, { method: "POST", body });
      push("success", okMessage);
      setConfirmingId(null);
      load();
    } catch (err) {
      push("error", err.message || "Action failed.");
    }
  }

  function smallBtn(extra = "") {
    return `rounded-md border border-border bg-panel-2 px-2 py-1 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${extra}`;
  }

  const columns = [
    { key: "id", label: "ID" },
    { key: "email", label: "Email" },
    { key: "role", label: "Role" },
    { key: "tier", label: "Tier" },
    {
      key: "status",
      label: "Status",
      render: (r) => (
        <span className={`text-xs font-medium ${r.status === "active" ? "text-safe" : "text-danger"}`}>
          {r.status}
        </span>
      ),
    },
    { key: "total_scans", label: "Scans" },
    {
      key: "actions",
      label: "Actions",
      sortable: false,
      render: (r) => {
        if (r.role === "superadmin") {
          return <span className="text-xs text-muted">—</span>;
        }
        const confirming = confirmingId === r.id;
        return (
          <span className="flex flex-wrap gap-1.5">
            <button
              type="button"
              onClick={() =>
                action(
                  `/admin/users/${r.id}/tier`,
                  { tier: r.tier === "premium" ? "free" : "premium" },
                  `${r.email} is now ${r.tier === "premium" ? "free" : "premium"}.`
                )
              }
              className={smallBtn("text-text hover:text-accent")}
            >
              {r.tier === "premium" ? "Make free" : "Make premium"}
            </button>

            {isSuperadmin && (
              <button
                type="button"
                onClick={() =>
                  action(
                    `/admin/users/${r.id}/role`,
                    { role: r.role === "admin" ? "user" : "admin" },
                    `${r.email} is now ${r.role === "admin" ? "a user" : "an admin"}.`
                  )
                }
                className={smallBtn("text-text hover:text-accent")}
              >
                {r.role === "admin" ? "Demote to user" : "Make admin"}
              </button>
            )}

            {r.status === "active" ? (
              confirming ? (
                <>
                  <button
                    type="button"
                    onClick={() =>
                      action(`/admin/users/${r.id}/suspend`, undefined, `${r.email} suspended.`)
                    }
                    className={smallBtn("border-danger/40 text-danger")}
                  >
                    Confirm suspend
                  </button>
                  <button
                    type="button"
                    onClick={() => setConfirmingId(null)}
                    className={smallBtn("text-muted")}
                  >
                    Cancel
                  </button>
                </>
              ) : (
                <button
                  type="button"
                  onClick={() => setConfirmingId(r.id)}
                  className={smallBtn("text-danger")}
                >
                  Suspend
                </button>
              )
            ) : (
              <button
                type="button"
                onClick={() =>
                  action(`/admin/users/${r.id}/activate`, undefined, `${r.email} re-activated.`)
                }
                className={smallBtn("text-safe")}
              >
                Activate
              </button>
            )}
          </span>
        );
      },
    },
  ];

  return (
    <div className="space-y-3">
      <p className="text-sm text-muted">
        Roles change via superadmin only; suspending blocks logins immediately.
      </p>
      <DataTable columns={columns} rows={rows} rowKey={(r) => r.id} />
    </div>
  );
}
