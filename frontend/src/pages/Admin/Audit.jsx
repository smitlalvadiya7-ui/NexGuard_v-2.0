import { useEffect, useState } from "react";
import { apiFetch } from "../../api.js";
import { useToast } from "../../components/Toast.jsx";
import DataTable from "../../components/DataTable.jsx";

/*
 * Audit trail of privileged actions. GET /superadmin/audit (backend/
 * main.py:1064, superadmin only — the tab itself is hidden for other roles
 * in Admin/index.jsx). Rows: {id, action, actor_user_id, actor_email,
 * target_user_id, detail, created_at}.
 */
const COLUMNS = [
  {
    key: "created_at",
    label: "Time",
    render: (r) => <span className="text-xs text-muted">{String(r.created_at || "").replace("T", " ")}</span>,
  },
  { key: "actor_email", label: "Actor", render: (r) => r.actor_email || `user #${r.actor_user_id}` },
  { key: "action", label: "Action" },
  { key: "target_user_id", label: "Target user", render: (r) => r.target_user_id ?? "—" },
  { key: "detail", label: "Detail", render: (r) => r.detail || "—" },
];

export default function Audit() {
  const { push } = useToast();
  const [rows, setRows] = useState([]);

  useEffect(() => {
    let alive = true;
    apiFetch("/superadmin/audit?limit=200")
      .then((data) => alive && setRows(Array.isArray(data) ? data : []))
      .catch((err) => alive && push("error", err.message || "Could not load the audit log."));
    return () => {
      alive = false;
    };
  }, [push]);

  return rows.length === 0 ? (
    <p className="py-8 text-center text-sm text-muted">No audit entries yet.</p>
  ) : (
    <DataTable columns={COLUMNS} rows={rows} rowKey={(r) => r.id} />
  );
}
