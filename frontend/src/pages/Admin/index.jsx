import { useSearchParams } from "react-router-dom";
import { useAuth } from "../../auth/AuthContext.jsx";
import Users from "./Users.jsx";
import Requests from "./Requests.jsx";
import Feedback from "./Feedback.jsx";
import AdminSupport from "./Support.jsx";
import Stats from "./Stats.jsx";
import Audit from "./Audit.jsx";

/*
 * Admin console — parity target index.html #adminPage (2280-2403). Route
 * access is already gated by <RequireAdmin>; the Audit tab additionally
 * requires superadmin (GET /superadmin/audit 403s anyone else), so it is
 * hidden — not just disabled — for plain admins.
 */
const PANELS = {
  users: Users,
  requests: Requests,
  feedback: Feedback,
  support: AdminSupport,
  stats: Stats,
  audit: Audit,
};

function tabClass(active) {
  return `whitespace-nowrap rounded-md px-3 py-1.5 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
    active ? "bg-panel text-text shadow-sm" : "text-muted hover:text-text"
  }`;
}

export default function Admin() {
  const { user } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const isSuperadmin = user && user !== "anonymous" && user.role === "superadmin";

  const tabs = [
    { key: "users", label: "Users" },
    { key: "requests", label: "Requests" },
    { key: "feedback", label: "Feedback" },
    { key: "support", label: "Support" },
    { key: "stats", label: "Stats" },
  ];
  if (isSuperadmin) tabs.push({ key: "audit", label: "Audit" });

  const requested = searchParams.get("tab");
  const activeTab = tabs.some((t) => t.key === requested) ? requested : "users";
  const ActivePanel = PANELS[activeTab];

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Admin</h1>

      <div role="tablist" aria-label="Admin section" className="flex w-fit flex-wrap gap-1 rounded-lg bg-panel-2 p-1">
        {tabs.map(({ key, label }) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={activeTab === key}
            onClick={() => setSearchParams({ tab: key })}
            className={tabClass(activeTab === key)}
          >
            {label}
          </button>
        ))}
      </div>

      <ActivePanel />
    </div>
  );
}
