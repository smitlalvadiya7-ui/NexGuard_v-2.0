import { useSearchParams } from "react-router-dom";
import { useAuth } from "../../auth/AuthContext.jsx";
import History from "./History.jsx";
import Watchlist from "./Watchlist.jsx";

/*
 * Activity — History + Watchlist tabs. The Watchlist tab replicates the old
 * UI's #watchlistNavBtn rule (index.html _updateSidebar: shown only when
 * tier === 'premium' || admin/superadmin), matching the backend's
 * require_premium gate on every /watchlist endpoint. A free user deep-linking
 * ?tab=watchlist silently falls back to History.
 */
function isPremiumViewer(user) {
  if (!user || user === "anonymous") return false;
  return user.tier === "premium" || user.role === "admin" || user.role === "superadmin";
}

function tabClass(active) {
  return `whitespace-nowrap rounded-md px-3 py-1.5 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
    active ? "bg-panel text-text shadow-sm" : "text-muted hover:text-text"
  }`;
}

export default function Activity() {
  const { user } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const premium = isPremiumViewer(user);

  const tabs = [{ key: "history", label: "History" }];
  if (premium) tabs.push({ key: "watchlist", label: "Watchlist" });

  const requested = searchParams.get("tab");
  const activeTab = tabs.some((t) => t.key === requested) ? requested : "history";

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Activity</h1>

      <div role="tablist" aria-label="Activity view" className="flex w-fit gap-1 rounded-lg bg-panel-2 p-1">
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

      {activeTab === "watchlist" ? <Watchlist /> : <History />}
    </div>
  );
}
