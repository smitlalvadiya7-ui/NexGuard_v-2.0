import { Link, NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext.jsx";
import {
  ShieldIcon,
  ScanIcon,
  ClockIcon,
  FileTextIcon,
  ChartIcon,
  SettingsIcon,
  HelpIcon,
  CrownIcon,
  LogoutIcon,
  UserIcon,
} from "./Icons.jsx";

const NAV_ITEMS = [
  { to: "/", label: "Dashboard", Icon: ShieldIcon },
  { to: "/scan", label: "Scan", Icon: ScanIcon },
  { to: "/activity", label: "Activity", Icon: ClockIcon },
  { to: "/reports", label: "Reports", Icon: FileTextIcon },
  { to: "/model", label: "Model", Icon: ChartIcon },
  { to: "/settings", label: "Settings", Icon: SettingsIcon },
  { to: "/support", label: "Support", Icon: HelpIcon },
];

function navLinkClass({ isActive }) {
  return `flex items-center gap-3 rounded-lg border-l-2 px-3 py-2 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
    isActive
      ? "border-accent bg-panel-2 text-accent"
      : "border-transparent text-muted hover:bg-panel-2 hover:text-text"
  }`;
}

export default function Sidebar() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const role = user && typeof user === "object" ? user.role : null;
  const isAdmin = role === "admin" || role === "superadmin";
  const isAnonymous = user === "anonymous";

  function handleSignOut() {
    logout();
    navigate("/login");
  }

  return (
    <aside className="flex h-screen w-60 shrink-0 flex-col border-r border-border bg-panel">
      <div className="flex items-center gap-2 px-4 py-5">
        <ShieldIcon size={22} className="shrink-0 text-accent" />
        <div className="min-w-0 leading-tight">
          <p className="truncate text-sm font-semibold text-text">NexGuard AI</p>
          <p className="truncate text-xs text-muted">Cyber Defense Platform</p>
        </div>
      </div>

      <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-2">
        {NAV_ITEMS.map(({ to, label, Icon }) => (
          <NavLink key={to} to={to} end className={navLinkClass}>
            <Icon size={18} />
            {label}
          </NavLink>
        ))}
        {isAdmin && (
          <NavLink to="/admin" end className={navLinkClass}>
            <CrownIcon size={18} />
            Admin
          </NavLink>
        )}
      </nav>

      <div className="border-t border-border p-3">
        <div className="flex items-center gap-2 px-1 py-1">
          <span className="flex size-8 shrink-0 items-center justify-center rounded-full bg-panel-2 text-xs font-semibold text-muted">
            {isAnonymous ? <UserIcon size={16} /> : user.email[0].toUpperCase()}
          </span>
          {isAnonymous ? (
            <span className="rounded-full bg-panel-2 px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide text-muted">
              Anonymous
            </span>
          ) : (
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-medium text-text">{user.email}</p>
              <span className="rounded-full bg-panel-2 px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide text-muted">
                {user.role}
              </span>
            </div>
          )}
        </div>

        {user?.tier === "free" && (
          <Link
            to="/settings"
            className="mt-3 flex w-full items-center justify-center rounded-lg border border-accent px-3 py-1.5 text-sm font-medium text-accent transition-colors hover:bg-accent hover:text-bg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            Request Premium
          </Link>
        )}

        <button
          type="button"
          onClick={handleSignOut}
          className="mt-3 flex w-full items-center gap-2 rounded-lg px-3 py-1.5 text-sm font-medium text-muted transition-colors hover:bg-panel-2 hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <LogoutIcon size={16} />
          Sign Out
        </button>
      </div>
    </aside>
  );
}
