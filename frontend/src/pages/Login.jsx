import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext.jsx";
import { LogoMark } from "../components/Icons.jsx";

function tabClass(active) {
  return `rounded-md py-1.5 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
    active ? "bg-panel text-text shadow-sm" : "text-muted hover:text-text"
  }`;
}

export default function Login() {
  const { user, login, register, skipAuth } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const [tab, setTab] = useState("login"); // "login" | "register"
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  // Bounces away from the login screen the moment a real session exists —
  // covers both an explicit login/register success and a stored token that
  // finishes revalidating (via AuthProvider's mount effect) while this page
  // is showing. Returns to the location RequireAuth captured when it bounced
  // the user here (deep links land on /login mid-hydration), falling back to
  // the dashboard for direct /login visits. Deliberately excludes the
  // "anonymous" sentinel: skipAuth() below already navigates explicitly to
  // /scan in the same tick, and letting this effect also fire for that
  // transition races it (both would navigate off /login at once, and either
  // could win).
  useEffect(() => {
    if (user && typeof user === "object") {
      navigate(location.state?.from?.pathname ?? "/", { replace: true });
    }
  }, [user, navigate, location]);

  function switchTab(next) {
    setTab(next);
    setError("");
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      if (tab === "login") {
        await login(email, password);
      } else {
        await register(email, password);
      }
    } catch (err) {
      setError(err.message || "Something went wrong. Try again.");
    } finally {
      setBusy(false);
    }
  }

  function handleSkip() {
    skipAuth();
    navigate("/scan");
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg px-4">
      <div className="w-full max-w-sm rounded-xl border border-border bg-panel p-8 shadow-sm">
        <div className="mb-6 flex flex-col items-center gap-2 text-center">
          <LogoMark size={40} />
          <h1 className="text-lg font-semibold text-text">NexGuard AI</h1>
          <p className="text-sm text-muted">Cyber Defense Platform</p>
        </div>

        <div role="tablist" aria-label="Authentication mode" className="mb-5 grid grid-cols-2 gap-1 rounded-lg bg-panel-2 p-1">
          <button
            type="button"
            role="tab"
            aria-selected={tab === "login"}
            onClick={() => switchTab("login")}
            className={tabClass(tab === "login")}
          >
            Sign In
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={tab === "register"}
            onClick={() => switchTab("register")}
            className={tabClass(tab === "register")}
          >
            Register
          </button>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col gap-3">
          <label className="flex flex-col gap-1 text-sm text-muted">
            Email address
            <input
              type="email"
              required
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text outline-none focus-visible:ring-2 focus-visible:ring-accent"
            />
          </label>
          <label className="flex flex-col gap-1 text-sm text-muted">
            Password
            <input
              type="password"
              required
              minLength={tab === "register" ? 12 : undefined}
              autoComplete={tab === "login" ? "current-password" : "new-password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text outline-none focus-visible:ring-2 focus-visible:ring-accent"
            />
            {tab === "register" && <span className="text-xs text-muted">Minimum 12 characters</span>}
          </label>

          {error && <p className="text-sm text-danger">{error}</p>}

          <button
            type="submit"
            disabled={busy}
            className="mt-1 rounded-lg bg-accent py-2 text-sm font-medium text-bg transition-opacity hover:opacity-90 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            {busy
              ? tab === "login"
                ? "Signing in…"
                : "Creating account…"
              : tab === "login"
                ? "Sign In"
                : "Create Account"}
          </button>
        </form>

        <button
          type="button"
          onClick={handleSkip}
          className="mt-5 w-full text-center text-sm text-muted hover:text-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent rounded"
        >
          Continue without login →
        </button>
      </div>
    </div>
  );
}
