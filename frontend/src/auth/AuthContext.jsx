import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import { apiFetch, getToken, setToken, clearToken, setOnUnauthorized } from "../api.js";

const EMAIL_KEY = "nexguard.email";
const ROLE_KEY = "nexguard.role";
const TIER_KEY = "nexguard.tier";

const AuthContext = createContext(undefined);

function persistUser({ email, role, tier }) {
  localStorage.setItem(EMAIL_KEY, email);
  localStorage.setItem(ROLE_KEY, role);
  localStorage.setItem(TIER_KEY, tier);
}

function clearStoredUser() {
  localStorage.removeItem(EMAIL_KEY);
  localStorage.removeItem(ROLE_KEY);
  localStorage.removeItem(TIER_KEY);
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);

  // Auth generation counter. Every authoritative session transition (login,
  // logout, skipAuth, provider unmount) bumps it. An async refresh() captures
  // the generation before awaiting and applies its /auth/me result ONLY if
  // the generation is unchanged — so a straggling revalidation for user A can
  // never overwrite a session user B established while it was in flight.
  const genRef = useRef(0);

  // Registered with setOnUnauthorized below so ANY apiFetch 401 (not just /auth/me)
  // logs the session out exactly once — apiFetch calls this callback before it
  // throws, so callers never need to duplicate this cleanup in a catch block.
  const logout = useCallback(() => {
    genRef.current += 1;
    clearToken();
    clearStoredUser();
    setUser(null);
  }, []);

  // Revalidates/hydrates from the backend. Used both for mount-time session
  // restore and as the `refresh()` escape hatch exposed to consumers (e.g.
  // after a tier change). Never returns the shape login() returns for a 401 —
  // apiFetch's onUnauthorized (logout) already clears state before the
  // rejection reaches us. Returns null when the result is stale (a newer auth
  // transition won the race) and was discarded.
  const refresh = useCallback(async () => {
    const gen = genRef.current;
    const me = await apiFetch("/auth/me");
    if (gen !== genRef.current) return null; // stale — discard silently
    const nextUser = { email: me.email, role: me.role, tier: me.tier };
    persistUser(nextUser);
    setUser(nextUser);
    return nextUser;
  }, []);

  const login = useCallback(async (email, password) => {
    // POST /auth/login returns {token, role, tier, status, email, id} — the
    // session token field is `token`, not `access_token`.
    const data = await apiFetch("/auth/login", { method: "POST", body: { email, password } });
    // Bump at the point the new session is applied (not before the await) so
    // a FAILED login doesn't spuriously invalidate a legitimate refresh.
    genRef.current += 1;
    setToken(data.token);
    const nextUser = { email: data.email, role: data.role, tier: data.tier };
    persistUser(nextUser);
    setUser(nextUser);
    return nextUser;
  }, []);

  const register = useCallback(
    async (email, password) => {
      // POST /auth/register returns only {id, email, role, message} — no
      // token and no tier, so it can't establish a session by itself. Log in
      // immediately afterward so the UI gets a session either way.
      await apiFetch("/auth/register", { method: "POST", body: { email, password } });
      return login(email, password);
    },
    [login]
  );

  const skipAuth = useCallback(() => {
    genRef.current += 1;
    setUser("anonymous");
  }, []);

  useEffect(() => {
    setOnUnauthorized(logout);
    if (getToken()) {
      refresh().catch(() => {
        // Non-401 failures (network error, 5xx) just leave the session
        // un-hydrated; a 401 already cleared everything via onUnauthorized.
      });
    }
    return () => {
      // Invalidate any in-flight refresh on unmount so its resolution never
      // calls setUser after teardown (same guard also covers StrictMode's
      // dev-time mount → cleanup → remount cycle: only the live mount's
      // revalidation applies).
      genRef.current += 1;
    };
    // Mount-only: register the shared 401 handler and revalidate a stored
    // token once. logout/refresh are stable (empty-dep useCallback).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const value = useMemo(
    () => ({ user, login, register, logout, skipAuth, refresh }),
    [user, login, register, logout, skipAuth, refresh]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (ctx === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
}
