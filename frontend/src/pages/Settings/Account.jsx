import { useEffect, useState } from "react";
import { apiFetch } from "../../api.js";
import { useAuth } from "../../auth/AuthContext.jsx";
import { useToast } from "../../components/Toast.jsx";

/*
 * Account + upgrade flows. Billing endpoints (backend/main.py):
 *   GET  /billing/config (595)            -> {enabled, publishable_key, ...}
 *   POST /billing/create-checkout-session (601) -> {url} (Stripe-enabled only)
 *   POST /requests/upgrade (746)          -> approval request (409 if pending)
 * Upgrade controls only render for logged-in FREE-tier users — the backend
 * 400s premium viewers on both paths.
 */
export default function Account() {
  const { user } = useAuth();
  const { push } = useToast();
  const [billing, setBilling] = useState(null);
  const [busy, setBusy] = useState("");

  const loggedIn = user && user !== "anonymous";
  const isFree = loggedIn && user.tier === "free";

  useEffect(() => {
    let alive = true;
    apiFetch("/billing/config")
      .then((cfg) => alive && setBilling(cfg))
      .catch(() => alive && setBilling(null));
    return () => {
      alive = false;
    };
  }, []);

  async function upgradeWithCard() {
    setBusy("card");
    try {
      const res = await apiFetch("/billing/create-checkout-session", { method: "POST", body: {} });
      if (res?.url) {
        window.location.assign(res.url);
      }
    } catch (err) {
      push("error", err.message || "Could not start checkout.");
    } finally {
      setBusy("");
    }
  }

  async function requestPremium() {
    setBusy("request");
    try {
      await apiFetch("/requests/upgrade", { method: "POST", body: {} });
      push("success", "Upgrade request sent — an admin will review it shortly.");
    } catch (err) {
      push("error", err.message || "Could not send the upgrade request.");
    } finally {
      setBusy("");
    }
  }

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-border bg-panel p-4">
        <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted">Account</h2>
        {!loggedIn ? (
          <p className="text-sm text-muted">
            You're browsing anonymously. Log in to manage your plan and API keys.
          </p>
        ) : (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div>
              <p className="text-xs text-muted">Email</p>
              <p className="truncate text-sm font-medium text-text">{user.email}</p>
            </div>
            <div>
              <p className="text-xs text-muted">Role</p>
              <p className="text-sm font-medium capitalize text-text">{user.role}</p>
            </div>
            <div>
              <p className="text-xs text-muted">Plan</p>
              <p className="text-sm font-medium capitalize text-text">{user.tier}</p>
            </div>
          </div>
        )}
      </div>

      {isFree && (
        <div className="space-y-3 rounded-lg border border-border bg-panel p-4">
          <h2 className="text-xs font-semibold uppercase tracking-wide text-muted">
            Upgrade to Premium
          </h2>
          <div className="flex flex-wrap items-center gap-2">
            {billing?.enabled && (
              <button
                type="button"
                onClick={upgradeWithCard}
                disabled={busy !== ""}
                className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-bg transition-opacity hover:opacity-90 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                {busy === "card" ? "Redirecting…" : "💳 Upgrade with Card"}
              </button>
            )}
            <button
              type="button"
              onClick={requestPremium}
              disabled={busy !== ""}
              className="rounded-lg bg-warn px-4 py-2 text-sm font-medium text-bg transition-opacity hover:opacity-90 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              {busy === "request" ? "Sending…" : "⭐ Request Premium (approval)"}
            </button>
          </div>
          <p className="text-xs text-muted">
            {billing?.enabled
              ? "Card checkout activates instantly; the approval path is reviewed by an admin."
              : "Demo, no payment: Premium is free during the demo. Send a request and an admin approves it."}
          </p>
        </div>
      )}

      {(!loggedIn || isFree) && (
        <div className="rounded-lg border border-border bg-panel p-4 text-sm text-muted">
          <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">
            Free tier limits
          </h2>
          <ul className="list-inside list-disc space-y-1">
            <li>10 scans per day for logged-in free accounts (5/day by IP when anonymous).</li>
            <li>Reports include the core verdict, score, confidence and flags.</li>
            <li>
              Premium intel — resolved IP, geolocation, WHOIS, SSL, redirect chain and the live
              page preview — stays locked behind the upgrade overlay.
            </li>
            <li>Premium is unlimited with the full forensic object on every scan.</li>
          </ul>
        </div>
      )}
    </div>
  );
}
