// NexGuard AI — extension sign-in (E2).
//
// Stores the user's JWT session (token + email + tier) in chrome.storage.local
// so every scan runs on their account instead of the anonymous free limit.
// Loaded in every extension context, like config.js:
//   * service worker  -> importScripts("config.js", "auth.js")
//   * popup/options    -> <script src="auth.js"></script>
// Also require()-able in Node for tests.
(function () {
  "use strict";

  const AUTH_KEYS = ["authToken", "authEmail", "authTier"];

  // Current session. Never throws; no/broken storage means signed out.
  async function getAuthState() {
    try {
      const { authToken, authEmail, authTier } =
        await chrome.storage.local.get(AUTH_KEYS);
      if (!authToken) return { signedIn: false, token: null, email: null, tier: null };
      return {
        signedIn: true,
        token: authToken,
        email: authEmail || null,
        tier: authTier || null,
      };
    } catch {
      return { signedIn: false, token: null, email: null, tier: null };
    }
  }

  // Headers to merge into backend requests: Bearer token when signed in,
  // empty object when not — callers can always spread the result.
  async function getAuthHeaders() {
    const s = await getAuthState();
    return s.signedIn ? { Authorization: "Bearer " + s.token } : {};
  }

  // Log in against <backend>/auth/login and store the session.
  // Resolves to { ok: true, email, tier } or { ok: false, error } — never throws.
  async function signIn(backend, email, password) {
    const em = (email || "").trim();
    const pw = password || "";
    if (!em || !pw) return { ok: false, error: "Enter your email and password." };

    let res;
    try {
      res = await fetch(backend + "/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: em, password: pw }),
      });
    } catch {
      return { ok: false, error: "Could not reach the backend. Is it running?" };
    }

    let data = {};
    try {
      data = await res.json();
    } catch {
      /* non-JSON error body — fall through to the generic message */
    }

    if (!res.ok || !data.token) {
      return { ok: false, error: data.detail || "Sign-in failed. Please try again." };
    }

    await chrome.storage.local.set({
      authToken: data.token,
      authEmail: data.email || em,
      authTier: data.tier || "free",
    });
    return { ok: true, email: data.email || em, tier: data.tier || "free" };
  }

  // Forget the stored session. Never throws.
  async function signOut() {
    try {
      await chrome.storage.local.remove(AUTH_KEYS);
    } catch {
      /* nothing to clear */
    }
  }

  const api = { getAuthState, getAuthHeaders, signIn, signOut };

  // Extension contexts: expose as globals (service worker + popup/options).
  if (typeof globalThis !== "undefined") {
    Object.assign(globalThis, api);
  }
  // Node (tests).
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})();
