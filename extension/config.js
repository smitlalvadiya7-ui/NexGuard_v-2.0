// NexGuard AI — shared backend-URL config (E1).
//
// The extension talks to a NexGuard backend. The URL is user-configurable
// (options page), stored in chrome.storage.local, and defaults to the local
// dev server. Loaded in every extension context:
//   * service worker  -> importScripts("config.js")
//   * popup/options    -> <script src="config.js"></script>
// Also require()-able in Node for tests.
(function () {
  "use strict";

  const NEXGUARD_DEFAULT_BACKEND = "http://127.0.0.1:8000";

  // Clean a user-typed backend URL. Returns "" for anything unusable so the
  // caller can fall back to the default. Adds http:// when no scheme is given
  // and strips trailing slashes so we can append paths cleanly.
  function normalizeBackendUrl(raw) {
    if (!raw || typeof raw !== "string") return "";
    let u = raw.trim();
    if (!u) return "";
    u = u.replace(/\/+$/, "");
    if (!u) return "";
    if (!/^https?:\/\//i.test(u)) u = "http://" + u;
    let parsed;
    try {
      parsed = new URL(u);
    } catch {
      return "";
    }
    if (!/^https?:$/.test(parsed.protocol)) return "";
    if (!parsed.hostname || /\s/.test(u)) return "";
    return u;
  }

  // Current backend URL (normalized), or the default. Never throws.
  async function getBackendUrl() {
    try {
      const { backendUrl } = await chrome.storage.local.get("backendUrl");
      return normalizeBackendUrl(backendUrl) || NEXGUARD_DEFAULT_BACKEND;
    } catch {
      return NEXGUARD_DEFAULT_BACKEND;
    }
  }

  // Save a backend URL; junk falls back to the default. Returns the stored value.
  async function setBackendUrl(raw) {
    const value = normalizeBackendUrl(raw) || NEXGUARD_DEFAULT_BACKEND;
    await chrome.storage.local.set({ backendUrl: value });
    return value;
  }

  const api = { NEXGUARD_DEFAULT_BACKEND, normalizeBackendUrl, getBackendUrl, setBackendUrl };

  // Extension contexts: expose as globals (service worker + popup/options).
  if (typeof globalThis !== "undefined") {
    Object.assign(globalThis, api);
  }
  // Node (tests).
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})();
