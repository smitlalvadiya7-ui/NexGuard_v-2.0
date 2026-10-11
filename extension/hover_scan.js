// NexGuard AI — in-page link safety (E5).
//
// Content script: when the user hovers an EXTERNAL link, the background
// scans it (60s verdict cache, short timeout, fail-open) and risky links get
// a small ⚠ / ✘ marker right after the anchor. SAFE links stay unmarked —
// low noise by design — and any error means no badge, never a block.
// Runs before content.js (see manifest); pure helpers are Node-testable.
(function () {
  "use strict";

  const HOVER_DEBOUNCE_MS = 250;

  const BADGES = {
    MALICIOUS: { char: "✘", color: "#EF4444" },
    SUSPICIOUS: { char: "⚠", color: "#F59E0B" },
  };

  function registrable(host) {
    const parts = String(host || "").toLowerCase().split(".");
    return parts.length <= 2 ? parts.join(".") : parts.slice(-2).join(".");
  }

  // Only external web links are worth a hover scan: http(s), different
  // registrable domain from the page. Anything unparsable is skipped.
  function shouldConsiderLink(href, pageHost) {
    if (!href || typeof href !== "string") return false;
    let u;
    try {
      u = new URL(href);
    } catch {
      return false;
    }
    if (!/^https?:$/.test(u.protocol)) return false;
    if (!u.hostname) return false;
    return registrable(u.hostname) !== registrable(pageHost);
  }

  // Badge spec for a verdict, or null for anything not clearly risky.
  function badgeFor(verdict, score) {
    const v = String(verdict || "").toUpperCase();
    const spec = BADGES[v];
    if (!spec) return null;
    return {
      char: spec.char,
      color: spec.color,
      title: "NexGuard: " + v + " (risk " + (score ?? "?") + "/100) — " +
        (v === "MALICIOUS" ? "do not open this link" : "be careful with this link"),
    };
  }

  const api = { shouldConsiderLink, badgeFor };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;   // Node tests
  }
  if (typeof globalThis !== "undefined") {
    Object.assign(globalThis, api);
  }

  // ── Runtime (browser content-script context only) ─────────────────────────
  if (typeof document === "undefined" || typeof chrome === "undefined" ||
      !chrome.runtime || !chrome.runtime.sendMessage) {
    return;
  }

  (async () => {
    // Respect settings: hover scanning can be turned off, and protection
    // level "off" disables it too (E6).
    try {
      const { hoverScan, protectionLevel } =
        await chrome.storage.local.get(["hoverScan", "protectionLevel"]);
      if (hoverScan === false || protectionLevel === "off") return;
    } catch {
      /* no storage — stay enabled */
    }

    const results = new Map();   // href -> "pending" | true (handled)
    let timer = null;

    function addBadge(anchor, verdict, score) {
      const spec = badgeFor(verdict, score);
      if (!spec || !anchor.isConnected) return;
      if (anchor.nextElementSibling &&
          anchor.nextElementSibling.hasAttribute?.("data-nexguard-badge")) return;
      const span = document.createElement("span");
      span.setAttribute("data-nexguard-badge", "");
      span.textContent = spec.char;
      span.title = spec.title;
      span.style.cssText = [
        "display:inline-block", "margin-left:4px", "font-weight:700",
        "color:" + spec.color, "cursor:help", "font-size:0.9em",
      ].join(";");
      anchor.insertAdjacentElement("afterend", span);
    }

    function scanAnchor(anchor) {
      const href = anchor.href;
      if (results.has(href)) return;
      results.set(href, "pending");
      chrome.runtime.sendMessage({ type: "SCAN_LINK", url: href }, (res) => {
        if (chrome.runtime.lastError || !res) return;   // fail-open: no badge
        addBadge(anchor, res.verdict, res.score);
      });
    }

    document.addEventListener("mouseover", (e) => {
      const anchor = e.target && e.target.closest ? e.target.closest("a[href]") : null;
      if (!anchor) return;
      if (!shouldConsiderLink(anchor.href, location.hostname)) return;
      if (results.has(anchor.href)) return;
      clearTimeout(timer);
      timer = setTimeout(() => scanAnchor(anchor), HOVER_DEBOUNCE_MS);
    });

    document.addEventListener("mouseout", () => clearTimeout(timer));
  })();
})();
