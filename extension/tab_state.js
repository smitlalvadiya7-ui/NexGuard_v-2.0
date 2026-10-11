// NexGuard AI — per-tab protection state → toolbar badge + popup status (E10).
//
// Before this, the extension was INVISIBLE on a normal page: a safe page, a
// skipped page and a dead backend all looked identical (nothing). Every
// top-level navigation now records what NexGuard did with it, and this module
// turns that state into the toolbar badge and the popup's status strip.
// Loaded in the service worker via importScripts and in popup.html via
// <script>; require()-able in Node for tests.
(function () {
  const COLORS = {
    safe: "#22C55E",
    warn: "#F59E0B",
    danger: "#EF4444",
    muted: "#64748B",
  };

  // state = { kind, verdict?, score?, url?, ts? }
  //   kind: "scanned" | "trusted" | "unreachable" | "off" | "bypassed" | "none"
  function badgeForState(state) {
    if (!state || !state.kind) return null;
    if (state.kind === "scanned") {
      const v = String(state.verdict || "UNKNOWN").toUpperCase();
      const score = Number.isFinite(Number(state.score)) ? Number(state.score) : 0;
      if (v === "SAFE") {
        return { text: "✓", color: COLORS.safe, title: "NexGuard — page scanned: SAFE" };
      }
      if (v === "SUSPICIOUS") {
        return { text: "!", color: COLORS.warn, title: `NexGuard — page scanned: SUSPICIOUS (risk ${score})` };
      }
      if (v === "MALICIOUS") {
        return { text: "✕", color: COLORS.danger, title: `NexGuard — page scanned: MALICIOUS (risk ${score})` };
      }
      // UNKNOWN or anything unexpected: honest question mark, never a check.
      return { text: "?", color: COLORS.muted, title: "NexGuard — scanned, but could not judge this page" };
    }
    if (state.kind === "trusted") {
      return { text: "✓", color: COLORS.muted, title: "NexGuard — trusted site, not scanned (safe list or your whitelist)" };
    }
    if (state.kind === "unreachable") {
      return { text: "?", color: COLORS.warn, title: "NexGuard — could not reach the backend, this page was NOT scanned" };
    }
    if (state.kind === "off") {
      return { text: "OFF", color: COLORS.muted, title: "NexGuard — automatic protection is off" };
    }
    if (state.kind === "bypassed") {
      return { text: "!", color: COLORS.danger, title: "NexGuard — you chose Proceed anyway on a flagged page" };
    }
    return null; // "none" / non-web pages
  }

  // The popup's plain-language status strip. Never claims safety it can't back.
  function describeState(state) {
    if (!state || !state.kind || state.kind === "none") {
      return { tone: "muted", text: "This page has not been scanned automatically yet." };
    }
    if (state.kind === "scanned") {
      const v = String(state.verdict || "UNKNOWN").toUpperCase();
      const score = Number.isFinite(Number(state.score)) ? Number(state.score) : 0;
      if (v === "SAFE") {
        return { tone: "safe", text: `Live protection scanned this page — SAFE (risk ${score}).` };
      }
      if (v === "SUSPICIOUS") {
        return { tone: "warn", text: `Live protection scanned this page — SUSPICIOUS (risk ${score}).` };
      }
      if (v === "MALICIOUS") {
        return { tone: "danger", text: `Live protection scanned this page — MALICIOUS (risk ${score}).` };
      }
      return { tone: "muted", text: "Scanned, but there was not enough signal to judge this page." };
    }
    if (state.kind === "trusted") {
      return { tone: "muted", text: "Trusted site — NexGuard skipped scanning it (safe list or your whitelist)." };
    }
    if (state.kind === "unreachable") {
      return {
        tone: "warn",
        text: "Could not reach your NexGuard backend — this page was NOT scanned. Start the backend, or check the URL in Settings.",
      };
    }
    if (state.kind === "off") {
      return { tone: "muted", text: "Automatic protection is off. Turn it on in Settings to scan pages as you browse." };
    }
    if (state.kind === "bypassed") {
      return { tone: "warn", text: "You chose “Proceed anyway” on a flagged page. Be careful here." };
    }
    return { tone: "muted", text: "This page has not been scanned automatically yet." };
  }

  const api = { badgeForState, describeState, COLORS };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
  if (typeof globalThis !== "undefined") {
    globalThis.badgeForState = badgeForState;
    globalThis.describeState = describeState;
  }
})();
