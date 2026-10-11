// NexGuard AI — extension settings (E6).
//
// Protection level, hover-scan toggle and the whitelist, all stored in
// chrome.storage.local with safe defaults. navDecision() is the single
// source of truth for what a scan result does to a navigation at each
// protection level — the background worker calls it instead of hardcoding
// policy. Loaded via importScripts (worker) / <script> (options page);
// require()-able in Node for tests.
(function () {
  "use strict";

  const PROTECTION_LEVELS = ["block", "warn", "off"];
  const DEFAULT_PROTECTION_LEVEL = "block";

  // M6 — per-surface threshold: the risk score at which a SUSPICIOUS page is
  // treated like MALICIOUS while browsing. The extension interrupts real
  // navigation, so it gets its own cutoff, tuned separately from the web app.
  // 40 = strictest allowed (blocks most suspicion), 90 = most relaxed.
  const DEFAULT_BLOCK_SUSPICIOUS_AT = 60;
  const BLOCK_AT_MIN = 40;
  const BLOCK_AT_MAX = 90;

  function validLevel(level) {
    return PROTECTION_LEVELS.includes(level) ? level : DEFAULT_PROTECTION_LEVEL;
  }

  function validBlockAt(value) {
    const n = Math.round(Number(value));
    if (!Number.isFinite(n) || n < BLOCK_AT_MIN || n > BLOCK_AT_MAX) {
      // out-of-range junk falls back to default; near-misses clamp
      if (Number.isFinite(n) && n < BLOCK_AT_MIN && n >= 0) return BLOCK_AT_MIN;
      if (Number.isFinite(n) && n > BLOCK_AT_MAX && n <= 100) return BLOCK_AT_MAX;
      return DEFAULT_BLOCK_SUSPICIOUS_AT;
    }
    return n;
  }

  // Current settings with safe defaults. Never throws.
  async function getSettings() {
    try {
      const { protectionLevel, hoverScan, webmailBadges, blockSuspiciousAt } =
        await chrome.storage.local.get(
          ["protectionLevel", "hoverScan", "webmailBadges", "blockSuspiciousAt"]);
      return {
        protectionLevel: validLevel(protectionLevel),
        hoverScan: hoverScan !== false,
        webmailBadges: webmailBadges !== false,
        blockSuspiciousAt: validBlockAt(blockSuspiciousAt),
      };
    } catch {
      return {
        protectionLevel: DEFAULT_PROTECTION_LEVEL, hoverScan: true,
        webmailBadges: true, blockSuspiciousAt: DEFAULT_BLOCK_SUSPICIOUS_AT,
      };
    }
  }

  async function setBlockSuspiciousAt(value) {
    const v = validBlockAt(value);
    await chrome.storage.local.set({ blockSuspiciousAt: v });
    return v;
  }

  async function setProtectionLevel(level) {
    const value = validLevel(level);
    await chrome.storage.local.set({ protectionLevel: value });
    return value;
  }

  async function setHoverScan(enabled) {
    await chrome.storage.local.set({ hoverScan: Boolean(enabled) });
  }

  async function setWebmailBadges(enabled) {
    await chrome.storage.local.set({ webmailBadges: Boolean(enabled) });
  }

  // "https://Example.COM/x" / " Sub.Site.org " -> a clean lowercase hostname;
  // junk -> "".
  function normalizeHost(raw) {
    if (!raw || typeof raw !== "string") return "";
    let h = raw.trim().toLowerCase();
    if (!h) return "";
    if (/^https?:\/\//.test(h)) {
      try {
        h = new URL(h).hostname;
      } catch {
        return "";
      }
    }
    h = h.replace(/\/.*$/, "");
    return /^[a-z0-9][a-z0-9.-]*\.[a-z0-9-]+$/.test(h) ? h : "";
  }

  async function getWhitelist() {
    try {
      const { whitelist = [] } = await chrome.storage.local.get("whitelist");
      return Array.isArray(whitelist) ? whitelist : [];
    } catch {
      return [];
    }
  }

  // Add a host (normalized). Junk and duplicates are no-ops. Returns the list.
  async function addToWhitelist(raw) {
    const host = normalizeHost(raw);
    const list = await getWhitelist();
    if (!host || list.includes(host)) return list;
    const next = [...list, host];
    await chrome.storage.local.set({ whitelist: next });
    return next;
  }

  async function removeFromWhitelist(host) {
    const list = await getWhitelist();
    const next = list.filter((h) => h !== host);
    await chrome.storage.local.set({ whitelist: next });
    return next;
  }

  // What a finished scan does to the navigation at this protection level:
  //   "block"   -> redirect to the warning interstitial
  //   "warnbar" -> non-blocking warning bar on the page
  //   "none"    -> nothing
  // Unknown levels behave like "block" (protective default).
  function navDecision(level, verdict, score, blockSuspiciousAt) {
    const lvl = validLevel(level);
    if (lvl === "off") return "none";
    const v = String(verdict || "").toUpperCase();
    const risky = v === "MALICIOUS" ||
      (v === "SUSPICIOUS" && score >= blockSuspiciousAt);
    if (risky) return lvl === "block" ? "block" : "warnbar";
    if (v === "SUSPICIOUS") return "warnbar";
    return "none";
  }

  const api = {
    PROTECTION_LEVELS,
    DEFAULT_PROTECTION_LEVEL,
    DEFAULT_BLOCK_SUSPICIOUS_AT,
    getSettings,
    setProtectionLevel,
    setHoverScan,
    setWebmailBadges,
    setBlockSuspiciousAt,
    normalizeHost,
    getWhitelist,
    addToWhitelist,
    removeFromWhitelist,
    navDecision,
  };

  if (typeof globalThis !== "undefined") {
    Object.assign(globalThis, api);
  }
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})();
