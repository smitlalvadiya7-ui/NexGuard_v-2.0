// NexGuard AI — background service worker (real-time blocking)
//
// On every top-level navigation we scan the destination URL via the local
// NexGuard backend. If the verdict is MALICIOUS (or SUSPICIOUS above a
// threshold) we redirect the tab to a warning interstitial. Lower-risk
// SUSPICIOUS pages get a non-blocking warning bar (content.js).
//
// Design goals: fast (short timeout, async), fail-open (never block on a
// backend error/timeout/quota), and low-noise (cache + safe-domain + whitelist
// skips so we don't rescan every navigation).

// Shared backend-URL config (E1): getBackendUrl() reads the user's configured
// URL from chrome.storage, defaulting to the local dev server.
// Sign-in session (E2): getAuthHeaders() adds the user's Bearer token so
// scans count against their account instead of the anonymous free limit.
// Right-click scans (E4): context_scan.js picks targets + builds result.html URLs.
// Settings (E6): getSettings()/navDecision() decide what a verdict does to a
// navigation at the user's protection level (block / warn only / off).
// Visible protection state (E10): every navigation records what NexGuard did
// (scanned/trusted/unreachable/off/bypassed) per tab; tab_state.js turns that
// into the toolbar badge, and the popup asks for it via GET_TAB_STATE.
importScripts("config.js", "auth.js", "context_scan.js", "settings.js", "tab_state.js");

const SCAN_TIMEOUT_MS = 2500;          // abort slow scans — keep browsing snappy
const CACHE_TTL_MS = 60 * 1000;        // remember a URL's verdict for 60s
const BYPASS_TTL_MS = 60 * 1000;       // "Proceed anyway" grace window
// M6: the SUSPICIOUS block threshold is a user setting now
// (settings.blockSuspiciousAt, default 60, clamped 40–90 in settings.js).

// Never scan local / private / non-web addresses.
const SKIP_HOST_PATTERNS = [
  /^localhost$/i, /^127\./, /^0\.0\.0\.0$/, /^\[?::1\]?$/,
  /^10\./, /^192\.168\./, /^172\.(1[6-9]|2[0-9]|3[0-1])\./, /\.local$/i,
];

// Well-known safe domains we don't bother scanning (matched on the registrable
// suffix, so subdomains are covered too).
const SAFE_DOMAINS = new Set([
  "google.com", "youtube.com", "gmail.com", "googleapis.com", "gstatic.com",
  "microsoft.com", "office.com", "live.com", "bing.com", "windows.com",
  "apple.com", "icloud.com", "amazon.com", "aws.amazon.com", "cloudfront.net",
  "github.com", "githubusercontent.com", "gitlab.com", "stackoverflow.com",
  "wikipedia.org", "mozilla.org", "cloudflare.com", "openai.com",
  "facebook.com", "instagram.com", "whatsapp.com", "linkedin.com", "x.com",
  "twitter.com", "reddit.com", "netflix.com", "spotify.com", "paypal.com",
  "stripe.com", "duckduckgo.com", "yahoo.com", "bing.net",
]);

// In-memory state (resets if the service worker is recycled — that's fine).
const verdictCache = new Map();   // url -> { verdict, score, reasons, ts }
const bypassUrls = new Map();     // url -> expiry timestamp (Proceed anyway)
const senderCache = new Map();    // sender -> { res, ts } (E8 webmail badge)
const SENDER_CACHE_TTL_MS = 10 * 60 * 1000;
const tabStates = new Map();      // tabId -> { kind, verdict?, score?, url, ts } (E10)

// Record what happened to a tab's navigation and paint the toolbar badge.
function setTabState(tabId, state) {
  const full = { ...state, ts: Date.now() };
  tabStates.set(tabId, full);
  const badge = badgeForState(full);
  try {
    chrome.action.setBadgeText({ tabId, text: badge ? badge.text : "" }).catch(() => {});
    if (badge) {
      chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color }).catch(() => {});
      chrome.action.setBadgeTextColor?.({ tabId, color: "#FFFFFF" })?.catch?.(() => {});
    }
    chrome.action.setTitle({
      tabId, title: badge ? badge.title : "NexGuard AI",
    }).catch(() => {});
  } catch { /* badge is cosmetic — never break the nav gate over it */ }
}

chrome.tabs.onRemoved.addListener((tabId) => tabStates.delete(tabId));

function registrableSuffix(hostname) {
  const parts = hostname.toLowerCase().split(".");
  return parts.length <= 2 ? hostname.toLowerCase() : parts.slice(-2).join(".");
}

async function isWhitelisted(hostname) {
  try {
    const { whitelist = [] } = await chrome.storage.local.get("whitelist");
    const host = hostname.toLowerCase();
    const root = registrableSuffix(host);
    return whitelist.some((w) => w === host || w === root);
  } catch {
    return false;
  }
}

function shouldSkipUrl(rawUrl) {
  try {
    const u = new URL(rawUrl);
    if (!/^https?:$/.test(u.protocol)) return true;            // skip chrome://, file://, extension pages
    if (SKIP_HOST_PATTERNS.some((re) => re.test(u.hostname))) return true;
    if (SAFE_DOMAINS.has(registrableSuffix(u.hostname))) return true;
    return false;
  } catch {
    return true;
  }
}

function consumeBypass(url) {
  const exp = bypassUrls.get(url);
  if (exp && exp > Date.now()) {
    bypassUrls.delete(url);   // one-time pass
    return true;
  }
  if (exp) bypassUrls.delete(url);
  return false;
}

async function scanUrl(url) {
  // Serve fresh cache
  const hit = verdictCache.get(url);
  if (hit && Date.now() - hit.ts < CACHE_TTL_MS) return hit;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS);
  try {
    const backend = await getBackendUrl();
    const res = await fetch(backend + "/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json", ...(await getAuthHeaders()) },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });
    if (!res.ok) return null;                       // 429 / errors => fail-open
    const data = await res.json();
    const entry = {
      verdict: (data.verdict || "UNKNOWN").toUpperCase(),
      score: data.risk_score ?? data.score ?? 0,
      reasons: data.reasons || data.flags || [],
      ts: Date.now(),
    };
    verdictCache.set(url, entry);
    return entry;
  } catch {
    return null;                                    // timeout / network => fail-open
  } finally {
    clearTimeout(timer);
  }
}

function buildWarningUrl(targetUrl, result) {
  const params = new URLSearchParams({
    url: targetUrl,
    verdict: result.verdict,
    score: String(result.score),
    reasons: JSON.stringify((result.reasons || []).slice(0, 8)),
  });
  return chrome.runtime.getURL("warning.html") + "?" + params.toString();
}

// ── Real-time gate: every top-level navigation ──────────────────────────────
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;                // top-level frame only
  const url = details.url;

  // Our own pages (warning interstitial, result page): keep the previous
  // state so the ✕ badge of a just-blocked page is not wiped by the redirect.
  if (url.startsWith(chrome.runtime.getURL(""))) return;

  let u;
  try { u = new URL(url); } catch { return; }
  if (!/^https?:$/.test(u.protocol) ||
      SKIP_HOST_PATTERNS.some((re) => re.test(u.hostname))) {
    setTabState(details.tabId, { kind: "none", url });
    return;
  }
  if (SAFE_DOMAINS.has(registrableSuffix(u.hostname))) {
    setTabState(details.tabId, { kind: "trusted", url });
    return;
  }
  if (consumeBypass(url)) {                         // user chose "Proceed anyway"
    setTabState(details.tabId, { kind: "bypassed", url });
    return;
  }

  // E6: protection level "off" disables navigation scanning entirely.
  const { protectionLevel, blockSuspiciousAt } = await getSettings();
  if (protectionLevel === "off") {
    setTabState(details.tabId, { kind: "off", url });
    return;
  }

  if (await isWhitelisted(u.hostname)) {
    setTabState(details.tabId, { kind: "trusted", url });
    return;
  }

  const result = await scanUrl(url);
  if (!result) {                                    // fail-open, but VISIBLY
    setTabState(details.tabId, { kind: "unreachable", url });
    return;
  }
  setTabState(details.tabId, {
    kind: "scanned", verdict: result.verdict, score: result.score, url,
  });

  const action = navDecision(protectionLevel, result.verdict, result.score,
                             blockSuspiciousAt);
  if (action === "block") {
    // The tab may already be loading the malicious page; redirecting interrupts it.
    chrome.tabs.update(details.tabId, { url: buildWarningUrl(url, result) }).catch(() => {});
  } else if (action === "warnbar") {
    // Non-blocking heads-up ("warn only" level shows this even for malicious).
    chrome.tabs.sendMessage(details.tabId, {
      type: "SHOW_WARNING", verdict: result.verdict, score: result.score,
    }).catch(() => {});
  }
});

// ── E4: right-click "Scan with NexGuard" context menus ──────────────────────
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "nexguard-scan-link", title: "Scan link with NexGuard", contexts: ["link"],
  });
  chrome.contextMenus.create({
    id: "nexguard-scan-image", title: "Scan image / QR with NexGuard", contexts: ["image"],
  });
  chrome.contextMenus.create({
    id: "nexguard-scan-selection", title: "Scan selected text with NexGuard", contexts: ["selection"],
  });
});

chrome.contextMenus.onClicked.addListener((info) => {
  let mode = null, target = null;
  if (info.menuItemId === "nexguard-scan-link" && info.linkUrl) {
    mode = "url"; target = info.linkUrl;
  } else if (info.menuItemId === "nexguard-scan-image" && info.srcUrl) {
    mode = "image"; target = info.srcUrl;
  } else if (info.menuItemId === "nexguard-scan-selection") {
    const sel = selectionTarget(info.selectionText);
    if (sel) ({ mode, target } = sel);
  }
  if (!mode || !target) return;
  chrome.tabs.create({ url: chrome.runtime.getURL(resultPageUrl(mode, target)) }).catch(() => {});
});

// ── Messages from the warning interstitial + hover scans (E5) ───────────────
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "PROCEED" && msg.url) {
    bypassUrls.set(msg.url, Date.now() + BYPASS_TTL_MS);
    sendResponse({ ok: true });
  } else if (msg.type === "WHITELIST_ADD" && msg.host) {
    chrome.storage.local.get("whitelist").then(({ whitelist = [] }) => {
      const host = msg.host.toLowerCase();
      if (!whitelist.includes(host)) whitelist.push(host);
      chrome.storage.local.set({ whitelist }).then(() => sendResponse({ ok: true }));
    });
    return true;   // async sendResponse
  } else if (msg.type === "SENDER_CHECK" && msg.sender) {
    // E8 webmail badge: header-free sender-origin check, cached 10 min.
    (async () => {
      try {
        const key = msg.sender.toLowerCase();
        const hit = senderCache.get(key);
        if (hit && Date.now() - hit.ts < SENDER_CACHE_TTL_MS) {
          return sendResponse(hit.res);
        }
        const backend = await getBackendUrl();
        const res = await fetch(backend + "/verify-sender", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sender: msg.sender }),
        });
        if (!res.ok) return sendResponse(null);
        const data = await res.json();
        senderCache.set(key, { res: data, ts: Date.now() });
        sendResponse(data);
      } catch {
        sendResponse(null);                         // fail-open: no badge
      }
    })();
    return true;   // async sendResponse
  } else if (msg.type === "GET_TAB_STATE") {
    // E10: the popup shows what live protection did with the current tab.
    sendResponse(tabStates.get(msg.tabId) || null);
  } else if (msg.type === "SCAN_LINK" && msg.url) {
    // E5 hover scan: cache + short timeout via scanUrl; null = no opinion
    // (skipped/whitelisted/unreachable), the content script shows nothing.
    (async () => {
      try {
        if (shouldSkipUrl(msg.url)) return sendResponse(null);
        const host = new URL(msg.url).hostname;
        if (await isWhitelisted(host)) return sendResponse(null);
        const result = await scanUrl(msg.url);
        sendResponse(result ? { verdict: result.verdict, score: result.score } : null);
      } catch {
        sendResponse(null);
      }
    })();
    return true;   // async sendResponse
  }
  return false;
});
