// NexGuard AI — webmail inline sender badge (E8).
//
// Runs ONLY on Gmail / Outlook web (see manifest matches). When an opened
// email's sender is visible, the background asks the backend's sender-origin
// engine (POST /verify-sender — local brand-list check, no headers available
// in the DOM) and the sender gets a small badge:
//   ✓ Genuine <brand>   — display name claims a brand AND the domain is official
//   ⚠ Not <brand>       — claims a brand from a NON-official domain
//   (nothing)           — no brand claim, or any error (low noise, fail-open)
// Gmail: span[email] is the long-stable sender element. Outlook: best-effort
// via title/aria-label attributes containing an address.
(function () {
  "use strict";

  const SCAN_DEBOUNCE_MS = 600;

  const EMAIL_RE = /([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24})/;

  // Pull {name, email} out of arbitrary label text ("PayPal <a@b.com>",
  // "From: X y@z.org — 10:32", bare address). null when no address.
  function parseAddressText(text) {
    if (!text || typeof text !== "string") return null;
    const m = EMAIL_RE.exec(text);
    if (!m) return null;
    const email = m[1];
    let name = text.slice(0, m.index)
      .replace(/^\s*from\s*:/i, "")
      .replace(/[<>"'—–:,-]+/g, " ")
      .trim();
    name = name.slice(0, 120);
    return { name, email };
  }

  // Badge spec for a /verify-sender response, or null for no badge.
  function webmailBadge(res) {
    if (!res || typeof res !== "object") return null;
    if (res.status === "brand_match") {
      return {
        text: "✓ Genuine " + (res.brand || "sender"),
        color: "#22C55E",
        title: res.detail || "Sender domain matches the brand it claims.",
      };
    }
    if (res.status === "impersonation") {
      return {
        text: "⚠ Not " + (res.brand || "the claimed brand"),
        color: "#EF4444",
        title: res.detail || "Sender domain does not belong to the brand it claims.",
      };
    }
    return null;
  }

  const api = { parseAddressText, webmailBadge };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;   // Node tests
  }
  if (typeof globalThis !== "undefined") {
    Object.assign(globalThis, api);
  }

  // ── Runtime (webmail pages only) ───────────────────────────────────────────
  if (typeof document === "undefined" || typeof chrome === "undefined" ||
      !chrome.runtime || !chrome.runtime.sendMessage) {
    return;
  }

  (async () => {
    try {
      const { webmailBadges } = await chrome.storage.local.get("webmailBadges");
      if (webmailBadges === false) return;
    } catch {
      /* no storage — stay enabled */
    }

    // email -> "pending" | /verify-sender result. A failed check is stored as
    // {status:"none"} so a dead backend never causes a retry storm; a page
    // reload starts fresh.
    const results = new Map();

    // Sender elements per host. Gmail exposes the address in span[email];
    // Outlook (best-effort) in title / aria-label attributes.
    function senderElements() {
      if (location.hostname === "mail.google.com") {
        return [...document.querySelectorAll("span[email]")].map((el) => ({
          el,
          name: el.getAttribute("name") || el.textContent || "",
          email: el.getAttribute("email") || "",
        }));
      }
      const out = [];
      for (const el of document.querySelectorAll('[title*="@"], [aria-label*="@"]')) {
        const parsed = parseAddressText(
          el.getAttribute("title") || el.getAttribute("aria-label") || ""
        );
        if (parsed) out.push({ el, name: parsed.name || el.textContent || "", email: parsed.email });
      }
      return out;
    }

    function addBadge(el, spec, email) {
      if (!spec || !el.isConnected) return;
      if (el.nextElementSibling &&
          el.nextElementSibling.hasAttribute?.("data-nexguard-sender-badge")) return;
      const span = document.createElement("span");
      span.setAttribute("data-nexguard-sender-badge", email);
      span.textContent = spec.text;
      span.title = spec.title;
      span.style.cssText = [
        "display:inline-block", "margin-left:6px", "padding:0 6px",
        "border-radius:999px", "font-size:11px", "font-weight:700",
        "line-height:16px", "color:#fff", "background:" + spec.color,
        "cursor:help", "vertical-align:middle",
      ].join(";");
      el.insertAdjacentElement("afterend", span);
    }

    function scan() {
      for (const { el, name, email } of senderElements()) {
        if (!email) continue;
        const key = email.toLowerCase();
        const cached = results.get(key);
        if (cached === "pending") continue;
        if (cached) {
          // Same sender in a newly rendered element (e.g. another opened
          // email) — badge it from the cached verdict.
          addBadge(el, webmailBadge(cached), email);
          continue;
        }
        results.set(key, "pending");
        const sender = name ? name + " <" + email + ">" : email;
        chrome.runtime.sendMessage({ type: "SENDER_CHECK", sender }, (res) => {
          if (chrome.runtime.lastError || !res) {
            results.set(key, { status: "none" });   // fail-open, no retry storm
            return;
          }
          results.set(key, res);
          addBadge(el, webmailBadge(res), email);
        });
      }
    }

    let timer = null;
    const observer = new MutationObserver(() => {
      clearTimeout(timer);
      timer = setTimeout(scan, SCAN_DEBOUNCE_MS);
    });
    observer.observe(document.body, { childList: true, subtree: true });
    scan();
  })();
})();
