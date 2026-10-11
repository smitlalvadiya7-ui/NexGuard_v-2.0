// NexGuard AI — right-click scan helpers (E4).
//
// Pure logic behind the context-menu scans: picking a target out of a text
// selection (URL vs message text) and building/parsing the result-page URL
// (result.html) that shows the scan. Loaded in the service worker via
// importScripts and in result.html via <script>; require()-able for tests.
(function () {
  "use strict";

  const TEXT_CAP = 4000;   // selection text sent for message analysis

  const SCHEME_URL_RE = /https?:\/\/[^\s<>"']+/i;
  const WWW_URL_RE = /\bwww\.[^\s<>"']+/i;
  // Bare domain (right-clicking "scan selection" is explicit intent, so no
  // intent-word gating like the support bot).
  const BARE_DOMAIN_RE = /\b[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9-]{1,63})*\.[a-z]{2,24}\b(?:\/[^\s<>"']*)?/i;
  const EMAIL_RE = /\S+@\S+/g;
  const TRAILING_PUNCT = /[.,;:!?)\]}'"]+$/;

  function clean(url) {
    return url.replace(TRAILING_PUNCT, "");
  }

  // First URL in the selected text, or null. Email addresses never match.
  function extractSelectionUrl(text) {
    if (!text || typeof text !== "string") return null;
    let m = SCHEME_URL_RE.exec(text);
    if (m) return clean(m[0]);
    const noEmails = text.replace(EMAIL_RE, " ");
    m = WWW_URL_RE.exec(noEmails);
    if (m) return clean(m[0]);
    m = BARE_DOMAIN_RE.exec(noEmails);
    if (m) return clean(m[0]);
    return null;
  }

  // What to scan for a text selection: the URL inside it, or the text itself
  // as a message. Returns null for an empty selection.
  function selectionTarget(text) {
    if (!text || typeof text !== "string" || !text.trim()) return null;
    const url = extractSelectionUrl(text);
    if (url) return { mode: "url", target: url };
    return { mode: "text", target: text.trim().slice(0, TEXT_CAP) };
  }

  // Extension-relative URL of the result page for a scan.
  function resultPageUrl(mode, target) {
    return "result.html?" + new URLSearchParams({ mode, target }).toString();
  }

  // Parse result.html's query string. Unknown modes fall back to "url".
  function parseResultParams(search) {
    const params = new URLSearchParams(search || "");
    const mode = params.get("mode");
    return {
      mode: mode === "image" || mode === "text" ? mode : "url",
      target: params.get("target") || "",
    };
  }

  const api = { extractSelectionUrl, selectionTarget, resultPageUrl, parseResultParams };

  if (typeof globalThis !== "undefined") {
    Object.assign(globalThis, api);
  }
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})();
