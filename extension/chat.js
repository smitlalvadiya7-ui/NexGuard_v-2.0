// NexGuard AI — popup chatbot view-model (C4).
//
// Pure logic for the "Ask NexGuard" box in the popup: builds the
// "Is this page safe?" quick question and turns a /support/ask response into
// a small safe-to-render entry (answer text + optional verdict chip). The
// backend bot runs REAL scans on pasted links/messages (C1), so the popup
// only relays what the engine found — it never invents a verdict.
// Loaded via <script src="chat.js"> in the popup; require()-able for tests.
(function () {
  "use strict";

  // Quick action: only real web pages can be scanned; on chrome:// pages and
  // similar the button is hidden instead of sending a junk question.
  function pageQuestion(url) {
    if (!url || typeof url !== "string") return null;
    try {
      const u = new URL(url);
      if (!/^https?:$/.test(u.protocol)) return null;
      return "Is this page safe? " + url;
    } catch {
      return null;
    }
  }

  // /support/ask response -> { text, scan } (scan = null or a chip model).
  function composeChatEntry(response) {
    if (!response || typeof response !== "object" ||
        typeof response.answer !== "string" || !response.answer) {
      return {
        text: "I could not get an answer — check that the backend is running.",
        scan: null,
      };
    }
    let scan = null;
    const s = response.scan;
    if (s && typeof s === "object" && s.verdict) {
      const verdict = String(s.verdict).toUpperCase();
      const known = { SAFE: "safe", SUSPICIOUS: "suspicious", MALICIOUS: "malicious" };
      scan = {
        verdict,
        verdictClass: known[verdict] || "unknown",   // UNKNOWN is never "safe"
        risk: Number(s.risk_score ?? s.score ?? 0) || 0,
      };
    }
    return { text: response.answer, scan };
  }

  // C3 — request body with the last few turns so "scan it again" works.
  // The backend re-validates; this keeps the payload small and well-shaped.
  function chatRequestPayload(question, history) {
    const turns = Array.isArray(history)
      ? history.filter((t) => t && (t.role === "user" || t.role === "bot") &&
                              typeof t.text === "string" && t.text)
               .slice(-6)
               .map((t) => ({ role: t.role, text: t.text.slice(0, 2000) }))
      : [];
    return { question, history: turns };
  }

  const api = { pageQuestion, composeChatEntry, chatRequestPayload };

  if (typeof globalThis !== "undefined") {
    Object.assign(globalThis, api);
  }
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})();
