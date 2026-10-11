// NexGuard AI — popup result view-model (E3).
//
// Pure logic for the rich popup: turns a raw /scan response into a small,
// safe-to-render model (verdict, confidence, "why this verdict" reasons,
// named sources) plus the "report wrong verdict" payload for POST /feedback.
// Mirrors the web app's ResultPanel wording so both surfaces feel the same.
// Loaded via <script src="popup_render.js"> in the popup; require()-able in
// Node for tests.
(function () {
  "use strict";

  // Same bands as the web app's ResultPanel: >=75 High, >=45 Medium, else Low.
  function confidenceLabel(confidence) {
    if (confidence === null || confidence === undefined || confidence === "") return null;
    if (typeof confidence === "number") {
      const level = confidence >= 75 ? "High" : confidence >= 45 ? "Medium" : "Low";
      return { level, text: level + " confidence · " + Math.round(confidence) + "%" };
    }
    const s = String(confidence);
    return { level: s, text: s + " confidence" };
  }

  // Normalize a /scan response into what the popup renders. Returns null for
  // non-objects; missing fields become safe defaults so rendering never throws.
  function buildResultModel(data) {
    if (!data || typeof data !== "object") return null;

    const verdict = String(data.verdict || "UNKNOWN").toUpperCase();
    const known = { SAFE: "safe", SUSPICIOUS: "suspicious", MALICIOUS: "malicious" };
    // Unknown verdicts render in the caution style — never as "safe".
    const verdictClass = known[verdict] || "suspicious";

    const reasons = Array.isArray(data.flags) && data.flags.length
      ? data.flags
      : Array.isArray(data.reasons) ? data.reasons : [];

    const sources = (Array.isArray(data.sources) ? data.sources : []).map((s) => {
      const flagged = s.status === "flag" || s.status === "warn";
      return {
        name: s.name || "Unknown source",
        text: s.detail || (flagged ? "flagged" : "clean"),
        flagged,
      };
    });

    const conf = confidenceLabel(data.confidence);
    return {
      verdict,
      verdictClass,
      riskScore: Number(data.risk_score ?? data.score ?? 0),
      confidenceText: conf ? conf.text : null,
      summary: data.plain_summary || "",
      reasons,
      sources,
    };
  }

  // Body for POST /feedback ("this verdict is wrong"). The user's label is the
  // opposite of what we predicted: a flagged page is reported as safe, a safe
  // page as malicious.
  function feedbackPayload(data, url) {
    const verdict = String((data && data.verdict) || "UNKNOWN").toUpperCase();
    const wasFlagged = verdict === "MALICIOUS" || verdict === "SUSPICIOUS";
    return {
      scan_url: url,
      module: "Extension",
      predicted_verdict: verdict,
      predicted_score: Number((data && (data.risk_score ?? data.score)) || 0),
      user_label: wasFlagged ? "safe" : "malicious",
    };
  }

  // Friendly message for a non-OK /scan response.
  function scanErrorMessage(status, body) {
    if (status === 429) {
      return (body && body.message) ||
        "Daily free scan limit reached. Sign in or upgrade for more scans.";
    }
    return "Scan failed. Check that the backend is running and try again.";
  }

  const api = { confidenceLabel, buildResultModel, feedbackPayload, scanErrorMessage };

  if (typeof globalThis !== "undefined") {
    Object.assign(globalThis, api);
  }
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})();
