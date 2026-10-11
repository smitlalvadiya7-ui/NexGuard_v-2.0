// NexGuard AI — composer for the "AI image check" ride-along line shown on
// the right-click image result page. Pure logic (node-testable); the engine
// (backend/image_origin.py) is the only source of truth — this only relays.
(() => {
  const TITLES = {
    AI_GENERATED: "AI-generated (confirmed by the file's metadata)",
    LIKELY_AI: "Likely AI-generated",
    LIKELY_REAL: "Likely a real photo",
    UNCERTAIN: "could not tell AI from real for this one",
  };

  function originLine(data) {
    if (!data || !TITLES[data.verdict]) return null;
    const v = data.verdict;
    let line = "🤖 AI image check: " + TITLES[v];
    if (v === "AI_GENERATED" && data.generator) {
      line += " — made with " + data.generator;
    } else if ((v === "LIKELY_AI" || v === "LIKELY_REAL") && data.confidence) {
      line += " (" + data.confidence + "% confidence)";
    }
    return line;
  }

  const api = { originLine };
  if (typeof globalThis !== "undefined") {
    Object.assign(globalThis, api);
  }
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})();
