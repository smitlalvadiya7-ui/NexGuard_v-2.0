// E3 — rich popup. Pure-logic tests for extension/popup_render.js,
// run with: node --test extension/tests/popup_render.test.cjs
const test = require("node:test");
const assert = require("node:assert");

const render = require("../popup_render.js");
const { confidenceLabel, buildResultModel, feedbackPayload, scanErrorMessage } = render;

// A trimmed real /scan response (free tier) for the happy path.
const FULL = {
  url: "http://paypal-verify.example.tk/login",
  domain: "paypal-verify.example.tk",
  verdict: "MALICIOUS",
  risk_score: 100,
  confidence: 100,
  plain_summary: "Dangerous site — do not enter login or payment details.",
  flags: ["URL uses insecure HTTP", "Possible impersonation: paypal"],
  sources: [
    { name: "VirusTotal", status: "clean" },
    { name: "Community Blocklist", status: "flag", detail: "listed" },
  ],
};

test("confidenceLabel maps bands like the web app", () => {
  assert.deepStrictEqual(confidenceLabel(100), { level: "High", text: "High confidence · 100%" });
  assert.deepStrictEqual(confidenceLabel(50), { level: "Medium", text: "Medium confidence · 50%" });
  assert.deepStrictEqual(confidenceLabel(10), { level: "Low", text: "Low confidence · 10%" });
  assert.strictEqual(confidenceLabel(null), null);
  assert.strictEqual(confidenceLabel(undefined), null);
});

test("buildResultModel maps a full scan result", () => {
  const m = buildResultModel(FULL);
  assert.strictEqual(m.verdict, "MALICIOUS");
  assert.strictEqual(m.verdictClass, "malicious");
  assert.strictEqual(m.riskScore, 100);
  assert.strictEqual(m.confidenceText, "High confidence · 100%");
  assert.strictEqual(m.summary, "Dangerous site — do not enter login or payment details.");
  assert.deepStrictEqual(m.reasons, FULL.flags);
  assert.strictEqual(m.sources.length, 2);
  assert.deepStrictEqual(m.sources[0], { name: "VirusTotal", text: "clean", flagged: false });
  assert.deepStrictEqual(m.sources[1],
    { name: "Community Blocklist", text: "listed", flagged: true });
});

test("buildResultModel survives a minimal/legacy result", () => {
  const m = buildResultModel({ verdict: "SAFE", risk_score: 0 });
  assert.strictEqual(m.verdict, "SAFE");
  assert.strictEqual(m.verdictClass, "safe");
  assert.strictEqual(m.riskScore, 0);
  assert.strictEqual(m.confidenceText, null);
  assert.strictEqual(m.summary, "");
  assert.deepStrictEqual(m.reasons, []);
  assert.deepStrictEqual(m.sources, []);
});

test("buildResultModel falls back to reasons when flags are missing", () => {
  const m = buildResultModel({ verdict: "SUSPICIOUS", reasons: ["odd TLD"] });
  assert.strictEqual(m.verdictClass, "suspicious");
  assert.deepStrictEqual(m.reasons, ["odd TLD"]);
});

test("buildResultModel never throws on junk", () => {
  assert.strictEqual(buildResultModel(null), null);
  assert.strictEqual(buildResultModel("nope"), null);
  const m = buildResultModel({});
  assert.strictEqual(m.verdict, "UNKNOWN");
  assert.strictEqual(m.verdictClass, "suspicious"); // unknown renders as caution, not safe
});

test("feedbackPayload flips MALICIOUS/SUSPICIOUS to a 'safe' report", () => {
  const p = feedbackPayload(FULL, "http://paypal-verify.example.tk/login");
  assert.deepStrictEqual(p, {
    scan_url: "http://paypal-verify.example.tk/login",
    module: "Extension",
    predicted_verdict: "MALICIOUS",
    predicted_score: 100,
    user_label: "safe",
  });
});

test("feedbackPayload flips SAFE to a 'malicious' report", () => {
  const p = feedbackPayload({ verdict: "SAFE", risk_score: 0 }, "https://example.com");
  assert.strictEqual(p.user_label, "malicious");
  assert.strictEqual(p.predicted_verdict, "SAFE");
  assert.strictEqual(p.predicted_score, 0);
});

test("scanErrorMessage explains the free daily limit (429)", () => {
  const msg = scanErrorMessage(429, { error: "free_limit", message: "Daily free scan limit reached. Upgrade to Premium for unlimited scans." });
  assert.match(msg, /limit/i);
});

test("scanErrorMessage falls back to a generic error", () => {
  assert.match(scanErrorMessage(500, {}), /failed|error/i);
  assert.match(scanErrorMessage(0, null), /failed|error/i);
});
