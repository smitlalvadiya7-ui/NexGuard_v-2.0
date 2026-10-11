// AI image origin ride-along — pure composer for the result page's 🤖 line.
// Run with: node --test extension/tests/image_origin.test.cjs
const test = require("node:test");
const assert = require("node:assert");

const { originLine } = require("../image_origin_line.js");

test("confirmed AI verdict names the proven generator", () => {
  const line = originLine({
    verdict: "AI_GENERATED", confidence: 100,
    generator: "Midjourney", generator_link: "https://www.midjourney.com",
  });
  assert.ok(line.includes("AI-generated (confirmed"));
  assert.ok(line.includes("Midjourney"));
});

test("likely verdicts show the confidence, never a tool name", () => {
  const ai = originLine({ verdict: "LIKELY_AI", confidence: 91, generator: null });
  assert.ok(ai.includes("Likely AI-generated"));
  assert.ok(ai.includes("91%"));
  const real = originLine({ verdict: "LIKELY_REAL", confidence: 88, generator: null });
  assert.ok(real.includes("Likely a real photo"));
  assert.ok(real.includes("88%"));
});

test("uncertain stays honest and junk returns null", () => {
  const line = originLine({ verdict: "UNCERTAIN", confidence: 0 });
  assert.ok(line.toLowerCase().includes("could not tell"));
  assert.strictEqual(originLine(null), null);
  assert.strictEqual(originLine({}), null);
  assert.strictEqual(originLine({ verdict: "WEIRD" }), null);
});
