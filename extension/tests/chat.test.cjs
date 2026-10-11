// C4 — chatbot in the popup. Pure-logic tests for extension/chat.js,
// run with: node --test extension/tests/chat.test.cjs
const test = require("node:test");
const assert = require("node:assert");

const chat = require("../chat.js");
const { pageQuestion, composeChatEntry, chatRequestPayload } = chat;

// ---------------------------------------------------------------------------
// chatRequestPayload — C3: question + last few turns for follow-ups
// ---------------------------------------------------------------------------

test("payload carries the question and the last 6 valid turns", () => {
  const history = [];
  for (let i = 0; i < 10; i++) history.push({ role: "user", text: "q" + i });
  history.push({ role: "evil", text: "drop me" });
  history.push({ role: "bot", text: "" });               // empty — dropped
  const p = chatRequestPayload("scan it again", history);
  assert.strictEqual(p.question, "scan it again");
  assert.strictEqual(p.history.length, 6);
  assert.strictEqual(p.history[5].text, "q9");
  assert.ok(!p.history.some((t) => t.role === "evil"));
});

test("payload works without history", () => {
  assert.deepStrictEqual(chatRequestPayload("hi", null),
    { question: "hi", history: [] });
  assert.deepStrictEqual(chatRequestPayload("hi", "junk"),
    { question: "hi", history: [] });
});

// ---------------------------------------------------------------------------
// pageQuestion — the "Is this page safe?" quick action
// ---------------------------------------------------------------------------

test("web pages produce a scan question containing the URL", () => {
  const q = pageQuestion("https://example-shop.top/checkout");
  assert.ok(q);
  assert.match(q, /safe/i);
  assert.ok(q.includes("https://example-shop.top/checkout"));
});

test("non-web pages produce no question (button hidden)", () => {
  assert.strictEqual(pageQuestion("chrome://extensions"), null);
  assert.strictEqual(pageQuestion("about:blank"), null);
  assert.strictEqual(pageQuestion(""), null);
  assert.strictEqual(pageQuestion(null), null);
  assert.strictEqual(pageQuestion("not a url"), null);
});

// ---------------------------------------------------------------------------
// composeChatEntry — /support/ask response -> safe render model
// ---------------------------------------------------------------------------

test("plain FAQ answer becomes a text entry without a scan chip", () => {
  const e = composeChatEntry({ matched: true, answer: "The URL scanner checks…" });
  assert.strictEqual(e.text, "The URL scanner checks…");
  assert.strictEqual(e.scan, null);
});

test("scan answers carry a verdict chip model", () => {
  const e = composeChatEntry({
    matched: true,
    answer: "I ran a full scan on http://x.top.",
    action: "scanned_url",
    scan: { target: "http://x.top", verdict: "MALICIOUS", risk_score: 88, confidence: 80 },
  });
  assert.ok(e.scan);
  assert.strictEqual(e.scan.verdict, "MALICIOUS");
  assert.strictEqual(e.scan.risk, 88);
  assert.strictEqual(e.scan.verdictClass, "malicious");
});

test("UNKNOWN scan chips never render in the safe style", () => {
  const e = composeChatEntry({
    answer: "x", scan: { verdict: "UNKNOWN", risk_score: 0 },
  });
  assert.notStrictEqual(e.scan.verdictClass, "safe");
});

test("junk responses become an honest fallback, never a crash", () => {
  for (const bad of [null, undefined, {}, { answer: "" }, "nope"]) {
    const e = composeChatEntry(bad);
    assert.ok(typeof e.text === "string" && e.text.length > 0);
    assert.strictEqual(e.scan, null);
    assert.match(e.text, /could not|no answer/i);
  }
});

test("scan chip survives missing risk/confidence fields", () => {
  const e = composeChatEntry({ answer: "x", scan: { verdict: "SAFE" } });
  assert.strictEqual(e.scan.risk, 0);
  assert.strictEqual(e.scan.verdictClass, "safe");
});
