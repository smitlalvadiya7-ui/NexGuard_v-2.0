// E10 — visible protection state. Pure-logic tests for extension/tab_state.js,
// run with: node --test extension/tests/tab_state.test.cjs
//
// The complaint this fixes: on a normal page the extension showed NOTHING —
// no way to tell "scanned and safe" from "backend down, nothing scanned".
// Every navigation now leaves a per-tab state; the toolbar badge and the
// popup status strip are both derived from it here.
const test = require("node:test");
const assert = require("node:assert");

const { badgeForState, describeState } = require("../tab_state.js");

// ---------------------------------------------------------------------------
// badgeForState — toolbar badge {text, color, title} per tab state
// ---------------------------------------------------------------------------

test("scanned SAFE gets a green check badge", () => {
  const b = badgeForState({ kind: "scanned", verdict: "SAFE", score: 0 });
  assert.ok(b);
  assert.strictEqual(b.text, "✓");
  assert.match(b.color, /^#/);
  assert.match(b.title, /SAFE/);
});

test("scanned SUSPICIOUS gets an amber badge with the risk score", () => {
  const b = badgeForState({ kind: "scanned", verdict: "SUSPICIOUS", score: 55 });
  assert.ok(b);
  assert.strictEqual(b.text, "!");
  assert.match(b.title, /SUSPICIOUS/);
  assert.match(b.title, /55/);
});

test("scanned MALICIOUS gets a red cross badge", () => {
  const b = badgeForState({ kind: "scanned", verdict: "MALICIOUS", score: 92 });
  assert.ok(b);
  assert.strictEqual(b.text, "✕");
  assert.match(b.title, /MALICIOUS/);
});

test("scanned UNKNOWN is honest — question mark, never a green check", () => {
  const b = badgeForState({ kind: "scanned", verdict: "UNKNOWN", score: 0 });
  assert.ok(b);
  assert.strictEqual(b.text, "?");
  assert.notStrictEqual(b.text, "✓");
});

test("trusted (safe list / whitelist) shows a check but says NOT scanned", () => {
  const b = badgeForState({ kind: "trusted" });
  assert.ok(b);
  assert.strictEqual(b.text, "✓");
  assert.match(b.title, /not scanned/i);
});

test("unreachable backend is VISIBLE — the old silence was the bug", () => {
  const b = badgeForState({ kind: "unreachable" });
  assert.ok(b);
  assert.strictEqual(b.text, "?");
  assert.match(b.title, /backend/i);
});

test("protection off shows OFF", () => {
  const b = badgeForState({ kind: "off" });
  assert.ok(b);
  assert.strictEqual(b.text, "OFF");
});

test("bypassed (Proceed anyway) stays marked", () => {
  const b = badgeForState({ kind: "bypassed" });
  assert.ok(b);
  assert.match(b.title, /proceed/i);
});

test("no state / non-web pages get no badge and never throw", () => {
  assert.strictEqual(badgeForState(null), null);
  assert.strictEqual(badgeForState(undefined), null);
  assert.strictEqual(badgeForState({ kind: "none" }), null);
  assert.strictEqual(badgeForState({ kind: "garbage-kind" }), null);
});

// ---------------------------------------------------------------------------
// describeState — the popup status strip {tone, text}
// ---------------------------------------------------------------------------

test("popup describes a scanned SAFE page", () => {
  const d = describeState({ kind: "scanned", verdict: "SAFE", score: 0 });
  assert.strictEqual(d.tone, "safe");
  assert.match(d.text, /scanned/i);
  assert.match(d.text, /SAFE/);
});

test("popup describes a scanned MALICIOUS page as danger", () => {
  const d = describeState({ kind: "scanned", verdict: "MALICIOUS", score: 88 });
  assert.strictEqual(d.tone, "danger");
  assert.match(d.text, /88/);
});

test("popup is loud when the backend is unreachable", () => {
  const d = describeState({ kind: "unreachable" });
  assert.strictEqual(d.tone, "warn");
  assert.match(d.text, /NOT scanned/i);
  assert.match(d.text, /backend/i);
});

test("popup says why a trusted page was skipped", () => {
  const d = describeState({ kind: "trusted" });
  assert.match(d.text, /trusted/i);
});

test("popup states protection is off", () => {
  const d = describeState({ kind: "off" });
  assert.match(d.text, /off/i);
});

test("popup handles missing state without lying", () => {
  const d = describeState(null);
  assert.strictEqual(d.tone, "muted");
  assert.match(d.text, /not been scanned/i);
  // never claims safety for a page we know nothing about
  assert.doesNotMatch(d.text, /safe/i);
});
