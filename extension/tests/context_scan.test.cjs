// E4 — right-click scans. Pure-logic tests for extension/context_scan.js,
// run with: node --test extension/tests/context_scan.test.cjs
const test = require("node:test");
const assert = require("node:assert");

const ctx = require("../context_scan.js");
const { extractSelectionUrl, selectionTarget, resultPageUrl, parseResultParams } = ctx;

// ---------------------------------------------------------------------------
// extractSelectionUrl — right-click on a selection IS explicit scan intent,
// so bare domains count too (unlike the support bot's intent gating).
// ---------------------------------------------------------------------------

test("extractSelectionUrl finds scheme and www URLs", () => {
  assert.strictEqual(extractSelectionUrl("check https://evil.tk/login now"), "https://evil.tk/login");
  assert.strictEqual(extractSelectionUrl("go to www.free-prizes.club!"), "www.free-prizes.club");
});

test("extractSelectionUrl finds bare domains", () => {
  assert.strictEqual(extractSelectionUrl("visit paypal-verify.tk today"), "paypal-verify.tk");
  assert.strictEqual(extractSelectionUrl("bit.ly/x7 is the link"), "bit.ly/x7");
});

test("extractSelectionUrl strips trailing punctuation", () => {
  assert.strictEqual(extractSelectionUrl("see https://evil.tk/a."), "https://evil.tk/a");
});

test("extractSelectionUrl ignores email addresses and plain text", () => {
  assert.strictEqual(extractSelectionUrl("mail me at me@example.com please"), null);
  assert.strictEqual(extractSelectionUrl("your account will be suspended"), null);
  assert.strictEqual(extractSelectionUrl(""), null);
  assert.strictEqual(extractSelectionUrl(null), null);
});

// ---------------------------------------------------------------------------
// selectionTarget
// ---------------------------------------------------------------------------

test("selectionTarget prefers a URL in the selection", () => {
  assert.deepStrictEqual(
    selectionTarget("is https://evil.tk/login safe?"),
    { mode: "url", target: "https://evil.tk/login" }
  );
});

test("selectionTarget falls back to text mode", () => {
  const t = selectionTarget("Dear customer verify your OTP immediately");
  assert.strictEqual(t.mode, "text");
  assert.strictEqual(t.target, "Dear customer verify your OTP immediately");
});

test("selectionTarget trims and caps very long text", () => {
  const t = selectionTarget("  " + "word ".repeat(2000));
  assert.strictEqual(t.mode, "text");
  assert.ok(t.target.length <= 4000);
  assert.ok(!t.target.startsWith(" "));
});

test("selectionTarget on empty selection is null", () => {
  assert.strictEqual(selectionTarget(""), null);
  assert.strictEqual(selectionTarget("   "), null);
  assert.strictEqual(selectionTarget(null), null);
});

// ---------------------------------------------------------------------------
// result page URL round-trip
// ---------------------------------------------------------------------------

test("resultPageUrl encodes the target", () => {
  const u = resultPageUrl("url", "https://evil.tk/a?b=c&d=e");
  assert.ok(u.startsWith("result.html?"));
  assert.ok(u.includes("mode=url"));
  assert.ok(!u.includes("b=c&d=e"));           // must be percent-encoded
});

test("parseResultParams round-trips resultPageUrl", () => {
  const target = "https://evil.tk/a?b=c&d=e";
  const u = resultPageUrl("image", target);
  const qs = u.slice(u.indexOf("?"));
  assert.deepStrictEqual(parseResultParams(qs), { mode: "image", target });
});

test("parseResultParams is safe on junk", () => {
  assert.deepStrictEqual(parseResultParams(""), { mode: "url", target: "" });
  assert.deepStrictEqual(parseResultParams("?mode=weird"), { mode: "url", target: "" });
  const p = parseResultParams("?mode=text&target=hello%20there");
  assert.deepStrictEqual(p, { mode: "text", target: "hello there" });
});
