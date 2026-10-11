// E5 — in-page link safety. Pure-logic tests for extension/hover_scan.js,
// run with: node --test extension/tests/hover_scan.test.cjs
const test = require("node:test");
const assert = require("node:assert");

const hover = require("../hover_scan.js");
const { shouldConsiderLink, badgeFor } = hover;

// ---------------------------------------------------------------------------
// shouldConsiderLink — only external web links are worth a hover scan
// ---------------------------------------------------------------------------

test("cross-domain http(s) links qualify", () => {
  assert.strictEqual(shouldConsiderLink("https://evil.tk/login", "news.example.com"), true);
  assert.strictEqual(shouldConsiderLink("http://paypal-verify.top/a", "blog.site.org"), true);
});

test("same-site links are skipped (including subdomains)", () => {
  assert.strictEqual(shouldConsiderLink("https://example.com/page", "example.com"), false);
  assert.strictEqual(shouldConsiderLink("https://sub.example.com/x", "www.example.com"), false);
});

test("non-web schemes and anchors are skipped", () => {
  assert.strictEqual(shouldConsiderLink("mailto:x@y.com", "site.com"), false);
  assert.strictEqual(shouldConsiderLink("javascript:void(0)", "site.com"), false);
  assert.strictEqual(shouldConsiderLink("#section", "site.com"), false);
  assert.strictEqual(shouldConsiderLink("", "site.com"), false);
  assert.strictEqual(shouldConsiderLink(null, "site.com"), false);
});

test("junk URLs never throw", () => {
  assert.strictEqual(shouldConsiderLink("http://", "site.com"), false);
  assert.strictEqual(shouldConsiderLink("not a url", "site.com"), false);
});

// ---------------------------------------------------------------------------
// badgeFor — badge only for risky verdicts; SAFE stays unmarked (low noise)
// ---------------------------------------------------------------------------

test("MALICIOUS gets a red danger badge", () => {
  const b = badgeFor("MALICIOUS", 92);
  assert.ok(b);
  assert.strictEqual(b.char, "✘");
  assert.match(b.title, /MALICIOUS/);
  assert.match(b.title, /92/);
  assert.match(b.color, /^#/);
});

test("SUSPICIOUS gets an amber warning badge", () => {
  const b = badgeFor("SUSPICIOUS", 55);
  assert.ok(b);
  assert.strictEqual(b.char, "⚠");
  assert.match(b.title, /SUSPICIOUS/);
});

test("SAFE / UNKNOWN / missing verdicts get no badge", () => {
  assert.strictEqual(badgeFor("SAFE", 0), null);
  assert.strictEqual(badgeFor("UNKNOWN", 0), null);
  assert.strictEqual(badgeFor(null, 0), null);
  assert.strictEqual(badgeFor(undefined, undefined), null);
});
