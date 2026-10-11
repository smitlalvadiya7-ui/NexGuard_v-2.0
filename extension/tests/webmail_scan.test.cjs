// E8 — webmail sender badge. Pure-logic tests for extension/webmail_scan.js,
// run with: node --test extension/tests/webmail_scan.test.cjs
const test = require("node:test");
const assert = require("node:assert");

const webmail = require("../webmail_scan.js");
const { parseAddressText, webmailBadge } = webmail;

// ---------------------------------------------------------------------------
// parseAddressText — pull {name, email} out of arbitrary webmail label text
// ---------------------------------------------------------------------------

test("parses 'Name <address>' labels", () => {
  assert.deepStrictEqual(
    parseAddressText("PayPal <service@paypal.com>"),
    { name: "PayPal", email: "service@paypal.com" }
  );
});

test("parses a bare address", () => {
  assert.deepStrictEqual(
    parseAddressText("service@paypal.com"),
    { name: "", email: "service@paypal.com" }
  );
});

test("parses noisy Outlook-style labels", () => {
  const p = parseAddressText("From: HDFC Bank Alerts hdfc.care@gmail.com — 10:32");
  assert.strictEqual(p.email, "hdfc.care@gmail.com");
  assert.match(p.name, /HDFC Bank Alerts/);
});

test("no address means null", () => {
  assert.strictEqual(parseAddressText("Inbox (42)"), null);
  assert.strictEqual(parseAddressText(""), null);
  assert.strictEqual(parseAddressText(null), null);
});

// ---------------------------------------------------------------------------
// webmailBadge — what each backend status renders as
// ---------------------------------------------------------------------------

test("brand_match renders a green check badge", () => {
  const b = webmailBadge({ status: "brand_match", brand: "paypal", detail: "official domain" });
  assert.ok(b);
  assert.match(b.text, /✓/);
  assert.match(b.text, /paypal/i);
  assert.strictEqual(b.color, "#22C55E");
  assert.strictEqual(b.title, "official domain");
});

test("impersonation renders a red warning badge", () => {
  const b = webmailBadge({ status: "impersonation", brand: "hdfc", detail: "not an hdfc domain" });
  assert.ok(b);
  assert.match(b.text, /⚠/);
  assert.match(b.text, /hdfc/i);
  assert.strictEqual(b.color, "#EF4444");
});

test("none / junk render no badge", () => {
  assert.strictEqual(webmailBadge({ status: "none" }), null);
  assert.strictEqual(webmailBadge(null), null);
  assert.strictEqual(webmailBadge({}), null);
});
