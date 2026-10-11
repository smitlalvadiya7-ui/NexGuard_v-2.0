// E6 — options/settings. Pure-logic tests for extension/settings.js,
// run with: node --test extension/tests/settings.test.cjs
const test = require("node:test");
const assert = require("node:assert");

const settings = require("../settings.js");
const {
  DEFAULT_PROTECTION_LEVEL,
  getSettings,
  setProtectionLevel,
  setHoverScan,
  setWebmailBadges,
  normalizeHost,
  getWhitelist,
  addToWhitelist,
  removeFromWhitelist,
  navDecision,
} = settings;

function stubStorage(initial = {}) {
  const store = { ...initial };
  global.chrome = {
    storage: {
      local: {
        get: async (keys) => {
          const wanted = Array.isArray(keys) ? keys : [keys];
          const out = {};
          for (const k of wanted) if (k in store) out[k] = store[k];
          return out;
        },
        set: async (obj) => Object.assign(store, obj),
      },
    },
  };
  return store;
}

// ---------------------------------------------------------------------------
// Settings read/write
// ---------------------------------------------------------------------------

test("defaults: protection block, hover scan on, webmail badges on", async () => {
  stubStorage();
  assert.deepStrictEqual(await getSettings(), {
    protectionLevel: "block", hoverScan: true, webmailBadges: true,
    blockSuspiciousAt: 60,
  });
  assert.strictEqual(DEFAULT_PROTECTION_LEVEL, "block");
});

test("stored values are returned", async () => {
  stubStorage({ protectionLevel: "warn", hoverScan: false, webmailBadges: false,
                blockSuspiciousAt: 45 });
  assert.deepStrictEqual(await getSettings(), {
    protectionLevel: "warn", hoverScan: false, webmailBadges: false,
    blockSuspiciousAt: 45,
  });
});

// ---------------------------------------------------------------------------
// M6 — per-surface block threshold (extension tuned separately from web app)
// ---------------------------------------------------------------------------

test("block threshold clamps to 40–90 and rejects junk", async () => {
  const { setBlockSuspiciousAt } = settings;
  stubStorage();
  assert.strictEqual(await setBlockSuspiciousAt(45), 45);
  assert.strictEqual((await getSettings()).blockSuspiciousAt, 45);
  assert.strictEqual(await setBlockSuspiciousAt(10), 40);    // too aggressive
  assert.strictEqual(await setBlockSuspiciousAt(99), 90);    // too permissive
  assert.strictEqual(await setBlockSuspiciousAt("junk"), 60);  // default
  assert.strictEqual(await setBlockSuspiciousAt(72.6), 73);  // integers only
});

test("junk stored threshold falls back to the default", async () => {
  stubStorage({ blockSuspiciousAt: "evil" });
  assert.strictEqual((await getSettings()).blockSuspiciousAt, 60);
  stubStorage({ blockSuspiciousAt: 500 });
  assert.strictEqual((await getSettings()).blockSuspiciousAt, 60);
});

test("navDecision honors a custom threshold", () => {
  // stricter: a SUSPICIOUS 55 blocks at threshold 50 but not at 60
  assert.strictEqual(navDecision("block", "SUSPICIOUS", 55, 50), "block");
  assert.strictEqual(navDecision("block", "SUSPICIOUS", 55, 60), "warnbar");
  // more relaxed: 75 only warns at threshold 80; MALICIOUS always blocks
  assert.strictEqual(navDecision("block", "SUSPICIOUS", 75, 80), "warnbar");
  assert.strictEqual(navDecision("block", "MALICIOUS", 10, 80), "block");
});

test("junk stored level falls back to block", async () => {
  stubStorage({ protectionLevel: "yolo" });
  assert.strictEqual((await getSettings()).protectionLevel, "block");
});

test("getSettings fails safe when storage throws", async () => {
  global.chrome = { storage: { local: { get: async () => { throw new Error("boom"); } } } };
  assert.deepStrictEqual(await getSettings(), {
    protectionLevel: "block", hoverScan: true, webmailBadges: true,
    blockSuspiciousAt: 60,
  });
});

test("setWebmailBadges stores a boolean (E8)", async () => {
  const store = stubStorage();
  await setWebmailBadges(false);
  assert.strictEqual(store.webmailBadges, false);
  await setWebmailBadges(1);
  assert.strictEqual(store.webmailBadges, true);
});

test("setProtectionLevel stores valid levels and rejects junk", async () => {
  const store = stubStorage();
  assert.strictEqual(await setProtectionLevel("warn"), "warn");
  assert.strictEqual(store.protectionLevel, "warn");
  assert.strictEqual(await setProtectionLevel("nonsense"), "block");
  assert.strictEqual(store.protectionLevel, "block");
});

test("setHoverScan stores a boolean", async () => {
  const store = stubStorage();
  await setHoverScan(false);
  assert.strictEqual(store.hoverScan, false);
  await setHoverScan("truthy");
  assert.strictEqual(store.hoverScan, true);
});

// ---------------------------------------------------------------------------
// Whitelist manager
// ---------------------------------------------------------------------------

test("normalizeHost cleans URLs and hostnames", () => {
  assert.strictEqual(normalizeHost("https://Example.COM/path?q=1"), "example.com");
  assert.strictEqual(normalizeHost("  sub.Site.org  "), "sub.site.org");
  assert.strictEqual(normalizeHost("www.shop.com"), "www.shop.com");
  assert.strictEqual(normalizeHost(""), "");
  assert.strictEqual(normalizeHost("not a host"), "");
  assert.strictEqual(normalizeHost(null), "");
});

test("addToWhitelist normalizes, dedupes and returns the list", async () => {
  const store = stubStorage({ whitelist: ["existing.com"] });
  const list = await addToWhitelist("https://New-Site.com/login");
  assert.deepStrictEqual(list, ["existing.com", "new-site.com"]);
  assert.deepStrictEqual(store.whitelist, ["existing.com", "new-site.com"]);
  // duplicate is a no-op
  assert.deepStrictEqual(await addToWhitelist("new-site.com"), ["existing.com", "new-site.com"]);
  // junk is a no-op
  assert.deepStrictEqual(await addToWhitelist("###"), ["existing.com", "new-site.com"]);
});

test("removeFromWhitelist removes and returns the list", async () => {
  const store = stubStorage({ whitelist: ["a.com", "b.com"] });
  assert.deepStrictEqual(await removeFromWhitelist("a.com"), ["b.com"]);
  assert.deepStrictEqual(store.whitelist, ["b.com"]);
});

test("getWhitelist is [] when empty or storage broken", async () => {
  stubStorage();
  assert.deepStrictEqual(await getWhitelist(), []);
  global.chrome = { storage: { local: { get: async () => { throw new Error("x"); } } } };
  assert.deepStrictEqual(await getWhitelist(), []);
});

// ---------------------------------------------------------------------------
// navDecision — what the background does with a scan result per level
// ---------------------------------------------------------------------------

test("level off never blocks or warns", () => {
  assert.strictEqual(navDecision("off", "MALICIOUS", 100, 60), "none");
});

test("level block: malicious and high-suspicious block, low-suspicious warns", () => {
  assert.strictEqual(navDecision("block", "MALICIOUS", 95, 60), "block");
  assert.strictEqual(navDecision("block", "SUSPICIOUS", 65, 60), "block");
  assert.strictEqual(navDecision("block", "SUSPICIOUS", 45, 60), "warnbar");
  assert.strictEqual(navDecision("block", "SAFE", 0, 60), "none");
});

test("level warn: everything risky becomes the warning bar, never a block", () => {
  assert.strictEqual(navDecision("warn", "MALICIOUS", 95, 60), "warnbar");
  assert.strictEqual(navDecision("warn", "SUSPICIOUS", 65, 60), "warnbar");
  assert.strictEqual(navDecision("warn", "SUSPICIOUS", 45, 60), "warnbar");
  assert.strictEqual(navDecision("warn", "SAFE", 0, 60), "none");
});

test("navDecision treats junk level as block (protective default)", () => {
  assert.strictEqual(navDecision("weird", "MALICIOUS", 95, 60), "block");
});
