// E1 — configurable backend URL. Pure-logic tests for extension/config.js,
// run with: node --test extension/tests/config.test.cjs
const test = require("node:test");
const assert = require("node:assert");

const config = require("../config.js");
const { NEXGUARD_DEFAULT_BACKEND, normalizeBackendUrl, getBackendUrl, setBackendUrl } = config;

test("default backend is the local dev server", () => {
  assert.strictEqual(NEXGUARD_DEFAULT_BACKEND, "http://127.0.0.1:8000");
});

test("normalizeBackendUrl trims trailing slashes", () => {
  assert.strictEqual(normalizeBackendUrl("http://127.0.0.1:8000/"), "http://127.0.0.1:8000");
  assert.strictEqual(normalizeBackendUrl("https://api.example.com///"), "https://api.example.com");
});

test("normalizeBackendUrl adds http:// when the scheme is missing", () => {
  assert.strictEqual(normalizeBackendUrl("127.0.0.1:8000"), "http://127.0.0.1:8000");
  assert.strictEqual(normalizeBackendUrl("nexguard.example.com"), "http://nexguard.example.com");
});

test("normalizeBackendUrl keeps https", () => {
  assert.strictEqual(normalizeBackendUrl("https://scan.mydomain.com"), "https://scan.mydomain.com");
});

test("normalizeBackendUrl rejects junk / empty", () => {
  assert.strictEqual(normalizeBackendUrl(""), "");
  assert.strictEqual(normalizeBackendUrl("   "), "");
  assert.strictEqual(normalizeBackendUrl("not a real url"), "");
  assert.strictEqual(normalizeBackendUrl(null), "");
  assert.strictEqual(normalizeBackendUrl(42), "");
});

test("getBackendUrl falls back to the default when storage is empty", async () => {
  global.chrome = { storage: { local: { get: async () => ({}) } } };
  assert.strictEqual(await getBackendUrl(), "http://127.0.0.1:8000");
});

test("getBackendUrl returns a normalized stored value", async () => {
  global.chrome = { storage: { local: { get: async () => ({ backendUrl: "https://scan.me/" }) } } };
  assert.strictEqual(await getBackendUrl(), "https://scan.me");
});

test("getBackendUrl fails safe to the default if storage throws", async () => {
  global.chrome = { storage: { local: { get: async () => { throw new Error("no storage"); } } } };
  assert.strictEqual(await getBackendUrl(), "http://127.0.0.1:8000");
});

test("setBackendUrl stores a normalized value and returns it", async () => {
  let saved = null;
  global.chrome = { storage: { local: { set: async (obj) => { saved = obj; } } } };
  const returned = await setBackendUrl("api.example.com/");
  assert.strictEqual(returned, "http://api.example.com");
  assert.deepStrictEqual(saved, { backendUrl: "http://api.example.com" });
});

test("setBackendUrl on junk falls back to the default", async () => {
  let saved = null;
  global.chrome = { storage: { local: { set: async (obj) => { saved = obj; } } } };
  const returned = await setBackendUrl("###");
  assert.strictEqual(returned, "http://127.0.0.1:8000");
  assert.deepStrictEqual(saved, { backendUrl: "http://127.0.0.1:8000" });
});
