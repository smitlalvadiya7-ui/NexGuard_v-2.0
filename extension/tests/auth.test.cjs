// E2 — extension sign-in. Pure-logic tests for extension/auth.js,
// run with: node --test extension/tests/auth.test.cjs
const test = require("node:test");
const assert = require("node:assert");

const auth = require("../auth.js");
const { getAuthState, getAuthHeaders, signIn, signOut } = auth;

// Minimal chrome.storage.local stub backed by a plain object.
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
        remove: async (keys) => {
          for (const k of Array.isArray(keys) ? keys : [keys]) delete store[k];
        },
      },
    },
  };
  return store;
}

test("getAuthState is signed out when storage is empty", async () => {
  stubStorage();
  const s = await getAuthState();
  assert.strictEqual(s.signedIn, false);
  assert.strictEqual(s.token, null);
});

test("getAuthState returns the stored session", async () => {
  stubStorage({ authToken: "tok123", authEmail: "me@x.com", authTier: "premium" });
  const s = await getAuthState();
  assert.strictEqual(s.signedIn, true);
  assert.strictEqual(s.token, "tok123");
  assert.strictEqual(s.email, "me@x.com");
  assert.strictEqual(s.tier, "premium");
});

test("getAuthState fails safe (signed out) if storage throws", async () => {
  global.chrome = { storage: { local: { get: async () => { throw new Error("no storage"); } } } };
  const s = await getAuthState();
  assert.strictEqual(s.signedIn, false);
});

test("getAuthHeaders is empty when signed out", async () => {
  stubStorage();
  assert.deepStrictEqual(await getAuthHeaders(), {});
});

test("getAuthHeaders carries the Bearer token when signed in", async () => {
  stubStorage({ authToken: "tok123" });
  assert.deepStrictEqual(await getAuthHeaders(), { Authorization: "Bearer tok123" });
});

test("signIn stores token/email/tier and reports ok", async () => {
  const store = stubStorage();
  let calledUrl = null, calledBody = null;
  global.fetch = async (url, opts) => {
    calledUrl = url;
    calledBody = JSON.parse(opts.body);
    return {
      ok: true,
      json: async () => ({ token: "jwt-abc", email: "me@x.com", tier: "free", role: "user" }),
    };
  };
  const r = await signIn("http://127.0.0.1:8000", "me@x.com", "secret1");
  assert.strictEqual(r.ok, true);
  assert.strictEqual(r.email, "me@x.com");
  assert.strictEqual(r.tier, "free");
  assert.strictEqual(calledUrl, "http://127.0.0.1:8000/auth/login");
  assert.deepStrictEqual(calledBody, { email: "me@x.com", password: "secret1" });
  assert.strictEqual(store.authToken, "jwt-abc");
  assert.strictEqual(store.authEmail, "me@x.com");
  assert.strictEqual(store.authTier, "free");
});

test("signIn surfaces the backend's error message and stores nothing", async () => {
  const store = stubStorage();
  global.fetch = async () => ({
    ok: false,
    status: 401,
    json: async () => ({ detail: "Invalid email or password" }),
  });
  const r = await signIn("http://127.0.0.1:8000", "me@x.com", "wrong");
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.error, "Invalid email or password");
  assert.strictEqual(store.authToken, undefined);
});

test("signIn reports a friendly error when the backend is unreachable", async () => {
  stubStorage();
  global.fetch = async () => { throw new Error("ECONNREFUSED"); };
  const r = await signIn("http://127.0.0.1:8000", "me@x.com", "secret1");
  assert.strictEqual(r.ok, false);
  assert.match(r.error, /backend/i);
});

test("signIn rejects empty fields without calling the backend", async () => {
  stubStorage();
  let fetched = false;
  global.fetch = async () => { fetched = true; };
  const r = await signIn("http://127.0.0.1:8000", "", "");
  assert.strictEqual(r.ok, false);
  assert.ok(r.error);
  assert.strictEqual(fetched, false);
});

test("signOut clears the stored session", async () => {
  const store = stubStorage({ authToken: "tok123", authEmail: "me@x.com", authTier: "free" });
  await signOut();
  assert.strictEqual(store.authToken, undefined);
  assert.strictEqual(store.authEmail, undefined);
  assert.strictEqual(store.authTier, undefined);
  const s = await getAuthState();
  assert.strictEqual(s.signedIn, false);
});
