import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { act } from "react";
import { vi } from "vitest";
import { AuthProvider, useAuth } from "../src/auth/AuthContext.jsx";

function mockResponse(status, body) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
    headers: { get: () => "application/json" },
  });
}

function renderUser(user) {
  if (user === null) return "null";
  if (user === "anonymous") return "anonymous";
  return JSON.stringify(user);
}

function Probe() {
  const { user, login, register, logout, skipAuth } = useAuth();
  return (
    <div>
      <div data-testid="user">{renderUser(user)}</div>
      <button onClick={() => login("a@b.com", "secret1")}>login</button>
      <button onClick={() => register("new@x.com", "secret1")}>register</button>
      <button onClick={() => logout()}>logout</button>
      <button onClick={() => skipAuth()}>skip</button>
    </div>
  );
}

function renderProbe() {
  return render(
    <AuthProvider>
      <Probe />
    </AuthProvider>
  );
}

beforeEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
});

test("(a) no stored token -> user is null", () => {
  renderProbe();
  expect(screen.getByTestId("user").textContent).toBe("null");
});

test("(b) login stores token + fields and sets user", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(200, { token: "jwt-1", role: "user", tier: "free", status: "active", email: "a@b.com", id: 1 })
  );
  renderProbe();
  fireEvent.click(screen.getByText("login"));

  await waitFor(() => expect(screen.getByTestId("user").textContent).toContain("a@b.com"));

  expect(localStorage.getItem("nexguard.token")).toBe("jwt-1");
  expect(localStorage.getItem("nexguard.email")).toBe("a@b.com");
  expect(localStorage.getItem("nexguard.role")).toBe("user");
  expect(localStorage.getItem("nexguard.tier")).toBe("free");
});

test("(c) stored token hydrates user from /auth/me on mount", async () => {
  localStorage.setItem("nexguard.token", "jwt-existing");
  global.fetch = vi.fn(() =>
    mockResponse(200, { id: 7, email: "c@d.com", role: "admin", tier: "premium", status: "active" })
  );

  renderProbe();

  await waitFor(() => expect(screen.getByTestId("user").textContent).toContain("c@d.com"));
  expect(global.fetch).toHaveBeenCalled();
  expect(String(global.fetch.mock.calls[0][0])).toContain("/auth/me");
  expect(localStorage.getItem("nexguard.role")).toBe("admin");
  expect(localStorage.getItem("nexguard.tier")).toBe("premium");
});

test("(d) /auth/me 401 on mount clears the stored session", async () => {
  localStorage.setItem("nexguard.token", "jwt-stale");
  localStorage.setItem("nexguard.email", "old@x.com");
  localStorage.setItem("nexguard.role", "user");
  localStorage.setItem("nexguard.tier", "free");
  global.fetch = vi.fn(() => mockResponse(401, { detail: "expired" }));

  renderProbe();

  await waitFor(() => expect(screen.getByTestId("user").textContent).toBe("null"));
  expect(localStorage.getItem("nexguard.token")).toBeNull();
  expect(localStorage.getItem("nexguard.email")).toBeNull();
  expect(localStorage.getItem("nexguard.role")).toBeNull();
  expect(localStorage.getItem("nexguard.tier")).toBeNull();
});

test("(e) skipAuth sets the anonymous user and writes no storage", () => {
  renderProbe();
  fireEvent.click(screen.getByText("skip"));

  expect(screen.getByTestId("user").textContent).toBe("anonymous");
  expect(localStorage.getItem("nexguard.token")).toBeNull();
  expect(localStorage.getItem("nexguard.email")).toBeNull();
  expect(localStorage.getItem("nexguard.role")).toBeNull();
  expect(localStorage.getItem("nexguard.tier")).toBeNull();
});

test("(f) logout clears storage and resets user to null", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(200, { token: "jwt-1", role: "user", tier: "free", status: "active", email: "a@b.com", id: 1 })
  );
  renderProbe();
  fireEvent.click(screen.getByText("login"));
  await waitFor(() => expect(screen.getByTestId("user").textContent).toContain("a@b.com"));

  fireEvent.click(screen.getByText("logout"));

  expect(screen.getByTestId("user").textContent).toBe("null");
  expect(localStorage.getItem("nexguard.token")).toBeNull();
  expect(localStorage.getItem("nexguard.email")).toBeNull();
  expect(localStorage.getItem("nexguard.role")).toBeNull();
  expect(localStorage.getItem("nexguard.tier")).toBeNull();
});

test("(g) register performs register-then-login because /auth/register returns no token", async () => {
  const calledUrls = [];
  global.fetch = vi.fn((url) => {
    calledUrls.push(String(url));
    if (String(url).includes("/auth/register")) {
      return mockResponse(200, { id: 2, email: "new@x.com", role: "user", message: "Account created" });
    }
    return mockResponse(200, {
      token: "jwt-2", role: "user", tier: "free", status: "active", email: "new@x.com", id: 2,
    });
  });

  renderProbe();
  fireEvent.click(screen.getByText("register"));

  await waitFor(() => expect(screen.getByTestId("user").textContent).toContain("new@x.com"));

  expect(calledUrls.some((u) => u.includes("/auth/register"))).toBe(true);
  expect(calledUrls.some((u) => u.includes("/auth/login"))).toBe(true);
  expect(localStorage.getItem("nexguard.token")).toBe("jwt-2");
});

test("(h) stale mount /auth/me must not overwrite a newer login (race guard)", async () => {
  // Stored session for user A -> mount fires GET /auth/me, which we keep
  // pending via a controllable promise.
  localStorage.setItem("nexguard.token", "jwt-A");

  let resolveMe;
  const mePending = new Promise((resolve) => {
    resolveMe = resolve;
  });

  global.fetch = vi.fn((url) => {
    const u = String(url);
    if (u.includes("/auth/me")) return mePending; // A's slow revalidation
    if (u.includes("/auth/login")) {
      return mockResponse(200, {
        token: "jwt-B", role: "admin", tier: "premium", status: "active", email: "b@x.com", id: 2,
      });
    }
    throw new Error(`unexpected fetch: ${u}`);
  });

  renderProbe();
  expect(global.fetch).toHaveBeenCalled();
  expect(String(global.fetch.mock.calls[0][0])).toContain("/auth/me");

  // While A's /auth/me is still in flight, user B completes a login.
  fireEvent.click(screen.getByText("login"));
  await waitFor(() => expect(screen.getByTestId("user").textContent).toContain("b@x.com"));
  expect(localStorage.getItem("nexguard.token")).toBe("jwt-B");

  // Now A's straggling /auth/me resolves. It is stale and must be discarded.
  await act(async () => {
    resolveMe({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ id: 1, email: "a@old.com", role: "user", tier: "free", status: "active" }),
      headers: { get: () => "application/json" },
    });
    // Macrotask flush so every chained microtask (res.json(), state apply)
    // inside apiFetch/refresh has fully settled before we assert.
    await new Promise((resolve) => setTimeout(resolve, 0));
  });

  expect(screen.getByTestId("user").textContent).toContain("b@x.com");
  expect(screen.getByTestId("user").textContent).not.toContain("a@old.com");
  expect(localStorage.getItem("nexguard.email")).toBe("b@x.com");
  expect(localStorage.getItem("nexguard.role")).toBe("admin");
  expect(localStorage.getItem("nexguard.tier")).toBe("premium");
  expect(localStorage.getItem("nexguard.token")).toBe("jwt-B");
});
