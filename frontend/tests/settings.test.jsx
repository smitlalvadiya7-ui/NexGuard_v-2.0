import { render, screen, fireEvent, act } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import Settings from "../src/pages/Settings/index.jsx";
import { ToastProvider } from "../src/components/Toast.jsx";
import { API_BASE } from "../src/api.js";

let mockUser = null;
vi.mock("../src/auth/AuthContext.jsx", () => ({
  useAuth: () => ({ user: mockUser, refresh: vi.fn() }),
}));

function mockResponse(status, body) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
    headers: { get: () => "application/json" },
  });
}

const existingKeys = [
  {
    id: 3,
    label: "my-bot",
    prefix: "ngk_abc12345",
    tier: "free",
    active: true,
    created_at: "2026-07-10T10:00:00",
    last_used: null,
    request_count: 7,
  },
];

function routeFetch({ billingEnabled = false, keys = existingKeys } = {}) {
  return vi.fn((url, opts = {}) => {
    const u = String(url);
    const method = opts.method || "GET";
    if (u.endsWith("/billing/config")) {
      return mockResponse(200, {
        enabled: billingEnabled,
        publishable_key: billingEnabled ? "pk_test_x" : "",
        webhook_configured: billingEnabled,
      });
    }
    if (u.endsWith("/billing/create-checkout-session")) {
      return mockResponse(200, { url: "https://checkout.stripe.example/session" });
    }
    if (u.endsWith("/requests/upgrade")) {
      return mockResponse(200, { id: 9, type: "upgrade", status: "pending" });
    }
    if (u.endsWith("/api-keys") && method === "GET") return mockResponse(200, keys);
    if (u.endsWith("/api-keys") && method === "POST") {
      return mockResponse(200, {
        id: 4,
        label: "production",
        prefix: "ngk_new55555",
        tier: "free",
        active: true,
        created_at: "2026-07-15T12:00:00",
        last_used: null,
        request_count: 0,
        key: "ngk_new55555_FULLSECRETONCE",
      });
    }
    if (u.endsWith("/api-keys/3/revoke")) {
      return mockResponse(200, { ...keys[0], active: false });
    }
    return mockResponse(404, { detail: "unexpected " + u + " " + method });
  });
}

async function renderSettings() {
  await act(async () => {
    render(
      <ToastProvider>
        <MemoryRouter>
          <Settings />
        </MemoryRouter>
      </ToastProvider>
    );
  });
}

beforeEach(() => {
  vi.restoreAllMocks();
  mockUser = { email: "user@example.com", role: "user", tier: "free" };
});

test("shows account fields and the free-tier explanation", async () => {
  global.fetch = routeFetch();
  await renderSettings();

  expect(screen.getByText("user@example.com")).toBeInTheDocument();
  expect(screen.getAllByText(/free/i).length).toBeGreaterThanOrEqual(1);
  expect(screen.getByText(/10 scans per day/i)).toBeInTheDocument();
});

test("creating a key reveals the secret exactly once with a copy notice", async () => {
  global.fetch = routeFetch();
  await renderSettings();

  fireEvent.change(screen.getByPlaceholderText(/label/i), { target: { value: "production" } });
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /generate key/i }));
  });

  expect(screen.getByText("ngk_new55555_FULLSECRETONCE")).toBeInTheDocument();
  expect(screen.getByText(/won't be shown again/i)).toBeInTheDocument();

  const postCall = global.fetch.mock.calls.find(
    ([u, o]) => String(u).endsWith("/api-keys") && o?.method === "POST"
  );
  expect(postCall[1].body).toBe(JSON.stringify({ label: "production" }));
});

test("revoking a key posts to /api-keys/{id}/revoke", async () => {
  global.fetch = routeFetch();
  await renderSettings();

  expect(screen.getByText("my-bot")).toBeInTheDocument();
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /revoke/i }));
  });

  const revokeCall = global.fetch.mock.calls.find(([u]) => String(u).includes("/revoke"));
  expect(revokeCall).toBeTruthy();
  expect(revokeCall[0]).toBe(API_BASE + "/api-keys/3/revoke");
  expect(revokeCall[1].method).toBe("POST");
});

test("request-premium posts to /requests/upgrade", async () => {
  global.fetch = routeFetch();
  await renderSettings();

  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /request premium/i }));
  });

  const call = global.fetch.mock.calls.find(([u]) => String(u).endsWith("/requests/upgrade"));
  expect(call).toBeTruthy();
  expect(call[1].method).toBe("POST");
});

test("the card-upgrade button shows only when Stripe is enabled and redirects to checkout", async () => {
  global.fetch = routeFetch({ billingEnabled: true });
  const assignSpy = vi.fn();
  vi.stubGlobal("location", { ...window.location, assign: assignSpy });
  await renderSettings();

  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /upgrade with card/i }));
  });

  const call = global.fetch.mock.calls.find(([u]) =>
    String(u).endsWith("/billing/create-checkout-session")
  );
  expect(call).toBeTruthy();
  expect(assignSpy).toHaveBeenCalledWith("https://checkout.stripe.example/session");
  vi.unstubAllGlobals();
});

test("no card-upgrade button when Stripe is disabled", async () => {
  global.fetch = routeFetch({ billingEnabled: false });
  await renderSettings();

  expect(screen.queryByRole("button", { name: /upgrade with card/i })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: /request premium/i })).toBeInTheDocument();
});

test("premium users see no upgrade controls", async () => {
  mockUser = { email: "vip@example.com", role: "user", tier: "premium" };
  global.fetch = routeFetch({ billingEnabled: true });
  await renderSettings();

  expect(screen.queryByRole("button", { name: /upgrade with card/i })).not.toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /request premium/i })).not.toBeInTheDocument();
});
