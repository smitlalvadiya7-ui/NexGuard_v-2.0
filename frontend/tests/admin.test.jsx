import { render, screen, fireEvent, act, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import Admin from "../src/pages/Admin/index.jsx";
import { ToastProvider } from "../src/components/Toast.jsx";
import { API_BASE } from "../src/api.js";

let mockUser = null;
vi.mock("../src/auth/AuthContext.jsx", () => ({
  useAuth: () => ({ user: mockUser }),
}));

function mockResponse(status, body) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
    headers: { get: () => "application/json" },
  });
}

const users = [
  {
    id: 1,
    email: "root@nexguard.local",
    role: "superadmin",
    tier: "premium",
    status: "active",
    daily_scan_count: 0,
    created_at: "2026-01-01T00:00:00",
    total_scans: 10,
  },
  {
    id: 7,
    email: "member@example.com",
    role: "user",
    tier: "free",
    status: "active",
    daily_scan_count: 3,
    created_at: "2026-06-01T00:00:00",
    total_scans: 42,
  },
];

const requests = [
  {
    id: 2,
    type: "upgrade",
    requester_user_id: 7,
    requester_email: "member@example.com",
    status: "pending",
    created_at: "2026-07-15T10:00:00",
    decided_by: null,
    decided_at: null,
    note: "",
  },
];

const feedback = [
  {
    id: 4,
    url: "https://misjudged.example",
    module: "URL Scanner",
    predicted_verdict: "SAFE",
    predicted_score: 5,
    user_label: "malicious",
    status: "pending",
    reporter_email: "member@example.com",
    created_at: "2026-07-15T09:00:00",
  },
];

const adminStats = {
  total_users: 5,
  users_by_role: { user: 3, admin: 1, superadmin: 1 },
  users_by_tier: { free: 3, premium: 2 },
  users_by_status: { active: 5 },
  total_scans: 300,
  threats_detected: 120,
  pending_requests: 1,
};

const audit = [
  {
    id: 9,
    action: "set_tier",
    actor_user_id: 1,
    actor_email: "root@nexguard.local",
    target_user_id: 7,
    detail: "tier=premium",
    created_at: "2026-07-14T08:00:00",
  },
];

function routeFetch() {
  return vi.fn((url, opts = {}) => {
    const u = String(url);
    const method = opts.method || "GET";
    if (u.includes("/admin/users") && method === "GET") return mockResponse(200, users);
    if (u.includes("/admin/users/7/")) return mockResponse(200, { ...users[1] });
    if (u.includes("/admin/requests")) return mockResponse(200, requests);
    if (u.includes("/requests/2/")) return mockResponse(200, { ...requests[0], status: "approved" });
    if (u.includes("/admin/feedback/4/review")) return mockResponse(200, { ...feedback[0], status: "accepted" });
    if (u.includes("/admin/feedback")) return mockResponse(200, feedback);
    if (u.includes("/admin/stats")) return mockResponse(200, adminStats);
    if (u.includes("/superadmin/audit")) return mockResponse(200, audit);
    return mockResponse(404, { detail: "unexpected " + u + " " + method });
  });
}

async function renderAdmin(entries = ["/admin"]) {
  await act(async () => {
    render(
      <ToastProvider>
        <MemoryRouter initialEntries={entries}>
          <Admin />
        </MemoryRouter>
      </ToastProvider>
    );
  });
}

beforeEach(() => {
  vi.restoreAllMocks();
  mockUser = { email: "root@nexguard.local", role: "superadmin", tier: "premium" };
});

test("users table renders and a tier change posts to /admin/users/{id}/tier", async () => {
  global.fetch = routeFetch();
  await renderAdmin();

  expect(screen.getByText("member@example.com")).toBeInTheDocument();
  expect(screen.getByText("root@nexguard.local")).toBeInTheDocument();

  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /make premium/i }));
  });

  const call = global.fetch.mock.calls.find(([u]) => String(u).includes("/admin/users/7/tier"));
  expect(call).toBeTruthy();
  expect(call[0]).toBe(API_BASE + "/admin/users/7/tier");
  expect(call[1].method).toBe("POST");
  expect(call[1].body).toBe(JSON.stringify({ tier: "premium" }));
});

test("a superadmin can change roles via /admin/users/{id}/role", async () => {
  global.fetch = routeFetch();
  await renderAdmin();

  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /make admin/i }));
  });

  const call = global.fetch.mock.calls.find(([u]) => String(u).includes("/admin/users/7/role"));
  expect(call).toBeTruthy();
  expect(call[1].body).toBe(JSON.stringify({ role: "admin" }));
});

test("an admin (not superadmin) sees no role controls and no audit tab", async () => {
  mockUser = { email: "admin@example.com", role: "admin", tier: "premium" };
  global.fetch = routeFetch();
  await renderAdmin();

  expect(screen.queryByRole("button", { name: /make admin/i })).not.toBeInTheDocument();
  expect(screen.queryByRole("tab", { name: /audit/i })).not.toBeInTheDocument();
});

test("suspend requires an inline confirm before posting", async () => {
  global.fetch = routeFetch();
  await renderAdmin();

  const row = screen.getByText("member@example.com").closest("tr");
  await act(async () => {
    fireEvent.click(within(row).getByRole("button", { name: /^suspend$/i }));
  });
  // no POST yet — confirm step is showing
  expect(global.fetch.mock.calls.find(([u]) => String(u).includes("/suspend"))).toBeFalsy();

  await act(async () => {
    fireEvent.click(within(row).getByRole("button", { name: /confirm/i }));
  });
  const call = global.fetch.mock.calls.find(([u]) => String(u).includes("/admin/users/7/suspend"));
  expect(call).toBeTruthy();
  expect(call[1].method).toBe("POST");
});

test("requests tab lists pending requests and approve posts the decision", async () => {
  global.fetch = routeFetch();
  await renderAdmin(["/admin?tab=requests"]);

  expect(screen.getByText("member@example.com")).toBeInTheDocument();
  expect(screen.getByText(/upgrade/i)).toBeInTheDocument();

  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /approve/i }));
  });

  const call = global.fetch.mock.calls.find(([u]) => String(u).includes("/requests/2/approve"));
  expect(call).toBeTruthy();
  expect(call[1].method).toBe("POST");
});

test("feedback tab reviews a reported verdict", async () => {
  global.fetch = routeFetch();
  await renderAdmin(["/admin?tab=feedback"]);

  expect(screen.getByText("https://misjudged.example")).toBeInTheDocument();

  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /accept/i }));
  });

  const call = global.fetch.mock.calls.find(([u]) =>
    String(u).includes("/admin/feedback/4/review")
  );
  expect(call).toBeTruthy();
  expect(JSON.parse(call[1].body)).toMatchObject({ decision: "accepted" });
});

test("stats tab renders platform totals", async () => {
  global.fetch = routeFetch();
  await renderAdmin(["/admin?tab=stats"]);

  expect(screen.getByText(/total users/i)).toBeInTheDocument();
  expect(screen.getByText("300")).toBeInTheDocument();
  expect(screen.getByText("120")).toBeInTheDocument();
});

test("audit tab renders for superadmins", async () => {
  global.fetch = routeFetch();
  await renderAdmin(["/admin?tab=audit"]);

  expect(screen.getByText("set_tier")).toBeInTheDocument();
  expect(screen.getByText(/tier=premium/)).toBeInTheDocument();
});
