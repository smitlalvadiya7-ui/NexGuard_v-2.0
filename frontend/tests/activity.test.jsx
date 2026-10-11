import { render, screen, fireEvent, act } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import Activity from "../src/pages/Activity/index.jsx";
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

const historyRows = [
  {
    id: 11,
    module: "URL Scanner",
    verdict: "MALICIOUS",
    score: 92,
    target: "https://evil.example/login",
    summary: "Known phishing kit",
    timestamp: "2026-07-15T09:30:00",
  },
  {
    id: 12,
    module: "QR Scanner",
    verdict: "SAFE",
    score: 2,
    target: "https://ok.example",
    summary: "Looks safe.",
    timestamp: "2026-07-15T08:00:00",
  },
];

const watchRows = [
  {
    id: 5,
    target: "watched.example",
    created_at: "2026-07-10T12:00:00",
    last_checked: "2026-07-14T12:00:00",
    last_verdict: "SAFE",
    last_score: 3,
  },
];

async function renderActivity(entries = ["/activity"]) {
  await act(async () => {
    render(
      <ToastProvider>
        <MemoryRouter initialEntries={entries}>
          <Activity />
        </MemoryRouter>
      </ToastProvider>
    );
  });
}

beforeEach(() => {
  vi.restoreAllMocks();
  mockUser = { email: "p@example.com", role: "user", tier: "premium" };
});

// ---------------------------------------------------------------------------
// (a) History
// ---------------------------------------------------------------------------
test("(a) history renders rows and rescan posts to /history/{id}/rescan", async () => {
  global.fetch = vi.fn((url, opts = {}) => {
    const u = String(url);
    if (u.includes("/history/11/rescan")) {
      return mockResponse(200, { verdict: "SUSPICIOUS", risk_score: 55 });
    }
    if (u.includes("/history")) return mockResponse(200, historyRows);
    return mockResponse(404, { detail: "unexpected " + u + " " + (opts.method || "GET") });
  });
  await renderActivity();

  expect(screen.getByText("https://evil.example/login")).toBeInTheDocument();
  expect(screen.getByText("https://ok.example")).toBeInTheDocument();
  // "Malicious" also appears as a verdict-filter <option>; the badge is the 2nd
  expect(screen.getAllByText(/^malicious$/i).length).toBeGreaterThanOrEqual(2);

  const rescanButtons = screen.getAllByRole("button", { name: /re-scan/i });
  await act(async () => {
    fireEvent.click(rescanButtons[0]);
  });

  const rescanCall = global.fetch.mock.calls.find(([u]) => String(u).includes("/rescan"));
  expect(rescanCall).toBeTruthy();
  expect(rescanCall[0]).toBe(API_BASE + "/history/11/rescan");
  expect(rescanCall[1].method).toBe("POST");
});

test("history filters are sent as query params", async () => {
  global.fetch = vi.fn(() => mockResponse(200, []));
  await renderActivity();

  fireEvent.change(screen.getByPlaceholderText(/search url or verdict/i), {
    target: { value: "evil" },
  });
  fireEvent.change(screen.getByLabelText(/verdict filter/i), { target: { value: "MALICIOUS" } });
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /^search$/i }));
  });

  const lastCall = String(global.fetch.mock.calls.at(-1)[0]);
  expect(lastCall).toContain("/history?");
  expect(lastCall).toContain("q=evil");
  expect(lastCall).toContain("verdict=MALICIOUS");
});

// ---------------------------------------------------------------------------
// (b) Watchlist add / remove
// ---------------------------------------------------------------------------
test("(b) watchlist add and remove call the right endpoints", async () => {
  global.fetch = vi.fn((url, opts = {}) => {
    const u = String(url);
    const method = opts.method || "GET";
    if (u.endsWith("/watchlist") && method === "GET") return mockResponse(200, watchRows);
    if (u.endsWith("/watchlist") && method === "POST") {
      return mockResponse(200, {
        id: 6,
        target: "new.example",
        created_at: "2026-07-15T12:00:00",
        last_checked: null,
        last_verdict: null,
        last_score: null,
      });
    }
    if (u.endsWith("/watchlist/5") && method === "DELETE") return mockResponse(200, { deleted: 5 });
    if (u.includes("/history")) return mockResponse(200, []);
    return mockResponse(404, { detail: "unexpected " + u + " " + method });
  });
  await renderActivity(["/activity?tab=watchlist"]);

  expect(screen.getByText("watched.example")).toBeInTheDocument();

  fireEvent.change(screen.getByPlaceholderText(/example-domain\.com/i), {
    target: { value: "new.example" },
  });
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /add to watchlist/i }));
  });

  const postCall = global.fetch.mock.calls.find(
    ([u, o]) => String(u).endsWith("/watchlist") && o?.method === "POST"
  );
  expect(postCall).toBeTruthy();
  expect(postCall[1].body).toBe(JSON.stringify({ target: "new.example" }));

  await act(async () => {
    fireEvent.click(screen.getAllByRole("button", { name: /remove/i })[0]);
  });
  const deleteCall = global.fetch.mock.calls.find(([, o]) => o?.method === "DELETE");
  expect(deleteCall).toBeTruthy();
  expect(deleteCall[0]).toBe(API_BASE + "/watchlist/5");
});

test("re-scan all posts to /watchlist/rescan", async () => {
  global.fetch = vi.fn((url, opts = {}) => {
    const u = String(url);
    const method = opts.method || "GET";
    if (u.endsWith("/watchlist") && method === "GET") return mockResponse(200, watchRows);
    if (u.endsWith("/watchlist/rescan")) {
      return mockResponse(200, { checked: 1, new_threats: [], results: [] });
    }
    if (u.includes("/history")) return mockResponse(200, []);
    return mockResponse(404, {});
  });
  await renderActivity(["/activity?tab=watchlist"]);

  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /re-scan all/i }));
  });

  const rescanCall = global.fetch.mock.calls.find(([u]) =>
    String(u).endsWith("/watchlist/rescan")
  );
  expect(rescanCall).toBeTruthy();
  expect(rescanCall[1].method).toBe("POST");
});

// ---------------------------------------------------------------------------
// (c) watchlist tab visibility — premium viewers only (old _updateSidebar rule:
//     tier === 'premium' || admin/superadmin)
// ---------------------------------------------------------------------------
test("(c) the watchlist tab is hidden for a plain free user", async () => {
  mockUser = { email: "free@example.com", role: "user", tier: "free" };
  global.fetch = vi.fn(() => mockResponse(200, []));
  await renderActivity();

  expect(screen.queryByRole("tab", { name: /watchlist/i })).not.toBeInTheDocument();
});

test("the watchlist tab shows for admins even on the free tier", async () => {
  mockUser = { email: "admin@example.com", role: "admin", tier: "free" };
  global.fetch = vi.fn(() => mockResponse(200, []));
  await renderActivity();

  expect(screen.getByRole("tab", { name: /watchlist/i })).toBeInTheDocument();
});

test("a free user deep-linking to ?tab=watchlist falls back to history", async () => {
  mockUser = { email: "free@example.com", role: "user", tier: "free" };
  global.fetch = vi.fn(() => mockResponse(200, []));
  await renderActivity(["/activity?tab=watchlist"]);

  expect(screen.getByRole("tab", { name: /history/i })).toHaveAttribute("aria-selected", "true");
  expect(screen.queryByRole("button", { name: /add to watchlist/i })).not.toBeInTheDocument();
});
