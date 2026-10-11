import { render, screen, act } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import Dashboard from "../src/pages/Dashboard.jsx";
import { ToastProvider } from "../src/components/Toast.jsx";
import { setToken, clearToken } from "../src/api.js";

let mockUser = null;
vi.mock("../src/auth/AuthContext.jsx", () => ({
  useAuth: () => ({ user: mockUser }),
}));

class FakeWebSocket {
  static instances = [];

  constructor(url) {
    this.url = url;
    FakeWebSocket.instances.push(this);
  }

  close() {}

  emitMessage(payload) {
    this.onmessage?.({ data: JSON.stringify(payload) });
  }
}

function mockResponse(status, body) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
    headers: { get: () => "application/json" },
  });
}

const statsFixture = {
  total_scans: 1234,
  threats_blocked: 87,
  avg_scan_time_ms: 812.5,
  scans_today: 41,
};

const analyticsFixture = {
  scope: "user",
  days: 7,
  verdict_distribution: { safe: 20, suspicious: 6, malicious: 4 },
  threats_over_time: [
    { date: "2026-07-09", count: 0 },
    { date: "2026-07-10", count: 2 },
    { date: "2026-07-11", count: 1 },
    { date: "2026-07-12", count: 0 },
    { date: "2026-07-13", count: 3 },
    { date: "2026-07-14", count: 1 },
    { date: "2026-07-15", count: 2 },
  ],
  scan_activity: [
    { date: "2026-07-09", safe: 3, suspicious: 0, malicious: 0 },
    { date: "2026-07-10", safe: 5, suspicious: 2, malicious: 0 },
    { date: "2026-07-11", safe: 2, suspicious: 1, malicious: 0 },
    { date: "2026-07-12", safe: 4, suspicious: 0, malicious: 0 },
    { date: "2026-07-13", safe: 1, suspicious: 2, malicious: 1 },
    { date: "2026-07-14", safe: 3, suspicious: 0, malicious: 1 },
    { date: "2026-07-15", safe: 2, suspicious: 1, malicious: 1 },
  ],
  top_threat_types: [{ type: "Phishing", count: 7 }],
  top_targeted_brands: [{ brand: "Paypal", count: 4 }],
  recent_scans: [
    {
      module: "URL Scanner",
      target: "https://recent.example",
      verdict: "SUSPICIOUS",
      score: 55,
      time: "2026-07-15T10:00:00",
    },
  ],
  threat_geo: [{ country: "Russia", lat: 55.7, lng: 37.6, count: 3 }],
};

const threatsFixture = {
  status: "live",
  sources: ["URLHaus", "OpenPhish"],
  fetched_at: new Date(Date.now() - 2 * 60 * 1000).toISOString(),
  threats: [
    { type: "PHISHING", target: "https://paypal-security-alert.example/login", severity: "CRITICAL", source: "OpenPhish" },
    { type: "MALWARE", target: "http://banking-login.example/drop.exe", severity: "HIGH", source: "URLHaus" },
  ],
};

function mockAllEndpoints() {
  global.fetch = vi.fn((url) => {
    const u = String(url);
    if (u.endsWith("/stats")) return mockResponse(200, statsFixture);
    if (u.includes("/analytics")) return mockResponse(200, analyticsFixture);
    if (u.endsWith("/live-threats")) return mockResponse(200, threatsFixture);
    return mockResponse(404, { detail: "unexpected " + u });
  });
}

async function renderDashboard() {
  await act(async () => {
    render(
      <ToastProvider>
        <MemoryRouter>
          <Dashboard />
        </MemoryRouter>
      </ToastProvider>
    );
  });
}

beforeEach(() => {
  vi.restoreAllMocks();
  FakeWebSocket.instances = [];
  vi.stubGlobal("WebSocket", FakeWebSocket);
  mockUser = { email: "user@example.com", role: "user", tier: "free" };
});

afterEach(() => {
  vi.unstubAllGlobals();
  clearToken();
});

test("renders the four stat tiles from /stats", async () => {
  mockAllEndpoints();
  await renderDashboard();

  expect(screen.getByText(/total scans/i)).toBeInTheDocument();
  expect(screen.getByText("1,234")).toBeInTheDocument();
  expect(screen.getByText(/threats blocked/i)).toBeInTheDocument();
  expect(screen.getByText("87")).toBeInTheDocument();
  // "Scans today" / its value appear in both the stat tile and the usage card
  expect(screen.getAllByText(/scans today/i).length).toBeGreaterThanOrEqual(1);
  expect(screen.getAllByText("41").length).toBeGreaterThanOrEqual(1);
  expect(screen.getByText(/avg response/i)).toBeInTheDocument();
  expect(screen.getByText("813")).toBeInTheDocument();
});

test("shows the usage/plan card for a logged-in free user with an upgrade link", async () => {
  mockAllEndpoints();
  await renderDashboard();

  expect(screen.getByText(/your usage & plan/i)).toBeInTheDocument();
  expect(screen.getByText(/^free$/i)).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /upgrade/i })).toHaveAttribute("href", "/settings");
});

test("hides the usage card for anonymous viewers", async () => {
  mockUser = "anonymous";
  mockAllEndpoints();
  await renderDashboard();

  expect(screen.queryByText(/your usage & plan/i)).not.toBeInTheDocument();
});

test("renders recent scans and the live threat feed seed", async () => {
  mockAllEndpoints();
  await renderDashboard();

  expect(screen.getByText("https://recent.example")).toBeInTheDocument();
  // "Suspicious" appears in both the donut legend and the row's verdict badge
  expect(screen.getAllByText(/^suspicious$/i).length).toBeGreaterThanOrEqual(1);
  // the DOMAIN is highlighted separately from the rest of the URL
  expect(screen.getByText("paypal-security-alert.example")).toBeInTheDocument();
  expect(screen.getByText("banking-login.example")).toBeInTheDocument();
});

// ---------------------------------------------------------------------------
// Task 5: honest live feed — source + freshness, no demo rows
// ---------------------------------------------------------------------------
test("live feed shows its sources and when it was fetched", async () => {
  mockAllEndpoints();
  await renderDashboard();

  expect(screen.getByText(/urlhaus · openphish/i)).toBeInTheDocument();
  expect(screen.getByText(/updated 2 min ago/i)).toBeInTheDocument();
  expect(screen.getByText(/auto-refresh/i)).toBeInTheDocument();
});

test("live feed is honest when the feeds are unreachable", async () => {
  global.fetch = vi.fn((url) => {
    const u = String(url);
    if (u.endsWith("/stats")) return mockResponse(200, statsFixture);
    if (u.includes("/analytics")) return mockResponse(200, analyticsFixture);
    if (u.endsWith("/live-threats"))
      return mockResponse(200, {
        status: "unavailable",
        threats: [],
        sources: [],
        fetched_at: new Date().toISOString(),
        detail: "Threat feeds (URLHaus, OpenPhish) are unreachable right now — retrying automatically.",
      });
    return mockResponse(404, {});
  });
  await renderDashboard();

  expect(screen.getByText(/feed unavailable — retrying/i)).toBeInTheDocument();
  // no fabricated demo rows
  expect(screen.queryByText(/paypal-security-alert/i)).not.toBeInTheDocument();
});

test("prepends WebSocket alerts to the live feed", async () => {
  // The alert feed is per-user now: the socket only opens for a signed-in
  // visitor, because the server refuses an anonymous handshake.
  setToken("test-jwt");
  mockAllEndpoints();
  await renderDashboard();

  expect(FakeWebSocket.instances).toHaveLength(1);
  await act(async () => {
    FakeWebSocket.instances[0].emitMessage({
      verdict: "MALICIOUS",
      target: "https://fresh-threat.example",
      severity: "CRITICAL",
      time: "2026-07-15T11:00:00",
    });
  });

  expect(screen.getByText("https://fresh-threat.example")).toBeInTheDocument();
});

test("renders top threat types, brands and origins from /analytics", async () => {
  mockAllEndpoints();
  await renderDashboard();

  expect(screen.getByText(/top threat types/i)).toBeInTheDocument();
  expect(screen.getByText(/top targeted brands/i)).toBeInTheDocument();
  expect(screen.getByText("Russia")).toBeInTheDocument();
});

// ---------------------------------------------------------------------------
// Task 4: stacked scan activity with a 7/30-day toggle + honest origins
// ---------------------------------------------------------------------------
test("shows the scan activity panel with a 7/30 day toggle", async () => {
  mockAllEndpoints();
  await renderDashboard();

  expect(screen.getByText(/scan activity/i)).toBeInTheDocument();
  // the old threats-only panel title is gone
  expect(screen.queryByText(/threats · last 7 days/i)).not.toBeInTheDocument();

  const { fireEvent } = await import("@testing-library/react");
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /30 days/i }));
  });
  const calls = global.fetch.mock.calls.map((c) => String(c[0]));
  expect(calls.some((u) => u.includes("/analytics?days=30"))).toBe(true);
});

// ---------------------------------------------------------------------------
// Task 8 follow-up: the dashboard quick actions match the merged Email box —
// one Email card (upload + Gmail inbox live inside it), no separate Gmail
// card, and Batch is reachable from the dashboard like every other tool.
// ---------------------------------------------------------------------------
test("tool shortcuts show ONE merged Email card and a Batch card", async () => {
  mockAllEndpoints();
  await renderDashboard();

  const email = screen.getByRole("link", { name: /email security/i });
  expect(email).toHaveAttribute("href", "/scan?type=email");
  expect(screen.queryByText(/gmail monitor/i)).not.toBeInTheDocument();

  const batch = screen.getByRole("link", { name: /batch scanner/i });
  expect(batch).toHaveAttribute("href", "/scan?type=batch");
});

test("threat origins panel has an honest empty state", async () => {
  global.fetch = vi.fn((url) => {
    const u = String(url);
    if (u.endsWith("/stats")) return mockResponse(200, statsFixture);
    if (u.includes("/analytics"))
      return mockResponse(200, { ...analyticsFixture, threat_geo: [] });
    if (u.endsWith("/live-threats")) return mockResponse(200, threatsFixture);
    return mockResponse(404, {});
  });
  await renderDashboard();

  expect(
    screen.getByText(/no flagged scans yet — origins appear here/i)
  ).toBeInTheDocument();
});
