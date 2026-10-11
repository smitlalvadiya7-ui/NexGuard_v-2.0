import { render, screen, act } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";

/*
 * The dashboard must not redraw its charts every second.
 *
 * The live-feed "auto-refresh in m:ss" countdown kept its seconds in the
 * Dashboard's own state, so once a second the whole page re-rendered: three
 * recharts charts, the stat tiles, the recent-scans list and the feed. On a
 * laptop on battery that is the lag and flicker the dashboard showed while it
 * sat open (2026-10-09). Only the countdown text has to change each second.
 */

const charts = vi.hoisted(() => ({ renders: 0 }));

vi.mock("recharts", async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    // Count how often a chart is drawn; skip recharts' own layout in jsdom.
    ResponsiveContainer: () => {
      charts.renders += 1;
      return <div data-testid="chart" />;
    },
  };
});

let mockUser = null;
vi.mock("../src/auth/AuthContext.jsx", () => ({
  useAuth: () => ({ user: mockUser }),
}));

import Dashboard from "../src/pages/Dashboard.jsx";
import { ToastProvider } from "../src/components/Toast.jsx";

function mockResponse(status, body) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
    headers: { get: () => "application/json" },
  });
}

const analytics = {
  scope: "user",
  days: 7,
  verdict_distribution: { safe: 20, suspicious: 6, malicious: 4 },
  scan_activity: [
    { date: "2026-07-14", safe: 3, suspicious: 0, malicious: 1 },
    { date: "2026-07-15", safe: 2, suspicious: 1, malicious: 1 },
  ],
  top_threat_types: [{ type: "Phishing", count: 7 }],
  top_targeted_brands: [{ brand: "Paypal", count: 4 }],
  recent_scans: [],
  threat_geo: [],
};

let feedCalls = 0;

beforeEach(() => {
  vi.useFakeTimers();
  charts.renders = 0;
  feedCalls = 0;
  mockUser = { email: "user@example.com", role: "user", tier: "free" };
  vi.stubGlobal("WebSocket", class { close() {} });
  global.fetch = vi.fn((url) => {
    const u = String(url);
    if (u.endsWith("/stats")) return mockResponse(200, { total_scans: 1, threats_blocked: 0, avg_scan_time_ms: 5, scans_today: 1 });
    if (u.includes("/analytics")) return mockResponse(200, analytics);
    if (u.endsWith("/live-threats")) {
      feedCalls += 1;
      return mockResponse(200, { status: "live", sources: ["URLHaus"], fetched_at: new Date().toISOString(), threats: [] });
    }
    return mockResponse(404, {});
  });
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

async function renderDashboard() {
  await act(async () => {
    render(
      <ToastProvider>
        <MemoryRouter>
          <Dashboard />
        </MemoryRouter>
      </ToastProvider>,
    );
  });
  await act(async () => {
    await vi.advanceTimersByTimeAsync(0);
  });
}

test("charts are not redrawn while the countdown ticks", async () => {
  await renderDashboard();
  const afterLoad = charts.renders;
  expect(afterLoad).toBeGreaterThan(0);

  await act(async () => {
    await vi.advanceTimersByTimeAsync(5000);
  });

  expect(charts.renders).toBe(afterLoad);
  expect(screen.getByText(/auto-refresh in 4:55/)).toBeInTheDocument();
});

test("the feed still refreshes itself every five minutes", async () => {
  await renderDashboard();
  expect(feedCalls).toBe(1);

  await act(async () => {
    await vi.advanceTimersByTimeAsync(300 * 1000);
  });
  await act(async () => {
    await vi.advanceTimersByTimeAsync(0);
  });

  expect(feedCalls).toBe(2);
  expect(screen.getByText(/auto-refresh in 5:00|auto-refresh in 4:5\d/)).toBeInTheDocument();
});
