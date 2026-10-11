import { render, screen, fireEvent, act } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import Reports from "../src/pages/Reports.jsx";
import { ToastProvider } from "../src/components/Toast.jsx";
import { API_BASE } from "../src/api.js";

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
    id: 21,
    module: "URL Scanner",
    verdict: "MALICIOUS",
    score: 92,
    target: "https://evil.example/login",
    summary: "Known phishing kit",
    timestamp: "2026-07-15T09:30:00",
  },
];

async function renderReports() {
  await act(async () => {
    render(
      <ToastProvider>
        <MemoryRouter>
          <Reports />
        </MemoryRouter>
      </ToastProvider>
    );
  });
}

beforeEach(() => {
  vi.restoreAllMocks();
  URL.createObjectURL = vi.fn(() => "blob:mock");
  URL.revokeObjectURL = vi.fn();
});

test("lists recent scans from /history", async () => {
  global.fetch = vi.fn(() => mockResponse(200, historyRows));
  await renderReports();

  expect(screen.getByText("https://evil.example/login")).toBeInTheDocument();
  expect(screen.getByText(/^malicious$/i)).toBeInTheDocument();
  expect(String(global.fetch.mock.calls[0][0])).toContain("/history");
});

test("generating a report POSTs the scan to /export-report and downloads the PDF", async () => {
  global.fetch = vi.fn((url, opts = {}) => {
    const u = String(url);
    if (u.endsWith("/export-report")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        blob: () => Promise.resolve(new Blob(["pdf"])),
      });
    }
    if (u.includes("/history")) return mockResponse(200, historyRows);
    return mockResponse(404, { detail: "unexpected " + u + " " + (opts.method || "GET") });
  });
  await renderReports();

  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /generate pdf/i }));
  });

  const exportCall = global.fetch.mock.calls.find(([u]) => String(u).endsWith("/export-report"));
  expect(exportCall).toBeTruthy();
  expect(exportCall[0]).toBe(API_BASE + "/export-report");
  expect(exportCall[1].method).toBe("POST");
  const body = JSON.parse(exportCall[1].body);
  expect(body).toMatchObject({
    module: "URL Scanner",
    target: "https://evil.example/login",
    verdict: "MALICIOUS",
    risk_score: 92,
  });
  expect(URL.createObjectURL).toHaveBeenCalled();
});

test("shows an empty state when there is no history", async () => {
  global.fetch = vi.fn(() => mockResponse(200, []));
  await renderReports();

  expect(screen.getByText(/no scans to report on yet/i)).toBeInTheDocument();
});
