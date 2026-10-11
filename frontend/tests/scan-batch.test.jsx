import { render, screen, fireEvent, act, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import DataTable from "../src/components/DataTable.jsx";
import BatchPanel from "../src/pages/Scan/BatchPanel.jsx";
import { ToastProvider } from "../src/components/Toast.jsx";
import { API_BASE } from "../src/api.js";

// BatchPanel gates on the viewer's tier/role; a mutable holder lets each test
// pick the viewer without re-mocking the module.
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

function wrap(ui) {
  return render(
    <ToastProvider>
      <MemoryRouter initialEntries={["/scan?type=batch"]}>{ui}</MemoryRouter>
    </ToastProvider>
  );
}

beforeEach(() => {
  vi.restoreAllMocks();
  mockUser = { email: "premium@example.com", role: "user", tier: "premium" };
});

afterEach(() => {
  vi.useRealTimers();
});

// ---------------------------------------------------------------------------
// DataTable
// ---------------------------------------------------------------------------
const columns = [
  { key: "url", label: "URL" },
  { key: "risk_score", label: "Score" },
];
const tableRows = [
  { url: "b.example", risk_score: 10 },
  { url: "a.example", risk_score: 90 },
  { url: "c.example", risk_score: 50 },
];

test("DataTable renders every row", () => {
  render(<DataTable columns={columns} rows={tableRows} rowKey={(r) => r.url} />);

  expect(screen.getAllByRole("row")).toHaveLength(4); // header + 3
  expect(screen.getByText("a.example")).toBeInTheDocument();
  expect(screen.getByText("c.example")).toBeInTheDocument();
});

test("DataTable sorts on header click and reverses on the second click", () => {
  render(<DataTable columns={columns} rows={tableRows} rowKey={(r) => r.url} />);

  fireEvent.click(screen.getByRole("button", { name: /score/i }));
  let rows = screen.getAllByRole("row");
  expect(within(rows[1]).getByText("b.example")).toBeInTheDocument(); // 10 first (asc)

  fireEvent.click(screen.getByRole("button", { name: /score/i }));
  rows = screen.getAllByRole("row");
  expect(within(rows[1]).getByText("a.example")).toBeInTheDocument(); // 90 first (desc)
});

test("DataTable sorts strings alphabetically", () => {
  render(<DataTable columns={columns} rows={tableRows} rowKey={(r) => r.url} />);

  fireEvent.click(screen.getByRole("button", { name: /url/i }));
  const rows = screen.getAllByRole("row");
  expect(within(rows[1]).getByText("a.example")).toBeInTheDocument();
});

// ---------------------------------------------------------------------------
// BatchPanel — premium gate
// ---------------------------------------------------------------------------
test("free users see the premium gate instead of the batch form", () => {
  mockUser = { email: "free@example.com", role: "user", tier: "free" };
  wrap(<BatchPanel />);

  expect(screen.getByText(/premium feature/i)).toBeInTheDocument();
  expect(screen.getByRole("link", { name: /go premium/i })).toHaveAttribute("href", "/settings");
  expect(screen.queryByRole("button", { name: /start batch scan/i })).not.toBeInTheDocument();
});

test("anonymous viewers see the premium gate too", () => {
  mockUser = "anonymous";
  wrap(<BatchPanel />);

  expect(screen.getByText(/premium feature/i)).toBeInTheDocument();
});

test("admins pass the gate without premium tier", () => {
  mockUser = { email: "admin@example.com", role: "admin", tier: "free" };
  wrap(<BatchPanel />);

  expect(screen.getByRole("button", { name: /start batch scan/i })).toBeInTheDocument();
});

// ---------------------------------------------------------------------------
// BatchPanel — submit + poll
// ---------------------------------------------------------------------------
test("submits pasted URLs, polls the job and renders progress then rows", async () => {
  vi.useFakeTimers();

  const runningView = {
    job_id: "job123",
    status: "running",
    total: 2,
    done: 1,
    counts: { MALICIOUS: 1, SUSPICIOUS: 0, SAFE: 0, ERROR: 0 },
    results: [
      {
        url: "https://evil.example",
        verdict: "MALICIOUS",
        risk_score: 92,
        summary: "Known phishing kit",
      },
    ],
    error: null,
  };
  const doneView = {
    ...runningView,
    status: "completed",
    done: 2,
    counts: { MALICIOUS: 1, SUSPICIOUS: 0, SAFE: 1, ERROR: 0 },
    results: [
      ...runningView.results,
      { url: "https://ok.example", verdict: "SAFE", risk_score: 3, summary: "Looks safe" },
    ],
  };

  global.fetch = vi
    .fn()
    .mockImplementationOnce(() => mockResponse(200, { job_id: "job123", total: 2, status: "running" }))
    .mockImplementationOnce(() => mockResponse(200, runningView))
    .mockImplementation(() => mockResponse(200, doneView));

  wrap(<BatchPanel />);

  fireEvent.change(screen.getByLabelText(/paste urls/i), {
    target: { value: "https://evil.example\nhttps://ok.example" },
  });
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /start batch scan/i }));
  });

  // POST went out as multipart with the pasted list in the `urls` field
  const [postUrl, postOpts] = global.fetch.mock.calls[0];
  expect(postUrl).toBe(API_BASE + "/scan-batch");
  expect(postOpts.method).toBe("POST");
  expect(postOpts.body).toBeInstanceOf(FormData);
  expect(postOpts.body.get("urls")).toBe("https://evil.example\nhttps://ok.example");

  // first poll: 1/2 done, partial rows
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1000);
  });
  expect(global.fetch.mock.calls[1][0]).toBe(API_BASE + "/scan-batch/job123");
  expect(screen.getByText(/1 \/ 2/)).toBeInTheDocument();
  expect(screen.getByText("https://evil.example")).toBeInTheDocument();

  // second poll: completed — all rows, no more polling afterwards
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1000);
  });
  expect(screen.getByText("https://ok.example")).toBeInTheDocument();
  expect(screen.getByText(/2 \/ 2/)).toBeInTheDocument();

  const callsAfterDone = global.fetch.mock.calls.length;
  await act(async () => {
    await vi.advanceTimersByTimeAsync(5000);
  });
  expect(global.fetch.mock.calls.length).toBe(callsAfterDone);

  // exports appear once the job is terminal
  expect(screen.getByRole("button", { name: /export csv/i })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: /export pdf/i })).toBeInTheDocument();
});

test("the CSV export downloads via the authenticated blob path", async () => {
  vi.useFakeTimers();
  const doneView = {
    job_id: "job9",
    status: "completed",
    total: 1,
    done: 1,
    counts: { MALICIOUS: 0, SUSPICIOUS: 0, SAFE: 1, ERROR: 0 },
    results: [{ url: "https://ok.example", verdict: "SAFE", risk_score: 1, summary: "ok" }],
    error: null,
  };
  global.fetch = vi
    .fn()
    .mockImplementationOnce(() => mockResponse(200, { job_id: "job9", total: 1, status: "running" }))
    .mockImplementationOnce(() => mockResponse(200, doneView))
    .mockImplementation(() =>
      Promise.resolve({ ok: true, status: 200, blob: () => Promise.resolve(new Blob(["csv"])) })
    );
  URL.createObjectURL = vi.fn(() => "blob:mock");
  URL.revokeObjectURL = vi.fn();

  wrap(<BatchPanel />);

  fireEvent.change(screen.getByLabelText(/paste urls/i), {
    target: { value: "https://ok.example" },
  });
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /start batch scan/i }));
  });
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1000);
  });

  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /export csv/i }));
  });

  const exportCall = global.fetch.mock.calls.find(([u]) => String(u).includes("export.csv"));
  expect(exportCall).toBeTruthy();
  expect(exportCall[0]).toBe(API_BASE + "/scan-batch/job9/export.csv");
});

test("submitting with no input does nothing", () => {
  global.fetch = vi.fn();
  wrap(<BatchPanel />);

  fireEvent.click(screen.getByRole("button", { name: /start batch scan/i }));

  expect(global.fetch).not.toHaveBeenCalled();
});

// ---------------------------------------------------------------------------
// 2026-09-29 test-pack batch: 89 of 200 rows were UNKNOWN, but the counters
// only knew MALICIOUS / SUSPICIOUS / SAFE / ERROR, so the panel said "0 errors"
// and those rows vanished from the summary. Skipped and over-limit lines were
// silent too.
// ---------------------------------------------------------------------------
async function runToCompletion(postBody, doneView) {
  vi.useFakeTimers();
  global.fetch = vi
    .fn()
    .mockImplementationOnce(() => mockResponse(200, postBody))
    .mockImplementation(() => mockResponse(200, doneView));
  wrap(<BatchPanel />);
  fireEvent.change(screen.getByLabelText(/paste urls/i), {
    target: { value: "https://a.example\nhttps://b.example" },
  });
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /start batch scan/i }));
  });
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1000);
  });
}

const unknownDoneView = {
  job_id: "job7",
  status: "completed",
  total: 2,
  done: 2,
  counts: { MALICIOUS: 0, SUSPICIOUS: 0, SAFE: 1, UNKNOWN: 1, ERROR: 0 },
  results: [
    { index: 0, url: "https://a.example", verdict: "SAFE", risk_score: 2, summary: "ok" },
    { index: 1, url: "https://b.example", verdict: "UNKNOWN", risk_score: 0, summary: "not checked" },
  ],
  invalid_count: 2,
  over_limit: 1,
  limit: 200,
  error: null,
};

test("UNKNOWN rows are counted as 'not checked'", async () => {
  await runToCompletion({ job_id: "job7", total: 2, status: "running" }, unknownDoneView);
  expect(screen.getByText(/1 not checked/i)).toBeInTheDocument();
});

test("an UNKNOWN row shows no risk number", async () => {
  await runToCompletion({ job_id: "job7", total: 2, status: "running" }, unknownDoneView);
  const row = screen.getByText("https://b.example").closest("tr");
  expect(within(row).getByText("—")).toBeInTheDocument();
  expect(within(row).queryByText("0")).not.toBeInTheDocument();
});

test("skipped and over-limit lines are reported, not silent", async () => {
  await runToCompletion(
    { job_id: "job7", total: 2, status: "running", invalid_count: 2, over_limit: 1, limit: 200 },
    unknownDoneView
  );
  expect(screen.getByText(/2 lines? (were|was) not valid/i)).toBeInTheDocument();
  expect(screen.getByText(/1 URL.*over the 200.URL limit/i)).toBeInTheDocument();
});
