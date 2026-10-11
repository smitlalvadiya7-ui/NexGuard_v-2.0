import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { vi } from "vitest";
import Scan from "../src/pages/Scan/index.jsx";
import { ToastProvider } from "../src/components/Toast.jsx";
import { AuthProvider } from "../src/auth/AuthContext.jsx";
import { API_BASE } from "../src/api.js";

function mockResponse(status, body) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
    headers: { get: () => "application/json" },
  });
}

// Sibling probe inside the same MemoryRouter so tests can assert the
// ?type= search param the switcher writes, without reaching into history
// internals.
function LocationProbe() {
  const location = useLocation();
  return <div data-testid="location">{location.pathname + location.search}</div>;
}

function renderScan(initialEntries = ["/scan"]) {
  return render(
    <ToastProvider>
      <MemoryRouter initialEntries={initialEntries}>
        <Scan />
        <LocationProbe />
      </MemoryRouter>
    </ToastProvider>
  );
}

function typeUrl(value) {
  fireEvent.change(screen.getByLabelText(/url to scan/i), { target: { value } });
}

function submit() {
  fireEvent.click(screen.getByRole("button", { name: /scan url/i }));
}

beforeEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// (a) submitting a URL calls POST /scan with {url} and renders the result
// ---------------------------------------------------------------------------
test("(a) typing a URL and submitting calls POST /scan with {url} and renders the verdict badge", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(200, {
      url: "https://example.com",
      verdict: "MALICIOUS",
      risk_score: 92,
      confidence: 88,
      flags: ["Known phishing kit"],
      tier_locked: [],
    })
  );
  renderScan();

  typeUrl("https://example.com");
  submit();

  expect(await screen.findByText(/^malicious$/i)).toBeInTheDocument();
  // POST /scan fires exactly once (a prior-scan history GET may follow it).
  const scanCalls = global.fetch.mock.calls.filter((c) => String(c[0]) === API_BASE + "/scan");
  expect(scanCalls).toHaveLength(1);
  const [calledUrl, opts] = scanCalls[0];
  expect(calledUrl).toBe(API_BASE + "/scan");
  expect(opts.method).toBe("POST");
  expect(opts.body).toBe(JSON.stringify({ url: "https://example.com" }));
});

test("shows a busy state on the Scan button while the request is in flight", async () => {
  let resolveFetch;
  global.fetch = vi.fn(
    () =>
      new Promise((resolve) => {
        resolveFetch = resolve;
      })
  );
  renderScan();

  typeUrl("https://example.com");
  submit();

  expect(screen.getByRole("button", { name: /scanning/i })).toBeDisabled();

  resolveFetch(
    await mockResponse(200, { verdict: "SAFE", risk_score: 2, flags: [], tier_locked: [] })
  );
  expect(await screen.findByText(/^safe$/i)).toBeInTheDocument();
});

test("submitting empty or whitespace-only input does nothing", () => {
  global.fetch = vi.fn();
  renderScan();

  submit();
  typeUrl("    ");
  submit();

  expect(global.fetch).not.toHaveBeenCalled();
});

// ---------------------------------------------------------------------------
// (b) FreeLimitError -> FreeLimitCard instead of a result
// ---------------------------------------------------------------------------
test("(b) a FreeLimitError renders FreeLimitCard instead of a result", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(429, {
      error: "free_limit",
      message: "Daily free scan limit reached. Upgrade to Premium for unlimited scans.",
    })
  );
  renderScan();

  typeUrl("https://example.com");
  submit();

  expect(await screen.findByText(/daily free limit reached/i)).toBeInTheDocument();
  expect(
    screen.getByText(/upgrade to premium for unlimited scans/i)
  ).toBeInTheDocument();
  // The real result surface (ResultPanel's risk gauge) must be absent.
  expect(screen.queryByRole("progressbar", { name: /risk score/i })).not.toBeInTheDocument();
  expect(screen.getByRole("link", { name: /upgrade to premium/i })).toHaveAttribute(
    "href",
    "/settings"
  );
});

test("a plain ApiError shows an error toast and an inline error line", async () => {
  global.fetch = vi.fn(() => mockResponse(500, { detail: "Scan backend unavailable" }));
  renderScan();

  typeUrl("https://example.com");
  submit();

  expect(await screen.findByRole("status")).toHaveTextContent(/scan backend unavailable/i);
  expect(screen.getByTestId("url-scan-error")).toHaveTextContent(/scan backend unavailable/i);
});

test("renders a compact embedded-links table when the response carries scanned_links", async () => {
  global.fetch = vi.fn(() =>
    mockResponse(200, {
      url: "https://example.com",
      verdict: "SUSPICIOUS",
      risk_score: 55,
      flags: [],
      tier_locked: [],
      scanned_links: [
        { url: "https://example.com/a", verdict: "SAFE" },
        { url: "https://evil.example/b", verdict: "MALICIOUS" },
      ],
    })
  );
  renderScan();

  typeUrl("https://example.com");
  submit();

  expect(await screen.findByText("https://example.com/a")).toBeInTheDocument();
  expect(screen.getByText("https://evil.example/b")).toBeInTheDocument();
});

// ---------------------------------------------------------------------------
// (c) the type switcher syncs to ?type=
// ---------------------------------------------------------------------------
test("(c) the type switcher updates the ?type= search param", () => {
  renderScan();
  expect(screen.getByTestId("location").textContent).toBe("/scan");
  expect(screen.getByRole("tab", { name: /^url$/i })).toHaveAttribute("aria-selected", "true");

  fireEvent.click(screen.getByRole("tab", { name: /^qr code$/i }));

  expect(screen.getByTestId("location").textContent).toBe("/scan?type=qr");
  expect(screen.getByRole("tab", { name: /^qr code$/i })).toHaveAttribute("aria-selected", "true");
  expect(screen.getByRole("button", { name: /scan qr/i })).toBeInTheDocument();
});

test("an unknown ?type= value falls back to the url panel", () => {
  renderScan(["/scan?type=bogus"]);
  expect(screen.getByRole("tab", { name: /^url$/i })).toHaveAttribute("aria-selected", "true");
  expect(screen.getByLabelText(/url to scan/i)).toBeInTheDocument();
});

test("the batch tab renders the real BatchPanel (premium gate for logged-out viewers)", () => {
  localStorage.clear(); // no stored session -> user is null -> gate shows
  render(
    <AuthProvider>
      <ToastProvider>
        <MemoryRouter initialEntries={["/scan?type=batch"]}>
          <Scan />
        </MemoryRouter>
      </ToastProvider>
    </AuthProvider>
  );
  expect(screen.getByText(/premium feature/i)).toBeInTheDocument();
});
