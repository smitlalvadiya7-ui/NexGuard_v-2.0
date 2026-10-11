import { render, screen, fireEvent, act } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import ReportVerdict from "../src/components/ReportVerdict.jsx";
import LiveProtection from "../src/pages/Scan/LiveProtection.jsx";
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

function wrap(ui) {
  return render(
    <ToastProvider>
      <MemoryRouter>{ui}</MemoryRouter>
    </ToastProvider>
  );
}

beforeEach(() => {
  vi.restoreAllMocks();
});

test("ReportVerdict posts the corrected label to /feedback", async () => {
  global.fetch = vi.fn(() => mockResponse(200, { ok: true, feedback: { id: 1 } }));
  wrap(
    <ReportVerdict url="https://evil.example" module="URL Scanner" verdict="SAFE" score={5} />
  );

  fireEvent.click(screen.getByRole("button", { name: /report incorrect verdict/i }));
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /actually malicious/i }));
  });

  expect(global.fetch).toHaveBeenCalledTimes(1);
  const [calledUrl, opts] = global.fetch.mock.calls[0];
  expect(calledUrl).toBe(API_BASE + "/feedback");
  expect(opts.method).toBe("POST");
  expect(JSON.parse(opts.body)).toEqual({
    scan_url: "https://evil.example",
    module: "URL Scanner",
    predicted_verdict: "SAFE",
    predicted_score: 5,
    user_label: "malicious",
  });
});

test("ReportVerdict renders nothing without a scanned URL", () => {
  const { container } = wrap(<ReportVerdict url="" verdict="SAFE" score={0} />);
  expect(container.querySelector("button")).toBeNull();
});

test("LiveProtection shows the unsupported note where SpeechRecognition is missing", () => {
  wrap(<LiveProtection />);
  expect(screen.getByText(/live scam protection/i)).toBeInTheDocument();
  expect(screen.getByText(/needs browser speech recognition/i)).toBeInTheDocument();
});
