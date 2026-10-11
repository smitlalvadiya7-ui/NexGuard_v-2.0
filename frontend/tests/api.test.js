import { vi } from "vitest";
import {
  apiFetch, setToken, clearToken, FreeLimitError, ApiError,
  setOnUnauthorized, API_BASE, wsUrl,
} from "../src/api.js";
import { downloadBlob } from "../src/api.js";

function mockResponse(status, body) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
    headers: { get: () => "application/json" },
  });
}

beforeEach(() => { clearToken(); vi.restoreAllMocks(); });

test("injects Authorization header when a token is set", async () => {
  setToken("jwt-abc");
  global.fetch = vi.fn(() => mockResponse(200, { ok: 1 }));
  await apiFetch("/auth/me");
  const [, opts] = global.fetch.mock.calls[0];
  expect(opts.headers.Authorization).toBe("Bearer jwt-abc");
});

test("JSON-encodes plain object bodies, passes FormData through", async () => {
  global.fetch = vi.fn(() => mockResponse(200, {}));
  await apiFetch("/scan", { method: "POST", body: { url: "https://x.com" } });
  expect(global.fetch.mock.calls[0][1].body).toBe('{"url":"https://x.com"}');
  const fd = new FormData();
  await apiFetch("/scan-qr", { method: "POST", body: fd });
  expect(global.fetch.mock.calls[1][1].body).toBe(fd);
});

test("429 free_limit throws FreeLimitError with the body attached", async () => {
  global.fetch = vi.fn(() => mockResponse(429, { error: "free_limit", used: 10, limit: 10 }));
  await expect(apiFetch("/scan", { method: "POST", body: { url: "x" } }))
    .rejects.toBeInstanceOf(FreeLimitError);
});

test("401 clears session via onUnauthorized and throws ApiError(401)", async () => {
  const onU = vi.fn();
  setOnUnauthorized(onU);
  global.fetch = vi.fn(() => mockResponse(401, { detail: "expired" }));
  await expect(apiFetch("/auth/me")).rejects.toMatchObject({ status: 401 });
  expect(onU).toHaveBeenCalled();
});

test("other errors normalize detail/message into ApiError", async () => {
  global.fetch = vi.fn(() => mockResponse(500, { detail: "boom" }));
  await expect(apiFetch("/stats")).rejects.toMatchObject({ status: 500, message: "boom" });
});

test("wsUrl derives from API_BASE", () => {
  expect(wsUrl("/ws/live-alerts").endsWith("/ws/live-alerts")).toBe(true);
  expect(wsUrl("/ws/live-alerts").startsWith("ws")).toBe(true);
});

test("downloadBlob fetches with auth header and clicks a temporary anchor to save the file", async () => {
  setToken("jwt-abc");
  const blob = new Blob(["id,verdict\n1,safe"], { type: "text/csv" });
  global.fetch = vi.fn(() =>
    Promise.resolve({ ok: true, status: 200, blob: () => Promise.resolve(blob) })
  );

  const clickSpy = vi.fn();
  const anchor = { click: clickSpy, remove: vi.fn(), style: {} };
  const createElementSpy = vi.spyOn(document, "createElement").mockReturnValue(anchor);
  const appendSpy = vi.spyOn(document.body, "appendChild").mockImplementation((node) => node);
  const createObjectURL = vi.fn(() => "blob:mock-url");
  const revokeObjectURL = vi.fn();
  global.URL.createObjectURL = createObjectURL;
  global.URL.revokeObjectURL = revokeObjectURL;

  await downloadBlob("/reports/42.csv", "report.csv");

  expect(global.fetch.mock.calls[0][0]).toBe(API_BASE + "/reports/42.csv");
  expect(global.fetch.mock.calls[0][1].headers.Authorization).toBe("Bearer jwt-abc");
  expect(createObjectURL).toHaveBeenCalledWith(blob);
  expect(anchor.href).toBe("blob:mock-url");
  expect(anchor.download).toBe("report.csv");
  expect(clickSpy).toHaveBeenCalledTimes(1);
  expect(revokeObjectURL).toHaveBeenCalledWith("blob:mock-url");

  createElementSpy.mockRestore();
  appendSpy.mockRestore();
});
