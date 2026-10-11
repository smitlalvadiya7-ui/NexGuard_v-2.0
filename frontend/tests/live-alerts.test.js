import { renderHook, act } from "@testing-library/react";
import { vi } from "vitest";
import useLiveAlerts from "../src/hooks/useLiveAlerts.js";
import { setToken, clearToken } from "../src/api.js";

class FakeWebSocket {
  static instances = [];

  constructor(url) {
    this.url = url;
    this.closed = false;
    FakeWebSocket.instances.push(this);
  }

  close() {
    this.closed = true;
  }

  emitOpen() {
    this.onopen?.();
  }

  emitMessage(payload) {
    this.onmessage?.({ data: JSON.stringify(payload) });
  }

  emitClose() {
    this.onclose?.();
  }
}

beforeEach(() => {
  FakeWebSocket.instances = [];
  vi.stubGlobal("WebSocket", FakeWebSocket);
  vi.useFakeTimers();
  // The socket now requires a JWT — the backend rejects anonymous handshakes
  // (it used to broadcast every user's scan targets to any listener).
  setToken("test-jwt");
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  clearToken();
});

test("does not open a socket when signed out", () => {
  clearToken();
  renderHook(() => useLiveAlerts(vi.fn()));

  expect(FakeWebSocket.instances).toHaveLength(0);
});

test("sends the auth token on the handshake", () => {
  renderHook(() => useLiveAlerts(vi.fn()));

  expect(FakeWebSocket.instances[0].url).toContain("token=test-jwt");
});

test("url-encodes the token", () => {
  setToken("a+b/c=");
  renderHook(() => useLiveAlerts(vi.fn()));

  expect(FakeWebSocket.instances[0].url).toContain("token=a%2Bb%2Fc%3D");
});

test("connects to /ws/live-alerts and forwards parsed messages to onAlert", () => {
  const onAlert = vi.fn();
  renderHook(() => useLiveAlerts(onAlert));

  expect(FakeWebSocket.instances).toHaveLength(1);
  const ws = FakeWebSocket.instances[0];
  expect(ws.url.startsWith("ws")).toBe(true);
  expect(ws.url).toContain("/ws/live-alerts?");

  act(() => {
    ws.emitOpen();
    ws.emitMessage({ verdict: "MALICIOUS", target: "https://evil.example", severity: "CRITICAL" });
    ws.emitMessage({ verdict: "SUSPICIOUS", target: "https://shady.example", severity: "HIGH" });
  });

  expect(onAlert).toHaveBeenCalledTimes(2);
  expect(onAlert.mock.calls[0][0]).toMatchObject({ target: "https://evil.example" });
});

test("filters server keep-alive heartbeats", () => {
  const onAlert = vi.fn();
  renderHook(() => useLiveAlerts(onAlert));

  act(() => {
    FakeWebSocket.instances[0].emitMessage({ type: "heartbeat" });
  });

  expect(onAlert).not.toHaveBeenCalled();
});

test("reconnects after close with growing backoff", () => {
  renderHook(() => useLiveAlerts(vi.fn()));
  expect(FakeWebSocket.instances).toHaveLength(1);

  act(() => {
    FakeWebSocket.instances[0].emitClose();
  });
  act(() => {
    vi.advanceTimersByTime(1000); // first retry after 1s
  });
  expect(FakeWebSocket.instances).toHaveLength(2);

  act(() => {
    FakeWebSocket.instances[1].emitClose();
  });
  act(() => {
    vi.advanceTimersByTime(1999); // second retry needs 2s — not yet
  });
  expect(FakeWebSocket.instances).toHaveLength(2);
  act(() => {
    vi.advanceTimersByTime(1);
  });
  expect(FakeWebSocket.instances).toHaveLength(3);
});

test("a successful reconnect resets the backoff", () => {
  renderHook(() => useLiveAlerts(vi.fn()));

  act(() => {
    FakeWebSocket.instances[0].emitClose();
    vi.advanceTimersByTime(1000);
  });
  act(() => {
    FakeWebSocket.instances[1].emitOpen(); // resets attempt counter
    FakeWebSocket.instances[1].emitClose();
  });
  act(() => {
    vi.advanceTimersByTime(1000); // back to the 1s delay
  });
  expect(FakeWebSocket.instances).toHaveLength(3);
});

test("unmount closes the socket and stops reconnecting", () => {
  const { unmount } = renderHook(() => useLiveAlerts(vi.fn()));
  const ws = FakeWebSocket.instances[0];

  unmount();
  expect(ws.closed).toBe(true);

  act(() => {
    ws.emitClose();
    vi.advanceTimersByTime(60000);
  });
  expect(FakeWebSocket.instances).toHaveLength(1);
});
