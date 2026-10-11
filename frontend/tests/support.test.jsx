import { render, screen, fireEvent, act } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import Support from "../src/pages/Support.jsx";
import AdminSupport from "../src/pages/Admin/Support.jsx";
import { ToastProvider } from "../src/components/Toast.jsx";
import { API_BASE } from "../src/api.js";

vi.mock("../src/auth/AuthContext.jsx", () => ({
  useAuth: () => ({ user: { email: "user@example.com", role: "user", tier: "free" } }),
}));

function mockResponse(status, body) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
    headers: { get: () => "application/json" },
  });
}

const FAQ = [
  { question: "How does the URL scanner work?", answer: "It checks the link against threat feeds." },
  { question: "What does 'Verified sender' mean?", answer: "The email really comes from that brand." },
];

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

// ---------------------------------------------------------------------------
// Support page
// ---------------------------------------------------------------------------
test("Support page lists the FAQ", async () => {
  global.fetch = vi.fn((url) => {
    if (String(url).endsWith("/support/faq")) return mockResponse(200, FAQ);
    if (String(url).endsWith("/support/tickets")) return mockResponse(200, []);
    return mockResponse(404, {});
  });
  await act(async () => {
    wrap(<Support />);
  });

  expect(await screen.findByText(/how does the url scanner work/i)).toBeInTheDocument();
  expect(screen.getByText(/verified sender/i)).toBeInTheDocument();
});

test("the assistant answers a question via /support/ask", async () => {
  global.fetch = vi.fn((url, opts) => {
    const u = String(url);
    if (u.endsWith("/support/faq")) return mockResponse(200, FAQ);
    if (u.endsWith("/support/tickets") && (!opts || opts.method !== "POST"))
      return mockResponse(200, []);
    if (u.endsWith("/support/ask"))
      return mockResponse(200, {
        matched: true,
        confidence: 0.8,
        question: "How does the voice / call scam scanner work?",
        answer: "It transcribes the call and scores it for scam intent.",
        related: ["What do SAFE, SUSPICIOUS and MALICIOUS mean?"],
      });
    return mockResponse(404, {});
  });
  await act(async () => {
    wrap(<Support />);
  });

  fireEvent.change(screen.getByLabelText(/ask the assistant/i), {
    target: { value: "how does voice scanning work" },
  });
  fireEvent.click(screen.getByRole("button", { name: /^ask$/i }));

  expect(await screen.findByText(/transcribes the call and scores it/i)).toBeInTheDocument();
});

test("a scanned link answer shows the verdict chip (C1)", async () => {
  global.fetch = vi.fn((url, opts) => {
    const u = String(url);
    if (u.endsWith("/support/faq")) return mockResponse(200, FAQ);
    if (u.endsWith("/support/tickets") && (!opts || opts.method !== "POST"))
      return mockResponse(200, []);
    if (u.endsWith("/support/ask"))
      return mockResponse(200, {
        matched: true,
        confidence: 1,
        question: null,
        answer:
          "I ran a full scan on https://evil.tk/login.\nVerdict: MALICIOUS — risk score 100/100 (high confidence).",
        related: ["What do SAFE, SUSPICIOUS and MALICIOUS mean?"],
        action: "scanned_url",
        scan: { target: "https://evil.tk/login", verdict: "MALICIOUS", risk_score: 100, confidence: 100 },
      });
    return mockResponse(404, {});
  });
  await act(async () => {
    wrap(<Support />);
  });

  fireEvent.change(screen.getByLabelText(/ask the assistant/i), {
    target: { value: "is https://evil.tk/login a scam?" },
  });
  fireEvent.click(screen.getByRole("button", { name: /^ask$/i }));

  // verdict chip + score + the composed answer text
  expect(await screen.findByText("MALICIOUS")).toBeInTheDocument();
  expect(screen.getByText(/risk 100\/100/i)).toBeInTheDocument();
  expect(screen.getByText(/i ran a full scan/i)).toBeInTheDocument();
});

test("the contact form posts a ticket and confirms", async () => {
  const calls = [];
  global.fetch = vi.fn((url, opts) => {
    const u = String(url);
    calls.push([u, opts]);
    if (u.endsWith("/support/faq")) return mockResponse(200, FAQ);
    if (u.endsWith("/support/tickets") && opts?.method === "POST")
      return mockResponse(200, { ok: true, ticket: { id: 7, status: "open" } });
    if (u.endsWith("/support/tickets")) return mockResponse(200, []);
    return mockResponse(404, {});
  });
  await act(async () => {
    wrap(<Support />);
  });

  fireEvent.change(screen.getByLabelText(/your email/i), {
    target: { value: "me@example.com" },
  });
  fireEvent.change(screen.getByLabelText(/message/i), {
    target: { value: "Please help with a suspicious SMS." },
  });
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /send message/i }));
  });

  expect(await screen.findByText(/your message was sent/i)).toBeInTheDocument();
  const post = calls.find((c) => c[0].endsWith("/support/tickets") && c[1]?.method === "POST");
  expect(post).toBeTruthy();
});

// ---------------------------------------------------------------------------
// Admin support inbox
// ---------------------------------------------------------------------------
test("Admin support inbox lists tickets and replies", async () => {
  const ticket = {
    id: 3,
    email: "visitor@example.com",
    subject: "Why flagged?",
    message: "My email was flagged.",
    category: "problem",
    status: "open",
    admin_reply: "",
    reporter_account: "not signed in",
    created_at: "2026-07-16T10:00:00",
  };
  global.fetch = vi.fn((url, opts) => {
    const u = String(url);
    if (u.includes("/admin/support/tickets") && (!opts || opts.method !== "POST"))
      return mockResponse(200, [ticket]);
    if (u.match(/\/admin\/support\/tickets\/3\/reply/))
      return mockResponse(200, { ...ticket, status: "answered", admin_reply: "Fixed." });
    return mockResponse(404, {});
  });
  await act(async () => {
    wrap(<AdminSupport />);
  });

  expect(await screen.findByText(/my email was flagged/i)).toBeInTheDocument();
  expect(screen.getByText(/visitor@example.com/i)).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText(/reply to ticket 3/i), {
    target: { value: "Fixed." },
  });
  await act(async () => {
    fireEvent.click(screen.getByRole("button", { name: /send reply/i }));
  });

  const replyCall = global.fetch.mock.calls.find((c) =>
    String(c[0]).endsWith("/admin/support/tickets/3/reply")
  );
  expect(replyCall).toBeTruthy();
  expect(replyCall[0]).toBe(API_BASE + "/admin/support/tickets/3/reply");
});
