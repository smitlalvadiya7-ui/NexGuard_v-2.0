import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import { AppRoutes } from "../src/App.jsx";
import { AuthProvider } from "../src/auth/AuthContext.jsx";
import { ToastProvider } from "../src/components/Toast.jsx";
import { initTheme } from "../src/theme.js";

function mockResponse(status, body) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(body),
    headers: { get: () => "application/json" },
  });
}

function renderApp(initialEntries = ["/"]) {
  return render(
    <AuthProvider>
      <ToastProvider>
        <MemoryRouter initialEntries={initialEntries}>
          <AppRoutes />
        </MemoryRouter>
      </ToastProvider>
    </AuthProvider>
  );
}

// Simulates a page reload with an already-established session: AuthContext
// only hydrates `user` by revalidating a stored token against /auth/me, so
// seeding these same localStorage keys is what auth.test.jsx already relies
// on for "logged in on mount".
function seedSession({ email = "person@example.com", role, tier = "free" }) {
  localStorage.setItem("nexguard.token", "jwt-test");
  localStorage.setItem("nexguard.email", email);
  localStorage.setItem("nexguard.role", role);
  localStorage.setItem("nexguard.tier", tier);
  global.fetch = vi.fn(() => mockResponse(200, { email, role, tier, status: "active", id: 1 }));
}

beforeEach(() => {
  localStorage.clear();
  vi.restoreAllMocks();
  document.documentElement.removeAttribute("data-theme");
});

test("(a) logged-out render at / redirects to the login screen", async () => {
  renderApp(["/"]);

  await waitFor(() => {
    expect(screen.getByText(/continue without login/i)).toBeInTheDocument();
  });
  expect(screen.getByRole("tab", { name: /sign in/i })).toBeInTheDocument();
});

test("(b) a 'user' role does not see an Admin nav item", async () => {
  seedSession({ role: "user" });
  renderApp(["/"]);

  await waitFor(() => {
    expect(screen.getByRole("heading", { name: /^dashboard$/i, level: 1 })).toBeInTheDocument();
  });
  expect(screen.queryByRole("link", { name: /admin/i })).not.toBeInTheDocument();
});

test("(c) an 'admin' role sees the Admin nav item and can open it", async () => {
  seedSession({ role: "admin" });
  renderApp(["/"]);

  await waitFor(() => {
    expect(screen.getByRole("heading", { name: /^dashboard$/i, level: 1 })).toBeInTheDocument();
  });

  const adminLink = screen.getByRole("link", { name: /admin/i });
  fireEvent.click(adminLink);

  expect(await screen.findByRole("heading", { name: /^admin$/i, level: 1 })).toBeInTheDocument();
});

test("(d) the theme toggle flips data-theme", async () => {
  initTheme();
  const before = document.documentElement.dataset.theme;

  renderApp(["/login"]);
  fireEvent.click(screen.getByText(/continue without login/i));

  await waitFor(() => {
    expect(screen.getByRole("heading", { name: /^scan$/i, level: 1 })).toBeInTheDocument();
  });

  fireEvent.click(screen.getByRole("button", { name: /toggle theme/i }));
  expect(document.documentElement.dataset.theme).not.toBe(before);
});

test("a stored session deep-linking to /reports lands on Reports, not Dashboard", async () => {
  // During /auth/me hydration `user` is still null, so RequireAuth bounces
  // the deep link through /login; once hydration completes, Login's rescue
  // effect must return to the ORIGINAL destination, not hardcoded "/".
  seedSession({ role: "user" });
  renderApp(["/reports"]);

  expect(
    await screen.findByRole("heading", { name: /^reports$/i, level: 1 })
  ).toBeInTheDocument();
  expect(screen.queryByRole("heading", { name: /^dashboard$/i, level: 1 })).not.toBeInTheDocument();
});

test("a 'user' role visiting /admin directly is redirected to the dashboard", async () => {
  seedSession({ role: "user" });
  renderApp(["/admin"]);

  await waitFor(() => {
    expect(screen.getByRole("heading", { name: /^dashboard$/i, level: 1 })).toBeInTheDocument();
  });
  expect(screen.queryByRole("heading", { name: /^admin$/i, level: 1 })).not.toBeInTheDocument();
});
