import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import Login from "../src/pages/Login.jsx";

// The register form must advertise the same minimum the server enforces
// (auth.MIN_PASSWORD_LENGTH = 12). When these drift, the form happily submits a
// password the backend then rejects with a 400.
vi.mock("../src/auth/AuthContext.jsx", () => ({
  useAuth: () => ({
    user: null,
    login: vi.fn(),
    register: vi.fn(),
    skipAuth: vi.fn(),
  }),
}));

function renderLogin() {
  return render(
    <MemoryRouter>
      <Login />
    </MemoryRouter>,
  );
}

function openRegisterTab() {
  fireEvent.click(screen.getByRole("tab", { name: /register/i }));
}

test("the register tab requires a 12-character password", () => {
  renderLogin();
  openRegisterTab();

  expect(screen.getByLabelText(/password/i)).toHaveAttribute("minlength", "12");
});

test("the register tab tells the user the 12-character minimum", () => {
  renderLogin();
  openRegisterTab();

  expect(screen.getByText(/minimum 12 characters/i)).toBeInTheDocument();
});

test("the login tab does not impose the minimum", () => {
  renderLogin();

  expect(screen.getByLabelText(/password/i)).not.toHaveAttribute("minlength");
});
