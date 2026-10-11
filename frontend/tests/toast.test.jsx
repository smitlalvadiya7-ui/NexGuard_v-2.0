import { render, screen, fireEvent, act } from "@testing-library/react";
import { ToastProvider, useToast } from "../src/components/Toast.jsx";

function Probe() {
  const { push } = useToast();
  return (
    <div>
      <button onClick={() => push("success", "Scan complete")}>push-success</button>
      <button onClick={() => push("error", "Scan failed")}>push-error</button>
    </div>
  );
}

function renderProbe() {
  return render(
    <ToastProvider>
      <Probe />
    </ToastProvider>
  );
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

test("push renders a toast with kind-colored border", () => {
  renderProbe();
  fireEvent.click(screen.getByText("push-success"));

  const toast = screen.getByRole("status");
  expect(toast).toHaveTextContent("Scan complete");
  expect(toast.className).toContain("border-l-safe");
});

test("a second push stacks rather than replacing the first", () => {
  renderProbe();
  fireEvent.click(screen.getByText("push-success"));
  fireEvent.click(screen.getByText("push-error"));

  expect(screen.getAllByRole("status")).toHaveLength(2);
  expect(screen.getByText("Scan complete")).toBeInTheDocument();
  expect(screen.getByText("Scan failed")).toBeInTheDocument();
});

test("a toast auto-dismisses after ~4s", () => {
  renderProbe();
  fireEvent.click(screen.getByText("push-success"));
  expect(screen.getByRole("status")).toBeInTheDocument();

  act(() => {
    vi.advanceTimersByTime(4000);
  });

  expect(screen.queryByRole("status")).not.toBeInTheDocument();
});

test("the dismiss button removes the toast immediately", () => {
  renderProbe();
  fireEvent.click(screen.getByText("push-success"));

  fireEvent.click(screen.getByRole("button", { name: /dismiss notification/i }));

  expect(screen.queryByRole("status")).not.toBeInTheDocument();
});
