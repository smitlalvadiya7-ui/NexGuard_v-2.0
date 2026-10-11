import { render, screen } from "@testing-library/react";
import App from "../src/App.jsx";

test("app renders the product name", () => {
  render(<App />);
  expect(screen.getByText(/NexGuard AI/i)).toBeInTheDocument();
});
