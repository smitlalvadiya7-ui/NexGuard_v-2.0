import { render, screen } from "@testing-library/react";
import StatTile from "../src/components/StatTile.jsx";

test("formats numbers with locale separators and shows the suffix", () => {
  render(<StatTile label="Total scans" value={12345} suffix="scans" />);
  expect(screen.getByText("12,345")).toBeInTheDocument();
  expect(screen.getByText("scans")).toBeInTheDocument();
});

test("null value renders an em dash, not a fake zero", () => {
  render(<StatTile label="Avg" value={null} />);
  expect(screen.getByText("—")).toBeInTheDocument();
});

test("loading renders a skeleton instead of a value", () => {
  const { container } = render(<StatTile label="Total scans" loading />);
  expect(container.querySelector(".animate-pulse")).not.toBeNull();
  expect(screen.queryByText("—")).not.toBeInTheDocument();
});

test("an upward trend renders a ▲ with the label", () => {
  render(<StatTile label="Scans today" value={40} trend={{ dir: "up", label: "vs avg" }} />);
  expect(screen.getByText(/▲/)).toBeInTheDocument();
  expect(screen.getByText(/vs avg/i)).toBeInTheDocument();
});

test("a downward trend renders a ▼", () => {
  render(<StatTile label="Scans today" value={2} trend={{ dir: "down", label: "vs avg" }} />);
  expect(screen.getByText(/▼/)).toBeInTheDocument();
});
