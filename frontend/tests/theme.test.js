import { initTheme, getTheme, toggleTheme } from "../src/theme.js";

beforeEach(() => {
  localStorage.clear();
  delete document.documentElement.dataset.theme;
});

test("initTheme defaults from prefers-color-scheme and stamps the html element", () => {
  initTheme();
  expect(["light", "dark"]).toContain(getTheme());
  expect(document.documentElement.dataset.theme).toBe(getTheme());
});

test("toggleTheme flips, persists, and re-stamps", () => {
  initTheme();
  const before = getTheme();
  const after = toggleTheme();
  expect(after).not.toBe(before);
  expect(localStorage.getItem("nexguard.theme")).toBe(after);
  expect(document.documentElement.dataset.theme).toBe(after);
});

test("stored preference wins over media query", () => {
  localStorage.setItem("nexguard.theme", "dark");
  initTheme();
  expect(getTheme()).toBe("dark");
});
