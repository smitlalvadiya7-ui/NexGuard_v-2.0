const KEY = "nexguard.theme";

function systemTheme() {
  if (typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-color-scheme: dark)").matches) {
    return "dark";
  }
  return "light";
}

export function getTheme() {
  return document.documentElement.dataset.theme || "light";
}

function apply(theme) {
  document.documentElement.dataset.theme = theme;
  return theme;
}

export function initTheme() {
  return apply(localStorage.getItem(KEY) || systemTheme());
}

export function toggleTheme() {
  const next = getTheme() === "dark" ? "light" : "dark";
  localStorage.setItem(KEY, next);
  return apply(next);
}
