import { useEffect, useState } from "react";

/*
 * Resolved design-token colors for SVG chart marks (Recharts). SVG
 * presentation attributes don't resolve var(), so values are read from the
 * live computed style and re-read whenever the theme toggle re-stamps
 * data-theme on <html>. Fallbacks are the light-theme values from
 * src/styles/tokens.css (used in jsdom, where no stylesheet is loaded).
 */
const TOKEN_FALLBACKS = {
  accent: "#3552d6",
  safe: "#157f3c",
  warn: "#a15c00",
  danger: "#c22a2a",
  border: "#e1e4ea",
  muted: "#5b6472",
};

function readTokens() {
  const styles = getComputedStyle(document.documentElement);
  const out = {};
  for (const name of Object.keys(TOKEN_FALLBACKS)) {
    out[name] = styles.getPropertyValue(`--${name}`).trim() || TOKEN_FALLBACKS[name];
  }
  return out;
}

export default function useChartTokens() {
  const [tokens, setTokens] = useState(readTokens);

  useEffect(() => {
    const observer = new MutationObserver(() => setTokens(readTokens()));
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return () => observer.disconnect();
  }, []);

  return tokens;
}
