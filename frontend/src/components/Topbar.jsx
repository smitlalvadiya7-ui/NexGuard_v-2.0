import { useState } from "react";
import { useLocation } from "react-router-dom";
import { getTheme, toggleTheme } from "../theme.js";
import { SunIcon, MoonIcon } from "./Icons.jsx";

const SECTION_TITLES = {
  "/": "Dashboard",
  "/scan": "Scan",
  "/activity": "Activity",
  "/reports": "Reports",
  "/model": "Model",
  "/settings": "Settings",
  "/admin": "Admin",
};

export default function Topbar() {
  const location = useLocation();
  const [theme, setTheme] = useState(getTheme());

  const title = SECTION_TITLES[location.pathname] || "NexGuard AI";

  function handleToggleTheme() {
    setTheme(toggleTheme());
  }

  return (
    <header className="flex h-14 shrink-0 items-center justify-between border-b border-border bg-panel px-6">
      <h2 className="text-lg font-semibold text-text">{title}</h2>
      <button
        type="button"
        onClick={handleToggleTheme}
        aria-label="Toggle theme"
        className="rounded-full p-2 text-muted transition-colors hover:bg-panel-2 hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        {theme === "dark" ? <SunIcon size={18} /> : <MoonIcon size={18} />}
      </button>
    </header>
  );
}
