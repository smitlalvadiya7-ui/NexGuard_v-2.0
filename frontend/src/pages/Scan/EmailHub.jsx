import { useState } from "react";
import EmailPanel from "./EmailPanel.jsx";
import GmailPanel from "./GmailPanel.jsx";

/*
 * Unified Email box (WORK_PLAN Task 8) — one panel, two ways in, like the
 * voice page (upload + live detection together):
 *   upload — analyze a .eml/.msg/.txt file or pasted mail (EmailPanel)
 *   inbox  — scan the connected Gmail inbox (GmailPanel)
 * Other providers (Yahoo/Outlook via IMAP) plug in here later as more
 * inbox choices — postponed per the 2026-07-16 decision (Gmail-only first).
 */
const MODES = [
  { key: "upload", label: "Upload email file" },
  { key: "inbox", label: "Scan inbox (Gmail)" },
];

export default function EmailHub({ initialMode }) {
  const [mode, setMode] = useState(initialMode === "inbox" ? "inbox" : "upload");

  return (
    <div className="space-y-4">
      <div
        role="tablist"
        aria-label="Email source"
        className="inline-flex rounded-lg border border-border bg-panel p-1"
      >
        {MODES.map(({ key, label }) => {
          const active = mode === key;
          return (
            <button
              key={key}
              type="button"
              role="tab"
              aria-selected={active}
              onClick={() => setMode(key)}
              className={[
                "rounded-md px-3 py-1.5 text-sm font-medium transition-colors",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent",
                active ? "bg-accent text-bg" : "text-muted hover:text-text",
              ].join(" ")}
            >
              {label}
            </button>
          );
        })}
      </div>

      {mode === "upload" ? <EmailPanel /> : <GmailPanel />}
    </div>
  );
}
