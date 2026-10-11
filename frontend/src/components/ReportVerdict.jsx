import { useState } from "react";
import { apiFetch } from "../api.js";
import { useToast } from "./Toast.jsx";

/*
 * "Report incorrect verdict" — parity for index.html reportVerdict()/
 * submitVerdictFeedback() (old lines ~4629-4668). POST /feedback
 * (backend/main.py:849, anonymous allowed) with the label the user believes
 * is correct; accepted reports feed the active-learning retrain set.
 */
export default function ReportVerdict({ url, module = "URL Scanner", verdict, score }) {
  const { push } = useToast();
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  if (!url) return null;

  async function submit(label) {
    setBusy(true);
    try {
      await apiFetch("/feedback", {
        method: "POST",
        body: {
          scan_url: url,
          module,
          predicted_verdict: verdict || "",
          predicted_score: score || 0,
          user_label: label,
        },
      });
      push("success", "Thanks — your report was submitted for admin review.");
      setOpen(false);
    } catch (err) {
      push("error", err.message || "Could not submit the report.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rounded-lg border border-border bg-panel p-3">
      {!open ? (
        <button
          type="button"
          onClick={() => setOpen(true)}
          className="w-full rounded-lg border border-border bg-transparent px-3 py-1.5 text-sm text-muted transition-colors hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          🚩 Report incorrect verdict
        </button>
      ) : (
        <div className="space-y-2">
          <p className="text-sm text-muted">
            Current verdict for <b className="break-all text-text">{url}</b>:{" "}
            <b className="text-text">{verdict || "—"}</b> ({score ?? 0}%). What is the correct
            label?
          </p>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              disabled={busy}
              onClick={() => submit("safe")}
              className="rounded-lg border border-border bg-panel-2 px-3 py-1.5 text-sm font-medium text-safe transition-opacity hover:opacity-80 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              ✓ Actually Safe
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() => submit("malicious")}
              className="rounded-lg border border-border bg-panel-2 px-3 py-1.5 text-sm font-medium text-danger transition-opacity hover:opacity-80 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              ⚠ Actually Malicious
            </button>
            <button
              type="button"
              onClick={() => setOpen(false)}
              className="rounded-lg px-3 py-1.5 text-sm text-muted transition-colors hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
