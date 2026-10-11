import { useState } from "react";
import { apiFetch, FreeLimitError } from "../../api.js";
import { useToast } from "../../components/Toast.jsx";
import { VerdictBadge } from "../../components/VerdictBadge.jsx";
import AuthBadges from "../../components/AuthBadges.jsx";
import FreeLimitCard from "../../components/FreeLimitCard.jsx";
import SenderOriginBadge from "../../components/SenderOriginBadge.jsx";

/*
 * Gmail inbox monitor — honest contract (WORK_PLAN Task 2).
 * GET /gmail-emails (backend/main.py) returns a status OBJECT:
 *   {status: "connected"|"not_connected"|"error"|"demo", emails: [...], detail?}
 * not_connected -> "Connect Gmail" setup card with an explicit, clearly
 * labeled "Try with sample emails" button (GET /gmail-emails?demo=1).
 * A broken or missing connection NEVER renders fake inbox rows.
 */
const VERDICT_BORDER = {
  MALICIOUS: "border-l-danger",
  SUSPICIOUS: "border-l-warn",
};

function score(email) {
  const value = email.risk_score ?? email.score ?? 0;
  return Math.max(0, Math.min(100, Math.round(value)));
}

function scoreClass(verdict) {
  const v = String(verdict || "").toUpperCase();
  if (v === "MALICIOUS") return "text-danger";
  if (v === "SUSPICIOUS") return "text-warn";
  return "text-safe";
}

const SETUP_STEPS = [
  "Create an OAuth client (type: Desktop app) in Google Cloud Console with the Gmail API enabled.",
  "Download the client file and save it as backend/credentials.json.",
  "Restart the backend, then click Scan Gmail Inbox — a browser window opens once to authorize read-only access.",
];

export default function GmailPanel() {
  const { push } = useToast();
  const [result, setResult] = useState(null); // {status, emails, detail}
  const [busy, setBusy] = useState(false);
  const [limitInfo, setLimitInfo] = useState(null);
  const [error, setError] = useState("");

  async function runScan(demo = false) {
    setBusy(true);
    setError("");
    setLimitInfo(null);
    setResult(null);
    try {
      const data = await apiFetch(demo ? "/gmail-emails?demo=1" : "/gmail-emails");
      // status object contract; tolerate unknown shapes as an error
      if (data && typeof data === "object" && data.status) {
        setResult({ emails: [], ...data });
      } else {
        setResult({ status: "error", detail: "Unexpected response from the backend.", emails: [] });
      }
    } catch (err) {
      if (err instanceof FreeLimitError) {
        setLimitInfo(err.info);
      } else {
        const message = err.message || "Gmail scan failed. Make sure the backend is running.";
        setError(message);
        push("error", message);
      }
    } finally {
      setBusy(false);
    }
  }

  const status = result?.status;
  const emails = result?.emails || [];

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">
        Scan recent inbox messages and highlight suspicious emails with AI reasoning.
      </p>

      <button
        type="button"
        onClick={() => runScan(false)}
        disabled={busy}
        className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-bg transition-opacity hover:opacity-90 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        {busy ? "Scanning…" : "Scan Gmail Inbox"}
      </button>

      {error && (
        <p data-testid="gmail-scan-error" className="text-sm text-danger">
          {error}
        </p>
      )}

      {limitInfo && <FreeLimitCard info={limitInfo} />}

      {!limitInfo && status === "not_connected" && (
        <div className="space-y-4 rounded-lg border border-border bg-panel p-6">
          <div className="space-y-1">
            <p className="text-base font-semibold text-text">Connect Gmail</p>
            <p className="text-sm text-muted">
              Gmail is not connected yet, so there is nothing to scan. Set it up once:
            </p>
          </div>
          <ol className="list-decimal space-y-2 pl-5 text-sm text-muted">
            {SETUP_STEPS.map((step) => (
              <li key={step}>
                {step.includes("backend/credentials.json") ? (
                  <>
                    Download the client file and save it as{" "}
                    <code className="font-mono text-xs text-text">backend/credentials.json</code>.
                  </>
                ) : (
                  step
                )}
              </li>
            ))}
          </ol>
          <div className="flex flex-wrap items-center gap-3 border-t border-border pt-4">
            <button
              type="button"
              onClick={() => runScan(true)}
              disabled={busy}
              className="rounded-lg border border-border bg-panel-2 px-4 py-2 text-sm font-medium text-text transition-opacity hover:opacity-90 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              Try with sample emails
            </button>
            <span className="text-xs text-muted">
              Analyzes bundled demo emails so you can preview the scanner — not your inbox.
            </span>
          </div>
        </div>
      )}

      {!limitInfo && status === "error" && (
        <div className="space-y-2 rounded-lg border border-danger/40 bg-panel p-6">
          <p className="text-base font-semibold text-danger">Gmail scan failed</p>
          <p className="text-sm text-muted">{result.detail || "Unknown error."}</p>
          <p className="text-xs text-muted">
            Nothing was scanned. Fix the connection and try again — NexGuard never shows
            placeholder results as if they were your inbox.
          </p>
        </div>
      )}

      {!limitInfo && status === "demo" && (
        <div
          data-testid="gmail-sample-banner"
          className="rounded-lg border border-warn/50 bg-warn/10 px-4 py-3 text-sm text-text"
        >
          <span className="font-semibold">Sample data.</span> These are bundled demo emails
          analyzed by the real scanner — not your inbox.
        </div>
      )}

      {!limitInfo && status === "connected" && emails.length === 0 && (
        <p className="py-6 text-center text-sm text-muted">
          No emails found in the last 30 days.
        </p>
      )}

      {!limitInfo && (status === "connected" || status === "demo") && emails.length > 0 && (
        <ul className="space-y-3">
          {emails.map((email, i) => {
            const verdict = String(email.verdict || "SAFE").toUpperCase();
            return (
              <li
                key={`${i}-${email.subject}`}
                className={`space-y-2 rounded-lg border border-border border-l-4 bg-panel p-4 ${
                  VERDICT_BORDER[verdict] || "border-l-safe"
                }`}
              >
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <p className="min-w-0 flex-1 truncate text-sm font-medium text-text">
                    {email.subject || "No Subject"}
                  </p>
                  <VerdictBadge verdict={verdict} />
                </div>
                <p className="truncate text-xs text-muted">From: {email.from || "Unknown"}</p>

                {Array.isArray(email.reasons) && email.reasons.length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {email.reasons.slice(0, 3).map((reason, j) => (
                      <span
                        key={j}
                        className="rounded-md bg-panel-2 px-2 py-1 font-mono text-[10px] leading-tight text-text"
                      >
                        {reason}
                      </span>
                    ))}
                  </div>
                )}

                <AuthBadges auth={email.auth_results} />
                <SenderOriginBadge origin={email.sender_origin} ratio={email.genuine_ratio} />

                <div className="flex flex-wrap items-center gap-3 text-xs">
                  <span className={`font-semibold ${scoreClass(verdict)}`}>{score(email)}/100</span>
                  {email.links_found > 0 && (
                    <span className="text-muted">
                      {email.links_found} link{email.links_found > 1 ? "s" : ""} scanned
                    </span>
                  )}
                  {email.source && (
                    <span className="uppercase tracking-wide text-[10px] text-muted">
                      {email.source}
                    </span>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
