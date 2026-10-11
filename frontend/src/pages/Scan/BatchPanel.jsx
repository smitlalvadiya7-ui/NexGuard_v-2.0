import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { apiFetch, downloadBlob } from "../../api.js";
import { useAuth } from "../../auth/AuthContext.jsx";
import { useToast } from "../../components/Toast.jsx";
import { VerdictBadge } from "../../components/VerdictBadge.jsx";
import UploadDropzone from "../../components/UploadDropzone.jsx";
import DataTable from "../../components/DataTable.jsx";

/*
 * Batch URL scanner — parity target index.html #batchPage + startBatch().
 * Premium-only end to end: POST /scan-batch (backend/main.py:1921,
 * require_premium — admins/superadmins pass regardless of tier) accepts a
 * multipart form with EITHER a CSV/TXT `file` OR a pasted `urls` field
 * (newline/comma separated) and returns {job_id, total, status}. Progress is
 * polled from GET /scan-batch/{job_id} until status leaves "running"
 * ("completed" | "error"), then CSV/PDF exports unlock.
 */
const POLL_MS = 1000;

// UNKNOWN ("not checked") and ERROR carry no risk number — showing "0" for
// them reads as "zero risk", the opposite of what they mean.
const SCORED = new Set(["MALICIOUS", "SUSPICIOUS", "SAFE"]);
const isScored = (r) => SCORED.has(String(r.verdict || "").toUpperCase());

const COLUMNS = [
  { key: "idx", label: "#", sortValue: (r) => r.idx },
  { key: "url", label: "URL" },
  {
    key: "verdict",
    label: "Verdict",
    render: (r) => <VerdictBadge verdict={r.verdict} />,
  },
  {
    key: "risk_score",
    label: "Score",
    sortValue: (r) => (isScored(r) ? r.risk_score : -1),
    render: (r) => (isScored(r) ? r.risk_score : "—"),
  },
  { key: "summary", label: "Summary" },
];

function plural(n, one, many) {
  return n === 1 ? one : many;
}

function isPremiumViewer(user) {
  if (!user || user === "anonymous") return false;
  return user.tier === "premium" || user.role === "admin" || user.role === "superadmin";
}

export default function BatchPanel() {
  const { user } = useAuth();
  const { push } = useToast();
  const [file, setFile] = useState(null);
  const [urls, setUrls] = useState("");
  const [busy, setBusy] = useState(false);
  const [job, setJob] = useState(null); // last polled _batch_view
  const [jobId, setJobId] = useState(null);
  const [error, setError] = useState("");
  const timerRef = useRef(null);

  function stopPolling() {
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
  }

  useEffect(() => {
    if (!jobId) return undefined;

    timerRef.current = setInterval(async () => {
      try {
        const view = await apiFetch(`/scan-batch/${jobId}`);
        setJob(view);
        if (view.status !== "running") {
          stopPolling();
          if (view.status === "error" && view.error) {
            setError(view.error);
          }
        }
      } catch (err) {
        stopPolling();
        setError(err.message || "Batch job polling failed.");
      }
    }, POLL_MS);

    return stopPolling;
  }, [jobId]);

  async function startBatch() {
    const pasted = urls.trim();
    if (!file && !pasted) return;

    setBusy(true);
    setError("");
    setJob(null);
    setJobId(null);
    try {
      const formData = new FormData();
      if (file) formData.append("file", file);
      if (pasted) formData.append("urls", pasted);
      const data = await apiFetch("/scan-batch", { method: "POST", body: formData });
      setJob({
        job_id: data.job_id,
        status: data.status,
        total: data.total,
        done: 0,
        counts: {},
        results: [],
        invalid_count: data.invalid_count || 0,
        over_limit: data.over_limit || 0,
        limit: data.limit || 200,
      });
      setJobId(data.job_id);
    } catch (err) {
      const message = err.message || "Could not start the batch scan.";
      setError(message);
      push("error", message);
    } finally {
      setBusy(false);
    }
  }

  function resetBatch() {
    stopPolling();
    setFile(null);
    setUrls("");
    setJob(null);
    setJobId(null);
    setError("");
  }

  async function exportJob(kind) {
    try {
      await downloadBlob(
        `/scan-batch/${jobId}/${kind === "csv" ? "export.csv" : "report.pdf"}`,
        `NexGuard_Batch_${jobId}.${kind}`
      );
    } catch (err) {
      push("error", err.message || "Export failed.");
    }
  }

  if (!isPremiumViewer(user)) {
    return (
      <div className="space-y-3 rounded-lg border border-border bg-panel p-8 text-center">
        <div aria-hidden="true" className="text-3xl">
          🔒
        </div>
        <p className="text-sm text-text">
          Batch scanning is a <b>Premium feature</b>. Upgrade to scan hundreds of URLs at once
          with a results table and CSV/PDF export.
        </p>
        <Link
          to="/settings"
          className="inline-flex rounded-full bg-accent px-4 py-2 text-sm font-semibold text-bg transition-opacity hover:opacity-90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          Go Premium
        </Link>
      </div>
    );
  }

  const total = job?.total || 0;
  const done = job?.done || 0;
  const pct = total > 0 ? Math.round((done / total) * 100) : 0;
  const terminal = job && job.status !== "running";
  // The server returns rows in input order and tags each with its input
  // position; fall back to list position for older responses.
  const rows = (job?.results || []).map((r, i) => ({
    ...r,
    idx: (Number.isInteger(r.index) ? r.index : i) + 1,
  }));
  const counts = job?.counts || {};
  const invalidCount = job?.invalid_count || 0;
  const overLimit = job?.over_limit || 0;
  const limit = job?.limit || 200;

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">
        Upload a CSV / list of URLs (or paste them) and scan up to 200 at once with live
        progress, a results table, and CSV / PDF export.
      </p>

      <div className="space-y-3 rounded-lg border border-border bg-panel p-4">
        <UploadDropzone accept=".csv,.txt" label="Upload CSV / TXT file" onFile={setFile} />
        <p className="text-center text-xs text-muted">— or paste URLs below (one per line) —</p>
        <textarea
          value={urls}
          onChange={(e) => setUrls(e.target.value)}
          rows={6}
          aria-label="Paste URLs (one per line)"
          placeholder={"https://example.com\nsuspicious-site.tk/login\nanother-domain.com"}
          className="w-full rounded-lg border border-border bg-bg px-3 py-2 font-mono text-xs text-text outline-none focus-visible:ring-2 focus-visible:ring-accent"
        />
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={startBatch}
            disabled={busy || (!file && !urls.trim())}
            className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-bg transition-opacity hover:opacity-90 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            {busy ? "Starting…" : "▶ Start Batch Scan"}
          </button>
          <button
            type="button"
            onClick={resetBatch}
            className="rounded-lg border border-border bg-panel-2 px-4 py-2 text-sm font-medium text-text transition-colors hover:text-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            Clear
          </button>
        </div>
      </div>

      {error && (
        <p data-testid="batch-scan-error" className="text-sm text-danger">
          {error}
        </p>
      )}

      {job && (
        <div className="space-y-3 rounded-lg border border-border bg-panel p-4">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">Progress</h3>
          <div
            role="progressbar"
            aria-valuenow={pct}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label="Batch scan progress"
            className="h-2 w-full overflow-hidden rounded-full bg-panel-2"
          >
            <div
              className="h-full rounded-full bg-accent transition-[width]"
              style={{ width: `${pct}%` }}
            />
          </div>
          <p className="text-sm text-text">
            {done} / {total} scanned{terminal ? ` — ${job.status}` : "…"}
          </p>

          <div className="flex flex-wrap gap-2 text-xs">
            <span className="rounded-md bg-danger/10 px-2 py-1 font-medium text-danger">
              {counts.MALICIOUS || 0} malicious
            </span>
            <span className="rounded-md bg-warn/10 px-2 py-1 font-medium text-warn">
              {counts.SUSPICIOUS || 0} suspicious
            </span>
            <span className="rounded-md bg-safe/10 px-2 py-1 font-medium text-safe">
              {counts.SAFE || 0} safe
            </span>
            <span
              className="rounded-md bg-muted/10 px-2 py-1 font-medium text-muted"
              title="No threat-intelligence source could be reached for these URLs — they have not been cleared."
            >
              {counts.UNKNOWN || 0} not checked
            </span>
            <span className="rounded-md bg-muted/10 px-2 py-1 font-medium text-muted">
              {counts.ERROR || 0} errors
            </span>
          </div>

          {(invalidCount > 0 || overLimit > 0) && (
            <ul data-testid="batch-input-notes" className="space-y-1 text-xs text-warn">
              {invalidCount > 0 && (
                <li>
                  {invalidCount} {plural(invalidCount, "line was", "lines were")} not valid
                  web addresses and {plural(invalidCount, "was", "were")} skipped.
                </li>
              )}
              {overLimit > 0 && (
                <li>
                  {overLimit} {plural(overLimit, "URL was", "URLs were")} not scanned — over
                  the {limit}-URL limit. Split the list and run them separately.
                </li>
              )}
            </ul>
          )}

          {terminal && rows.length > 0 && (
            <div className="flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => exportJob("csv")}
                className="rounded-lg border border-border bg-panel-2 px-3 py-1.5 text-sm font-medium text-text transition-colors hover:text-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                ⬇ Export CSV
              </button>
              <button
                type="button"
                onClick={() => exportJob("pdf")}
                className="rounded-lg border border-border bg-panel-2 px-3 py-1.5 text-sm font-medium text-text transition-colors hover:text-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                ⬇ Export PDF
              </button>
            </div>
          )}

          {rows.length > 0 && <DataTable columns={COLUMNS} rows={rows} rowKey={(r) => r.idx} />}
        </div>
      )}
    </div>
  );
}
