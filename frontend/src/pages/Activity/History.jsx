import { useCallback, useEffect, useState } from "react";
import { apiFetch, downloadBlob } from "../../api.js";
import { useToast } from "../../components/Toast.jsx";
import { VerdictBadge } from "../../components/VerdictBadge.jsx";
import DataTable from "../../components/DataTable.jsx";

/*
 * Scan history — parity target index.html #historyPage + loadHistoryPage().
 * GET /history (backend/main.py:1376) takes q/module/verdict/date/limit/offset
 * and returns an array of {id, module, verdict, score, target, summary,
 * timestamp}. The total count only travels in the X-Total-Count header, which
 * apiFetch doesn't surface — pagination therefore enables "Next" whenever a
 * full page came back (a full page may coincide with the exact end; the next
 * click then shows an empty page — harmless).
 */
const PAGE_SIZE = 20;

const MODULES = [
  "URL Scanner",
  "QR Scanner",
  "Email Analyzer",
  "Gmail Monitor",
  "Voice Analyzer",
  "Screenshot OCR",
  "Batch Scanner",
];

export default function History() {
  const { push } = useToast();
  const [rows, setRows] = useState([]);
  const [q, setQ] = useState("");
  const [module, setModule] = useState("");
  const [verdict, setVerdict] = useState("");
  const [date, setDate] = useState("");
  const [page, setPage] = useState(0);
  const [busyId, setBusyId] = useState(null);
  const [loaded, setLoaded] = useState(false);

  const load = useCallback(
    async (pageIndex, filters) => {
      const params = new URLSearchParams();
      params.set("limit", String(PAGE_SIZE));
      params.set("offset", String(pageIndex * PAGE_SIZE));
      if (filters.q) params.set("q", filters.q);
      if (filters.module) params.set("module", filters.module);
      if (filters.verdict) params.set("verdict", filters.verdict);
      if (filters.date) params.set("date", filters.date);
      try {
        const data = await apiFetch(`/history?${params.toString()}`);
        setRows(Array.isArray(data) ? data : []);
        setPage(pageIndex);
      } catch (err) {
        push("error", err.message || "Could not load history.");
      } finally {
        setLoaded(true);
      }
    },
    [push]
  );

  useEffect(() => {
    load(0, { q: "", module: "", verdict: "", date: "" });
  }, [load]);

  function search(pageIndex = 0) {
    load(pageIndex, { q: q.trim(), module, verdict, date });
  }

  function resetFilters() {
    setQ("");
    setModule("");
    setVerdict("");
    setDate("");
    load(0, { q: "", module: "", verdict: "", date: "" });
  }

  async function rescan(row) {
    setBusyId(row.id);
    try {
      const result = await apiFetch(`/history/${row.id}/rescan`, { method: "POST" });
      push(
        (result.verdict || "").toUpperCase() === "MALICIOUS" ? "error" : "success",
        `Re-scan: ${result.verdict || "done"} (${result.risk_score ?? result.score ?? 0})`
      );
      search(page);
    } catch (err) {
      push("error", err.message || "Re-scan failed.");
    } finally {
      setBusyId(null);
    }
  }

  async function downloadPdf(row) {
    try {
      await downloadBlob(`/history/${row.id}/report.pdf`, `NexGuard_Report_${row.id}.pdf`);
    } catch (err) {
      push("error", err.message || "PDF download failed.");
    }
  }

  const columns = [
    {
      key: "timestamp",
      label: "Time",
      render: (r) => <span className="text-xs text-muted">{String(r.timestamp || "").replace("T", " ")}</span>,
    },
    { key: "module", label: "Module" },
    { key: "target", label: "Target" },
    {
      key: "verdict",
      label: "Verdict",
      render: (r) => <VerdictBadge verdict={r.verdict} />,
    },
    { key: "score", label: "Risk" },
    {
      key: "actions",
      label: "Actions",
      sortable: false,
      render: (r) => (
        <span className="flex gap-2">
          <button
            type="button"
            onClick={() => rescan(r)}
            disabled={busyId === r.id}
            className="rounded-md border border-border bg-panel-2 px-2 py-1 text-xs font-medium text-text transition-colors hover:text-accent disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            {busyId === r.id ? "Scanning…" : "🔄 Re-scan"}
          </button>
          <button
            type="button"
            onClick={() => downloadPdf(r)}
            className="rounded-md border border-border bg-panel-2 px-2 py-1 text-xs font-medium text-text transition-colors hover:text-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            ⬇ PDF
          </button>
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">
        Search, filter and re-open every scan. Re-scan a target or export a PDF report.
      </p>

      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-panel p-3">
        <input
          type="text"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && search()}
          placeholder="Search URL or verdict…"
          aria-label="Search history"
          className="min-w-40 flex-1 rounded-lg border border-border bg-bg px-3 py-1.5 text-sm text-text outline-none focus-visible:ring-2 focus-visible:ring-accent"
        />
        <select
          value={module}
          onChange={(e) => setModule(e.target.value)}
          aria-label="Module filter"
          className="rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-text outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <option value="">All modules</option>
          {MODULES.map((m) => (
            <option key={m}>{m}</option>
          ))}
        </select>
        <select
          value={verdict}
          onChange={(e) => setVerdict(e.target.value)}
          aria-label="Verdict filter"
          className="rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-text outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <option value="">All verdicts</option>
          <option value="SAFE">Safe</option>
          <option value="SUSPICIOUS">Suspicious</option>
          <option value="MALICIOUS">Malicious</option>
        </select>
        <input
          type="date"
          value={date}
          onChange={(e) => setDate(e.target.value)}
          aria-label="Date filter"
          className="rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-text outline-none focus-visible:ring-2 focus-visible:ring-accent"
        />
        <button
          type="button"
          onClick={() => search()}
          className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-bg transition-opacity hover:opacity-90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          Search
        </button>
        <button
          type="button"
          onClick={resetFilters}
          className="rounded-lg border border-border bg-panel-2 px-3 py-1.5 text-sm font-medium text-text transition-colors hover:text-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          Reset
        </button>
      </div>

      {loaded && rows.length === 0 ? (
        <p className="py-10 text-center text-sm text-muted">
          No scans found. Run a scan and it will appear here.
        </p>
      ) : (
        <DataTable columns={columns} rows={rows} rowKey={(r) => r.id} />
      )}

      <div className="flex items-center justify-center gap-3 text-sm">
        <button
          type="button"
          onClick={() => search(page - 1)}
          disabled={page === 0}
          className="rounded-lg border border-border bg-panel-2 px-3 py-1.5 font-medium text-text transition-colors hover:text-accent disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          ‹ Prev
        </button>
        <span className="text-muted">Page {page + 1}</span>
        <button
          type="button"
          onClick={() => search(page + 1)}
          disabled={rows.length < PAGE_SIZE}
          className="rounded-lg border border-border bg-panel-2 px-3 py-1.5 font-medium text-text transition-colors hover:text-accent disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          Next ›
        </button>
      </div>
    </div>
  );
}
