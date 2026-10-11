import { useState } from "react";
import { apiFetch, FreeLimitError } from "../../api.js";
import { useToast } from "../../components/Toast.jsx";
import { ResultPanel } from "../../components/ResultPanel.jsx";
import EmbeddedLinks from "../../components/EmbeddedLinks.jsx";
import ReportVerdict from "../../components/ReportVerdict.jsx";
import ScanHistoryLookup from "../../components/ScanHistoryLookup.jsx";
import FreeLimitCard from "../../components/FreeLimitCard.jsx";

/*
 * URL scanner panel — parity target is index.html's #urlPage + scanUrl().
 *
 * POST /scan { url } (backend/main.py:1087) never populates scanned_links
 * for this endpoint today (verified: that field is only set by
 * /analyze-email, /analyze-voice, /analyze-screenshot and /gmail-emails via
 * aggregator.scan_embedded_links — renderUrlResult in the old UI never reads
 * it either). The <EmbeddedLinks> table is still wired defensively off
 * `result.scanned_links` so it "just works" if a future backend revision
 * adds sub-link scanning to this endpoint, per the task brief.
 */
export default function UrlPanel() {
  const { push } = useToast();
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [limitInfo, setLimitInfo] = useState(null);
  const [error, setError] = useState("");

  async function runScan() {
    const trimmed = url.trim();
    if (!trimmed) return;

    setBusy(true);
    setError("");
    setLimitInfo(null);
    setResult(null);
    try {
      const data = await apiFetch("/scan", { method: "POST", body: { url: trimmed } });
      setResult(data);
    } catch (err) {
      if (err instanceof FreeLimitError) {
        setLimitInfo(err.info);
      } else {
        const message = err.message || "Something went wrong. Try again.";
        setError(message);
        push("error", message);
      }
    } finally {
      setBusy(false);
    }
  }

  function handleSubmit(e) {
    e.preventDefault();
    runScan();
  }

  return (
    <div className="space-y-4">
      <form
        onSubmit={handleSubmit}
        className="flex flex-col gap-3 rounded-lg border border-border bg-panel p-4 sm:flex-row"
      >
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example-phishing-site.com/login"
          aria-label="URL to scan"
          className="flex-1 rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text outline-none focus-visible:ring-2 focus-visible:ring-accent"
        />
        <button
          type="submit"
          disabled={busy}
          className="shrink-0 rounded-lg bg-accent px-4 py-2 text-sm font-medium text-bg transition-opacity hover:opacity-90 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {busy ? "Scanning…" : "Scan URL"}
        </button>
      </form>

      {error && (
        <p data-testid="url-scan-error" className="text-sm text-danger">
          {error}
        </p>
      )}

      {limitInfo && <FreeLimitCard info={limitInfo} />}

      {!limitInfo && result && (
        <>
          <ResultPanel result={result} />
          <ScanHistoryLookup target={result.url || url.trim()} />
          <EmbeddedLinks links={result.scanned_links} />
          <ReportVerdict
            url={result.url || url.trim()}
            module="URL Scanner"
            verdict={result.verdict}
            score={result.risk_score ?? result.score ?? 0}
          />
        </>
      )}
    </div>
  );
}
