import { useState } from "react";
import { apiFetch, FreeLimitError } from "../../api.js";
import { useToast } from "../../components/Toast.jsx";
import { ResultPanel } from "../../components/ResultPanel.jsx";
import UploadDropzone from "../../components/UploadDropzone.jsx";
import EmbeddedLinks from "../../components/EmbeddedLinks.jsx";
import FreeLimitCard from "../../components/FreeLimitCard.jsx";

/*
 * QR scanner — parity target index.html #qrPage + scanQR().
 * POST /scan-qr (backend/main.py:1114) decodes the image and runs the decoded
 * URL through the full /scan pipeline, so the response is the standard URL
 * contract (flags, tier_locked, ...) with `url` = the decoded payload; when
 * no QR is detected it returns {verdict: "UNKNOWN", analysis: "QR not
 * detected", indicators: []} instead.
 */
export default function QrPanel() {
  const { push } = useToast();
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [limitInfo, setLimitInfo] = useState(null);
  const [error, setError] = useState("");

  async function runScan() {
    if (!file) return;

    setBusy(true);
    setError("");
    setLimitInfo(null);
    setResult(null);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const data = await apiFetch("/scan-qr", { method: "POST", body: formData });
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

  const summary = result?.analysis || result?.ai_explanation;

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">
        Upload a QR image. NexGuard extracts the hidden data and scans the URL automatically.
      </p>

      <div className="space-y-3 rounded-lg border border-border bg-panel p-4">
        <UploadDropzone accept="image/*" label="Upload QR image" onFile={setFile} />
        <button
          type="button"
          onClick={runScan}
          disabled={busy || !file}
          className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-bg transition-opacity hover:opacity-90 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {busy ? "Scanning…" : "Scan QR"}
        </button>
      </div>

      {error && (
        <p data-testid="qr-scan-error" className="text-sm text-danger">
          {error}
        </p>
      )}

      {limitInfo && <FreeLimitCard info={limitInfo} />}

      {!limitInfo && result && (
        <>
          {summary && <p className="text-sm text-muted">{summary}</p>}
          <ResultPanel result={result} />
          <EmbeddedLinks links={result.scanned_links} />
        </>
      )}
    </div>
  );
}
