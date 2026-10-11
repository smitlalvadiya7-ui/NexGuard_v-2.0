import { useState } from "react";
import { apiFetch, FreeLimitError } from "../../api.js";
import { useToast } from "../../components/Toast.jsx";
import { ResultPanel } from "../../components/ResultPanel.jsx";
import UploadDropzone from "../../components/UploadDropzone.jsx";
import EmbeddedLinks from "../../components/EmbeddedLinks.jsx";
import FreeLimitCard from "../../components/FreeLimitCard.jsx";

/*
 * Screenshot phishing detector — parity target index.html #screenshotPage +
 * analyzeScreenshot(). POST /analyze-screenshot (backend/main.py:1318) OCRs
 * the image; the response carries the extracted text in `text` and its
 * indicators in `reasons` (normalized to `flags` for ResultPanel).
 */
export default function ScreenshotPanel() {
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
      const data = await apiFetch("/analyze-screenshot", { method: "POST", body: formData });
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

  const display = result && {
    ...result,
    flags: Array.isArray(result.flags) && result.flags.length > 0 ? result.flags : result.reasons,
  };

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">
        Upload suspicious screenshots, fake banking pages or scam chats.
      </p>

      <div className="space-y-3 rounded-lg border border-border bg-panel p-4">
        <UploadDropzone accept="image/*" label="Upload screenshot" onFile={setFile} />
        <button
          type="button"
          onClick={runScan}
          disabled={busy || !file}
          className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-bg transition-opacity hover:opacity-90 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {busy ? "Analyzing…" : "Analyze Screenshot"}
        </button>
      </div>

      {error && (
        <p data-testid="screenshot-scan-error" className="text-sm text-danger">
          {error}
        </p>
      )}

      {limitInfo && <FreeLimitCard info={limitInfo} />}

      {!limitInfo && display && (
        <>
          <ResultPanel result={display} />

          {result.text && (
            <div className="rounded-lg border border-border bg-panel p-4">
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">
                Extracted text
              </h3>
              <pre className="whitespace-pre-wrap break-words font-mono text-xs leading-relaxed text-text">
                {result.text}
              </pre>
            </div>
          )}

          <EmbeddedLinks links={result.scanned_links} />
        </>
      )}
    </div>
  );
}
