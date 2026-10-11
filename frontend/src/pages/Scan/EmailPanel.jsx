import { useState } from "react";
import { apiFetch, FreeLimitError } from "../../api.js";
import { useToast } from "../../components/Toast.jsx";
import { ResultPanel } from "../../components/ResultPanel.jsx";
import UploadDropzone from "../../components/UploadDropzone.jsx";
import EmbeddedLinks from "../../components/EmbeddedLinks.jsx";
import AuthBadges from "../../components/AuthBadges.jsx";
import FreeLimitCard from "../../components/FreeLimitCard.jsx";
import SenderOriginBadge from "../../components/SenderOriginBadge.jsx";

/*
 * Email analyzer — parity target index.html #emailPage + analyzeEmail().
 * POST /analyze-email (backend/main.py:1156) accepts ONLY a multipart `file`
 * field (verified in the handler), so the pasted-text path wraps the textarea
 * content in a File before posting — parse_email happily reads plain text.
 * A chosen file always wins over pasted text.
 *
 * The analyzer response uses `reasons` (not `flags`, which is URL-contract
 * only), so the ResultPanel input is normalized below.
 */
export default function EmailPanel() {
  const { push } = useToast();
  const [file, setFile] = useState(null);
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [limitInfo, setLimitInfo] = useState(null);
  const [error, setError] = useState("");

  async function runScan() {
    const pasted = text.trim();
    const payload =
      file || (pasted ? new File([pasted], "pasted-email.eml", { type: "message/rfc822" }) : null);
    if (!payload) return;

    setBusy(true);
    setError("");
    setLimitInfo(null);
    setResult(null);
    try {
      const formData = new FormData();
      formData.append("file", payload);
      const data = await apiFetch("/analyze-email", { method: "POST", body: formData });
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
  const attachments = Array.isArray(result?.attachment_results)
    ? result.attachment_results
    : Array.isArray(result?.attachments)
      ? result.attachments
      : [];

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">
        Upload .txt, .eml or .msg files — or paste a raw email — to detect fraud, suspicious
        keywords and phishing indicators.
      </p>

      <div className="space-y-3 rounded-lg border border-border bg-panel p-4">
        <UploadDropzone accept=".eml,.msg,.txt" label="Upload email file" onFile={setFile} />
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={6}
          aria-label="Paste raw email (headers and body)"
          placeholder="Or paste the raw email here — headers and body…"
          className="w-full rounded-lg border border-border bg-bg px-3 py-2 font-mono text-xs text-text outline-none focus-visible:ring-2 focus-visible:ring-accent"
        />
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={runScan}
            disabled={busy || (!file && !text.trim())}
            className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-bg transition-opacity hover:opacity-90 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            {busy ? "Analyzing…" : "Analyze Email"}
          </button>
          {file && <span className="text-xs text-muted">An uploaded file overrides pasted text.</span>}
        </div>
      </div>

      {error && (
        <p data-testid="email-scan-error" className="text-sm text-danger">
          {error}
        </p>
      )}

      {limitInfo && <FreeLimitCard info={limitInfo} />}

      {!limitInfo && display && (
        <>
          <div className="space-y-2 rounded-lg border border-border bg-panel p-4">
            <div className="flex flex-wrap items-baseline justify-between gap-2 text-sm">
              <span className="font-medium text-text">{result.subject || "No Subject"}</span>
              <span className="text-muted">From: {result.sender || "Unknown"}</span>
            </div>
            <AuthBadges auth={result.auth_results} />
            <SenderOriginBadge origin={result.sender_origin} ratio={result.genuine_ratio} />
          </div>

          <ResultPanel result={display} />
          <EmbeddedLinks links={result.scanned_links} />

          {attachments.length > 0 && (
            <div className="rounded-lg border border-border bg-panel p-4">
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">
                Attachments
              </h3>
              <ul className="space-y-1 text-sm">
                {attachments.map((att, i) => (
                  <li key={`${i}-${att.name}`} className="flex items-baseline justify-between gap-3">
                    <span className="truncate text-text">{att.name || att.filename || "attachment"}</span>
                    <span
                      className={`shrink-0 text-xs font-medium ${
                        att.status && att.status !== "clean" ? "text-danger" : "text-safe"
                      }`}
                    >
                      {att.status || "clean"}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </div>
  );
}
