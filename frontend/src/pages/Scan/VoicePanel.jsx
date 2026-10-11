import { useState } from "react";
import { apiFetch, FreeLimitError } from "../../api.js";
import { useToast } from "../../components/Toast.jsx";
import { ResultPanel } from "../../components/ResultPanel.jsx";
import UploadDropzone from "../../components/UploadDropzone.jsx";
import EmbeddedLinks from "../../components/EmbeddedLinks.jsx";
import FreeLimitCard from "../../components/FreeLimitCard.jsx";
import LiveProtection from "./LiveProtection.jsx";

/*
 * Voice scam analyzer — parity target index.html #voicePage + analyzeVoice().
 * POST /analyze-voice (backend/main.py:1278) transcribes the clip; the
 * response carries the transcript in `text` and scam-phrase indicators in
 * `reasons` (normalized to `flags` for ResultPanel). The old page's "Live
 * Scam Protection" mic section is ported as <LiveProtection /> below.
 */
export default function VoicePanel() {
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
      const data = await apiFetch("/analyze-voice", { method: "POST", body: formData });
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

  const LANGUAGE_NAMES = {
    en: "English", hi: "Hindi", gu: "Gujarati", ta: "Tamil", te: "Telugu",
    mr: "Marathi", bn: "Bengali", pa: "Punjabi", kn: "Kannada", ml: "Malayalam",
    ur: "Urdu", es: "Spanish", fr: "French", de: "German", zh: "Chinese",
    ar: "Arabic", ru: "Russian", pt: "Portuguese", ja: "Japanese", ko: "Korean",
  };
  const hasRatio = typeof result?.scam_ratio === "number";
  const ratioClass =
    result?.scam_ratio >= 70 ? "text-danger" : result?.scam_ratio >= 40 ? "text-warn" : "text-safe";

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">
        Detect scam conversations, fake banking calls, OTP harvesting and pressure tactics.
      </p>

      <div className="space-y-3 rounded-lg border border-border bg-panel p-4">
        <UploadDropzone accept="audio/*" label="Upload voice file" onFile={setFile} />
        <button
          type="button"
          onClick={runScan}
          disabled={busy || !file}
          className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-bg transition-opacity hover:opacity-90 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {busy ? "Analyzing…" : "Analyze Voice"}
        </button>
      </div>

      {error && (
        <p data-testid="voice-scan-error" className="text-sm text-danger">
          {error}
        </p>
      )}

      {limitInfo && <FreeLimitCard info={limitInfo} />}

      {!limitInfo && display && (
        <>
          <ResultPanel result={display} />

          {(hasRatio || result.language) && (
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 rounded-lg border border-border bg-panel px-4 py-3 text-sm">
              {hasRatio && (
                <span className={`font-semibold ${ratioClass}`}>
                  {result.scam_ratio}% likely scam
                </span>
              )}
              {result.confidence && (
                <span className="text-xs text-muted">{result.confidence} confidence</span>
              )}
              {result.language && (
                <span className="text-xs text-muted">
                  Language: {LANGUAGE_NAMES[result.language] || result.language}
                </span>
              )}
            </div>
          )}

          {result.text && (
            <div className="rounded-lg border border-border bg-panel p-4">
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">
                Transcript
              </h3>
              <p className="whitespace-pre-wrap break-words text-sm leading-relaxed text-text">
                {result.text}
              </p>
            </div>
          )}

          <EmbeddedLinks links={result.scanned_links} />
        </>
      )}

      <LiveProtection />
    </div>
  );
}
