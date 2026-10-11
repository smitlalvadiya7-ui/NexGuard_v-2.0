import { useState } from "react";
import { apiFetch, FreeLimitError } from "../../api.js";
import { useToast } from "../../components/Toast.jsx";
import UploadDropzone from "../../components/UploadDropzone.jsx";
import FreeLimitCard from "../../components/FreeLimitCard.jsx";

/*
 * AI Image Check — POST /analyze-image-origin (backend/image_origin.py).
 * The engine is honest about certainty: AI_GENERATED only on metadata proof
 * (and only then a generator is named), LIKELY_* from the local classifier,
 * UNCERTAIN otherwise. This panel renders that honesty as-is: a custom card
 * (ResultPanel is phishing-verdict-shaped) with findings + action links.
 */

const VERDICTS = {
  AI_GENERATED: { emoji: "🤖", title: "AI-generated (confirmed)", tone: "text-danger" },
  LIKELY_AI: { emoji: "🤖", title: "Likely AI-generated", tone: "text-warning" },
  LIKELY_REAL: { emoji: "🧑", title: "Likely a real photo", tone: "text-success" },
  UNCERTAIN: { emoji: "❓", title: "Uncertain", tone: "text-muted" },
};

export default function ImageOriginPanel() {
  const { push } = useToast();
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [limitInfo, setLimitInfo] = useState(null);
  const [error, setError] = useState("");

  async function runCheck() {
    if (!file) return;
    setBusy(true);
    setError("");
    setLimitInfo(null);
    setResult(null);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const data = await apiFetch("/analyze-image-origin", { method: "POST", body: formData });
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

  const v = result && (VERDICTS[result.verdict] || VERDICTS.UNCERTAIN);

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted">
        Find out if a picture was made by AI (ChatGPT, Midjourney, Gemini…) or
        is a real photo. Runs fully on this machine — the image is not sent
        anywhere else.
      </p>

      <div className="space-y-3 rounded-lg border border-border bg-panel p-4">
        <UploadDropzone accept="image/*" label="Upload image" onFile={setFile} />
        <button
          type="button"
          onClick={runCheck}
          disabled={busy || !file}
          className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-bg transition-opacity hover:opacity-90 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {busy ? "Checking…" : "Check image"}
        </button>
      </div>

      {error && (
        <p data-testid="image-origin-error" className="text-sm text-danger">
          {error}
        </p>
      )}

      {limitInfo && <FreeLimitCard info={limitInfo} />}

      {!limitInfo && result && v && (
        <div className="space-y-4">
          <div className="rounded-lg border border-border bg-panel p-4">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-2xl" aria-hidden="true">{v.emoji}</span>
              <h3 className={`text-base font-semibold ${v.tone}`}>{v.title}</h3>
              {result.verdict !== "AI_GENERATED" && result.confidence > 0 && (
                <span className="rounded-full border border-border px-2 py-0.5 text-xs text-muted">
                  confidence {result.confidence}%
                </span>
              )}
            </div>

            <p className="mt-2 text-sm text-text">{result.analysis}</p>

            {result.generator && (
              <p className="mt-2 text-sm">
                Made with{" "}
                {result.generator_link ? (
                  <a
                    href={result.generator_link}
                    target="_blank"
                    rel="noreferrer"
                    className="font-medium text-accent underline"
                  >
                    {result.generator}
                  </a>
                ) : (
                  <span className="font-medium">{result.generator}</span>
                )}{" "}
                — proven by the file's own metadata.
              </p>
            )}

            {Array.isArray(result.reasons) && result.reasons.length > 0 && (
              <div className="mt-3">
                <h4 className="text-xs font-semibold uppercase tracking-wide text-muted">
                  What was found
                </h4>
                <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-text">
                  {result.reasons.map((r) => (
                    <li key={r}>{r}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {Array.isArray(result.actions) && result.actions.length > 0 && (
            <div className="rounded-lg border border-border bg-panel p-4">
              <h4 className="text-xs font-semibold uppercase tracking-wide text-muted">
                What you can do
              </h4>
              <ul className="mt-2 space-y-1.5 text-sm">
                {result.actions.map((a) => (
                  <li key={a.label}>
                    {a.url ? (
                      <a
                        href={a.url}
                        target="_blank"
                        rel="noreferrer"
                        className="text-accent underline"
                      >
                        {a.label}
                      </a>
                    ) : (
                      <span className="text-text">{a.label}</span>
                    )}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
