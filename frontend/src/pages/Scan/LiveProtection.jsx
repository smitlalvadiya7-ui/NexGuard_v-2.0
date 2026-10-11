import { useEffect, useRef, useState } from "react";

/*
 * Live Scam Protection — parity for index.html toggleProtection()/
 * analyzeConversation() (old lines ~4453-4583). Fully client-side: browser
 * SpeechRecognition transcribes the mic, the same keyword rules score each
 * utterance, and speechSynthesis speaks a warning at risk >= 70. Renders a
 * "not supported" note where the API is missing (jsdom, Firefox, Safari).
 */
function scoreConversation(text) {
  const lower = text.toLowerCase();
  let risk = 0;
  let type = "Normal";
  const reasons = [];

  if (
    ["otp", "verify", "bank", "account blocked", "blocked", "money", "send money", "security code"].some(
      (needle) => lower.includes(needle)
    )
  ) {
    risk += 75;
    type = "Banking Scam";
    reasons.push("Banking verification pattern detected.");
  }
  if (["urgent", "send money", "immediately"].some((needle) => lower.includes(needle))) {
    risk += 50;
    type = "Financial Fraud";
    reasons.push("Urgency pressure tactic detected.");
  }
  if (["password", "security code"].some((needle) => lower.includes(needle))) {
    risk += 55;
    type = "Credential Theft";
    reasons.push("Sensitive credential request detected.");
  }

  risk = Math.min(100, risk);
  const level = risk >= 70 ? "HIGH" : risk >= 40 ? "MEDIUM" : "SAFE";
  return { risk, type, level, reasons };
}

const LEVEL_CLASS = {
  HIGH: "text-danger",
  MEDIUM: "text-warn",
  SAFE: "text-safe",
};

export default function LiveProtection() {
  const [active, setActive] = useState(false);
  const [transcript, setTranscript] = useState("Waiting for voice...");
  const [analysis, setAnalysis] = useState({ risk: 0, type: "Normal", level: "SAFE", reasons: [] });
  const [timeline, setTimeline] = useState([]);
  const recognitionRef = useRef(null);
  const activeRef = useRef(false);

  const Recognition =
    typeof window !== "undefined" && (window.SpeechRecognition || window.webkitSpeechRecognition);

  useEffect(() => {
    return () => {
      activeRef.current = false;
      try {
        recognitionRef.current?.stop();
      } catch {
        /* already stopped */
      }
    };
  }, []);

  function handleText(text) {
    setTranscript(text);
    const result = scoreConversation(text);
    setAnalysis(result);
    if (result.risk >= 70) {
      setTimeline((prev) => [
        { time: new Date().toLocaleTimeString(), type: result.type, risk: result.risk },
        ...prev.slice(0, 9),
      ]);
      try {
        const warning = new SpeechSynthesisUtterance(
          "Warning. High risk scam detected. Do not share OTP or banking information."
        );
        speechSynthesis.speak(warning);
      } catch {
        /* speech synthesis unavailable */
      }
    }
  }

  function toggle() {
    if (activeRef.current) {
      activeRef.current = false;
      setActive(false);
      try {
        recognitionRef.current?.stop();
      } catch {
        /* already stopped */
      }
      return;
    }

    const recognition = new Recognition();
    recognition.continuous = true;
    recognition.lang = "en-US";
    recognition.onresult = (event) => {
      const text = event.results[event.results.length - 1][0].transcript;
      handleText(text);
    };
    // Chrome ends/errors continuous sessions regularly — restart while active.
    recognition.onerror = () => {
      if (activeRef.current) recognition.start();
    };
    recognition.onend = () => {
      if (activeRef.current) recognition.start();
    };
    recognitionRef.current = recognition;
    activeRef.current = true;
    setActive(true);
    recognition.start();
  }

  if (!Recognition) {
    return (
      <div className="rounded-lg border border-border bg-panel p-4">
        <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">
          Live Scam Protection
        </h3>
        <p className="text-sm text-muted">
          Live microphone protection needs browser speech recognition (available in Chrome/Edge).
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3 rounded-lg border border-border bg-panel p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">
          Live Scam Protection
        </h3>
        <button
          type="button"
          onClick={toggle}
          className="rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-bg transition-opacity hover:opacity-90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          {active ? "Stop AI Protection" : "Start AI Protection"}
        </button>
      </div>

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div>
          <p className="text-xs text-muted">Status</p>
          <p className={`text-sm font-semibold ${active ? "text-safe" : "text-muted"}`}>
            {active ? "ACTIVE" : "INACTIVE"}
          </p>
        </div>
        <div>
          <p className="text-xs text-muted">Threat Level</p>
          <p className={`text-sm font-semibold ${LEVEL_CLASS[analysis.level]}`}>{analysis.level}</p>
        </div>
        <div>
          <p className="text-xs text-muted">Type</p>
          <p className="text-sm font-semibold text-text">{analysis.type}</p>
        </div>
        <div>
          <p className="text-xs text-muted">Risk Score</p>
          <p className={`text-sm font-semibold tabular-nums ${LEVEL_CLASS[analysis.level]}`}>
            {analysis.risk}%
          </p>
        </div>
      </div>

      <div className="rounded-lg bg-panel-2 p-3 text-sm text-text">{transcript}</div>
      <div className="rounded-lg bg-panel-2 p-3 text-sm text-muted">
        {analysis.reasons.length > 0 ? analysis.reasons.join(" ") : "No analysis yet."}
      </div>

      {timeline.length > 0 && (
        <ul className="space-y-1.5">
          {timeline.map((entry, i) => (
            <li key={`${entry.time}-${i}`} className="rounded-lg bg-danger/10 p-2 text-xs text-danger">
              ⚠ {entry.time} — {entry.type} — Risk {entry.risk}%
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
