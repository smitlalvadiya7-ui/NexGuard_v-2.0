import { useCallback, useEffect, useRef, useState } from "react";
import { apiFetch } from "../api.js";
import { useAuth } from "../auth/AuthContext.jsx";
import { useToast } from "../components/Toast.jsx";

/*
 * Support center (WORK_PLAN Task 12): FAQ + a built-in assistant
 * (POST /support/ask, no API key) + a contact form that opens a ticket
 * (POST /support/tickets). Signed-in users see their tickets and any admin
 * follow-up (GET /support/tickets). Anonymous users can still submit.
 */
const CATEGORIES = [
  { value: "question", label: "General question" },
  { value: "problem", label: "Report a problem" },
  { value: "wrong_info", label: "Something looks wrong / incorrect info" },
  { value: "other", label: "Other" },
];

const STATUS_CLASS = {
  open: "text-warn",
  answered: "text-accent",
  resolved: "text-safe",
};

// Verdict chip when the assistant actually ran a scan (C1).
const VERDICT_CHIP = {
  SAFE: "border-safe/40 bg-safe/10 text-safe",
  SUSPICIOUS: "border-warn/40 bg-warn/10 text-warn",
  MALICIOUS: "border-danger/40 bg-danger/10 text-danger",
  UNKNOWN: "border-border bg-panel-2 text-muted",
};

function Panel({ title, children }) {
  return (
    <div className="rounded-lg border border-border bg-panel p-4">
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-muted">{title}</h2>
      {children}
    </div>
  );
}

export default function Support() {
  const { user } = useAuth();
  const { push } = useToast();
  const loggedIn = user && user !== "anonymous";

  const [faq, setFaq] = useState([]);
  const [openIdx, setOpenIdx] = useState(null);

  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState(null);
  const [asking, setAsking] = useState(false);
  // C3 — last few turns (not rendered) so follow-ups like "scan it again"
  // reuse the URL from earlier; the backend validates and caps this.
  const turnsRef = useRef([]);

  const [email, setEmail] = useState(loggedIn ? user.email : "");
  const [subject, setSubject] = useState("");
  const [category, setCategory] = useState("question");
  const [message, setMessage] = useState("");
  const [sending, setSending] = useState(false);
  const [sent, setSent] = useState(false);

  const [tickets, setTickets] = useState([]);

  const loadTickets = useCallback(async () => {
    if (!loggedIn) return;
    try {
      const data = await apiFetch("/support/tickets");
      setTickets(Array.isArray(data) ? data : []);
    } catch {
      /* non-fatal */
    }
  }, [loggedIn]);

  useEffect(() => {
    (async () => {
      try {
        const data = await apiFetch("/support/faq");
        setFaq(Array.isArray(data) ? data : []);
      } catch {
        setFaq([]);
      }
    })();
    loadTickets();
  }, [loadTickets]);

  async function ask() {
    const q = question.trim();
    if (!q) return;
    setAsking(true);
    setAnswer(null);
    try {
      const res = await apiFetch("/support/ask", {
        method: "POST",
        body: { question: q, history: turnsRef.current.slice(-6) },
      });
      setAnswer(res);
      if (res?.answer) {
        turnsRef.current.push({ role: "user", text: q }, { role: "bot", text: res.answer });
        turnsRef.current = turnsRef.current.slice(-6);
      }
    } catch (err) {
      push("error", err.message || "Assistant unavailable.");
    } finally {
      setAsking(false);
    }
  }

  async function submitTicket(e) {
    e.preventDefault();
    if (!email.trim() || !message.trim()) {
      push("error", "Please add your email and a message.");
      return;
    }
    setSending(true);
    try {
      await apiFetch("/support/tickets", {
        method: "POST",
        body: { email: email.trim(), subject: subject.trim(), category, message: message.trim() },
      });
      setSent(true);
      setSubject("");
      setMessage("");
      push("success", "Message sent — we'll get back to you.");
      loadTickets();
    } catch (err) {
      push("error", err.message || "Could not send your message.");
    } finally {
      setSending(false);
    }
  }

  const inputClass =
    "w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text outline-none focus-visible:ring-2 focus-visible:ring-accent";

  return (
    <div className="space-y-6">
      <header className="space-y-1">
        <h1 className="text-xl font-semibold">Support</h1>
        <p className="text-sm text-muted">
          Ask the assistant, browse the FAQ, or send our team a message.
        </p>
      </header>

      {/* Assistant */}
      <Panel title="Ask the assistant">
        <div className="flex flex-wrap gap-2">
          <input
            aria-label="Ask the assistant"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && ask()}
            placeholder="e.g. How does the voice scanner work?"
            className={inputClass + " flex-1"}
          />
          <button
            type="button"
            onClick={ask}
            disabled={asking || !question.trim()}
            className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-bg transition-opacity hover:opacity-90 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            {asking ? "…" : "Ask"}
          </button>
        </div>
        {answer && (
          <div className="mt-3 space-y-2 rounded-lg border border-border bg-panel-2/50 p-3">
            {answer.scan?.verdict && (
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`rounded-full border px-2 py-0.5 text-[11px] font-bold ${
                    VERDICT_CHIP[answer.scan.verdict] || VERDICT_CHIP.UNKNOWN
                  }`}
                >
                  {answer.scan.verdict}
                </span>
                <span className="text-xs text-muted">
                  risk {answer.scan.risk_score}/100
                </span>
              </div>
            )}
            <p className="whitespace-pre-line text-sm text-text">{answer.answer}</p>
            {answer.related?.length > 0 && (
              <div className="flex flex-wrap gap-1.5">
                {answer.related.map((r) => (
                  <button
                    key={r}
                    type="button"
                    onClick={() => {
                      setQuestion(r);
                      setAnswer(null);
                    }}
                    className="rounded-md bg-panel-2 px-2 py-1 text-[11px] text-muted transition-colors hover:text-text"
                  >
                    {r}
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
      </Panel>

      {/* FAQ */}
      <Panel title="Frequently asked questions">
        {faq.length === 0 ? (
          <p className="py-4 text-center text-sm text-muted">FAQ unavailable.</p>
        ) : (
          <ul className="divide-y divide-border">
            {faq.map((item, i) => (
              <li key={item.question}>
                <button
                  type="button"
                  onClick={() => setOpenIdx(openIdx === i ? null : i)}
                  className="flex w-full items-center justify-between gap-3 py-3 text-left text-sm font-medium text-text focus-visible:outline-none"
                >
                  <span>{item.question}</span>
                  <span aria-hidden="true" className="text-muted">
                    {openIdx === i ? "−" : "+"}
                  </span>
                </button>
                {openIdx === i && <p className="pb-3 text-sm text-muted">{item.answer}</p>}
              </li>
            ))}
          </ul>
        )}
      </Panel>

      {/* Contact form */}
      <Panel title="Contact us">
        {sent ? (
          <div className="space-y-2 py-2 text-sm">
            <p className="font-medium text-safe">Thanks — your message was sent.</p>
            <p className="text-muted">
              We'll get back to you by email. {loggedIn && "You can track it below."}
            </p>
            <button
              type="button"
              onClick={() => setSent(false)}
              className="text-xs text-accent hover:underline"
            >
              Send another message
            </button>
          </div>
        ) : (
          <form onSubmit={submitTicket} className="space-y-3">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <label htmlFor="sup-email" className="mb-1 block text-xs text-muted">
                  Your email
                </label>
                <input
                  id="sup-email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className={inputClass}
                  required
                />
              </div>
              <div>
                <label htmlFor="sup-cat" className="mb-1 block text-xs text-muted">
                  Topic
                </label>
                <select
                  id="sup-cat"
                  value={category}
                  onChange={(e) => setCategory(e.target.value)}
                  className={inputClass}
                >
                  {CATEGORIES.map((c) => (
                    <option key={c.value} value={c.value}>
                      {c.label}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div>
              <label htmlFor="sup-subject" className="mb-1 block text-xs text-muted">
                Subject (optional)
              </label>
              <input
                id="sup-subject"
                value={subject}
                onChange={(e) => setSubject(e.target.value)}
                className={inputClass}
              />
            </div>
            <div>
              <label htmlFor="sup-message" className="mb-1 block text-xs text-muted">
                Message
              </label>
              <textarea
                id="sup-message"
                rows={5}
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                className={inputClass}
                required
              />
            </div>
            <button
              type="submit"
              disabled={sending}
              className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-bg transition-opacity hover:opacity-90 disabled:opacity-60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              {sending ? "Sending…" : "Send message"}
            </button>
          </form>
        )}
      </Panel>

      {/* My tickets */}
      {loggedIn && tickets.length > 0 && (
        <Panel title="Your messages">
          <ul className="space-y-3">
            {tickets.map((t) => (
              <li key={t.id} className="rounded-lg border border-border bg-panel-2/40 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-sm font-medium text-text">
                    {t.subject || t.message.slice(0, 60)}
                  </span>
                  <span className={`text-xs font-semibold uppercase ${STATUS_CLASS[t.status] || "text-muted"}`}>
                    {t.status}
                  </span>
                </div>
                <p className="mt-1 text-xs text-muted">{t.message}</p>
                {t.admin_reply && (
                  <div className="mt-2 rounded-md border-l-2 border-accent bg-panel px-3 py-2">
                    <p className="text-[10px] font-semibold uppercase tracking-wide text-accent">
                      Support reply
                    </p>
                    <p className="text-sm text-text">{t.admin_reply}</p>
                  </div>
                )}
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </div>
  );
}
