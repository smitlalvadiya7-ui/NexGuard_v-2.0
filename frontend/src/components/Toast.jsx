import { createContext, useCallback, useContext, useMemo, useRef, useState } from "react";

const ToastContext = createContext(undefined);

const AUTO_DISMISS_MS = 4000;

let nextId = 0;

// Left-border accent per kind; the toast body itself stays a neutral panel
// card so the color reads as a status indicator, not a wall of alarming color.
const KIND_BORDER = {
  success: "border-l-safe",
  error: "border-l-danger",
  info: "border-l-accent",
};

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const timers = useRef(new Map());

  const dismiss = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
    const timer = timers.current.get(id);
    if (timer) {
      clearTimeout(timer);
      timers.current.delete(id);
    }
  }, []);

  const push = useCallback(
    (kind, text) => {
      const id = ++nextId;
      setToasts((prev) => [...prev, { id, kind, text }]);
      timers.current.set(
        id,
        setTimeout(() => dismiss(id), AUTO_DISMISS_MS)
      );
      return id;
    },
    [dismiss]
  );

  const value = useMemo(() => ({ push, dismiss }), [push, dismiss]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pointer-events-none fixed right-4 top-4 z-50 flex w-80 max-w-[calc(100vw-2rem)] flex-col gap-2">
        {toasts.map((t) => (
          <div
            key={t.id}
            role="status"
            className={`pointer-events-auto flex items-start justify-between gap-3 rounded-lg border border-border border-l-4 bg-panel px-4 py-3 text-sm text-text shadow-lg animate-[toast-in_0.2s_ease-out] ${
              KIND_BORDER[t.kind] || KIND_BORDER.info
            }`}
          >
            <p className="min-w-0 break-words">{t.text}</p>
            <button
              type="button"
              onClick={() => dismiss(t.id)}
              aria-label="Dismiss notification"
              className="shrink-0 text-muted hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent rounded"
            >
              &times;
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (ctx === undefined) {
    throw new Error("useToast must be used within a ToastProvider");
  }
  return ctx;
}
