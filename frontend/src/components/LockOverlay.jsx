import { Link } from "react-router-dom";

/*
 * Generic premium-gate wrapper. When `locked`, the wrapped children are
 * blurred and made non-interactive/inert to assistive tech, and a centered
 * "Upgrade to Premium" CTA (-> /settings) is overlaid on top. When not
 * locked, children render exactly as passed in — no extra markup.
 */
export function LockOverlay({ locked, children }) {
  // `?? null`: a bare `return children` would return `undefined` for a
  // childless call (React treats a component returning undefined as a bug,
  // not as "render nothing" — that requires an explicit null).
  if (!locked) return children ?? null;

  return (
    <div className="relative">
      <div aria-hidden="true" inert className="pointer-events-none select-none blur-sm">
        {children}
      </div>
      <div className="absolute inset-0 flex items-center justify-center rounded-md bg-panel/60">
        <Link
          to="/settings"
          className="inline-flex items-center gap-1.5 whitespace-nowrap rounded-full bg-accent px-3 py-1.5 text-xs font-semibold text-bg shadow-sm transition-opacity hover:opacity-90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          🔒 Upgrade to Premium
        </Link>
      </div>
    </div>
  );
}
