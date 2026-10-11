import { VerdictBadge } from "./VerdictBadge.jsx";

/*
 * Compact per-link verdict table for a result's `scanned_links` (populated by
 * /analyze-email, /analyze-voice, /analyze-screenshot, /gmail-emails via
 * aggregator.scan_embedded_links — and defensively read on /scan too).
 * Renders nothing when there are no links, so panels can drop it in
 * unconditionally.
 */
export default function EmbeddedLinks({ links }) {
  const rows = Array.isArray(links) ? links : [];
  if (rows.length === 0) return null;

  return (
    <div className="rounded-lg border border-border bg-panel p-4">
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">
        Embedded links
      </h3>
      <table className="w-full text-left text-sm">
        <tbody>
          {rows.map((link, i) => (
            <tr key={`${i}-${link.url}`} className="border-t border-border first:border-t-0">
              <td className="max-w-0 truncate break-all py-2 pr-3 text-text">{link.url}</td>
              <td className="py-2 text-right">
                <VerdictBadge verdict={link.verdict} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
