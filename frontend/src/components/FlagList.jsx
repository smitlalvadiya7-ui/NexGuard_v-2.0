/*
 * Compact list of scan-result flags (result.flags). Renders nothing at all
 * (no empty box/border) when there's nothing to show, so ResultPanel can
 * drop it in unconditionally.
 */
export function FlagList({ flags }) {
  if (!Array.isArray(flags) || flags.length === 0) return null;

  return (
    <ul className="space-y-1.5">
      {flags.map((flag, i) => (
        <li
          key={i}
          className="flex items-start gap-2 rounded-md bg-panel-2 px-3 py-2 font-mono text-xs leading-relaxed text-text"
        >
          <span aria-hidden="true" className="text-danger">
            ▸
          </span>
          <span className="break-words">{flag}</span>
        </li>
      ))}
    </ul>
  );
}
