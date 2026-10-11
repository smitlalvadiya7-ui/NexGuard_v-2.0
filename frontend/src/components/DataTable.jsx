import { useMemo, useState } from "react";

/*
 * Plain sortable table shared by Batch/History/Watchlist/Admin. Header click
 * sorts (ascending, then descending on the same column). No pagination inside
 * — the caller slices its rows first.
 *
 * columns: [{ key, label, sortable = true, render?(row), sortValue?(row) }]
 *   render     — custom cell content (defaults to String(row[key]))
 *   sortValue  — custom comparable (defaults to row[key])
 * rows: array of plain objects
 * rowKey(row, index) — stable React key (defaults to the index)
 */
function compare(a, b) {
  if (a === b) return 0;
  if (a === null || a === undefined) return -1;
  if (b === null || b === undefined) return 1;
  if (typeof a === "number" && typeof b === "number") return a - b;
  return String(a).localeCompare(String(b), undefined, { numeric: true });
}

export default function DataTable({ columns, rows, rowKey }) {
  const [sort, setSort] = useState(null); // { key, dir: 1 | -1 }

  function toggleSort(key) {
    setSort((prev) => (prev?.key === key ? { key, dir: -prev.dir } : { key, dir: 1 }));
  }

  const sorted = useMemo(() => {
    if (!sort) return rows;
    const col = columns.find((c) => c.key === sort.key);
    const value = col?.sortValue || ((row) => row[sort.key]);
    return [...rows].sort((a, b) => sort.dir * compare(value(a), value(b)));
  }, [rows, sort, columns]);

  return (
    <div className="overflow-x-auto rounded-lg border border-border bg-panel">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-border">
            {columns.map((col) => (
              <th key={col.key} className="px-3 py-2 text-xs font-semibold uppercase tracking-wide text-muted">
                {col.sortable === false ? (
                  col.label
                ) : (
                  <button
                    type="button"
                    onClick={() => toggleSort(col.key)}
                    aria-label={`Sort by ${col.label}`}
                    className="inline-flex items-center gap-1 uppercase tracking-wide hover:text-text focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  >
                    {col.label}
                    {sort?.key === col.key && (
                      <span aria-hidden="true">{sort.dir === 1 ? "▲" : "▼"}</span>
                    )}
                  </button>
                )}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="px-3 py-6 text-center text-sm text-muted">
                No rows.
              </td>
            </tr>
          ) : (
            sorted.map((row, i) => (
              <tr key={rowKey ? rowKey(row, i) : i} className="border-t border-border first:border-t-0">
                {columns.map((col) => (
                  <td key={col.key} className="max-w-xs truncate break-all px-3 py-2 align-top text-text">
                    {col.render ? col.render(row) : String(row[col.key] ?? "")}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}
