/*
 * 2×2 confusion matrix. Correct cells (TP/TN) tint safe, error cells (FP/FN)
 * tint danger — always with an explicit text label per cell, never color
 * alone. Counts are pinned to en-US formatting like every other numeric
 * surface.
 */
function fmt(value) {
  return typeof value === "number" ? value.toLocaleString("en-US") : "—";
}

function Cell({ value, label, error }) {
  return (
    <div
      className={`rounded-lg border border-border p-3 text-center ${
        error ? "bg-danger/10" : "bg-safe/10"
      }`}
    >
      <p className={`text-xl font-semibold tabular-nums ${error ? "text-danger" : "text-safe"}`}>
        {fmt(value)}
      </p>
      <p className="mt-0.5 text-[11px] font-medium uppercase tracking-wide text-muted">{label}</p>
    </div>
  );
}

export default function ConfusionMatrix({ tp, fp, tn, fn }) {
  return (
    <div className="inline-grid grid-cols-2 gap-2">
      <Cell value={tp} label="True positives" />
      <Cell value={fp} label="False positives" error />
      <Cell value={fn} label="False negatives" error />
      <Cell value={tn} label="True negatives" />
    </div>
  );
}
