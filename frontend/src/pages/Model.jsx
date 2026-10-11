import { useEffect, useState } from "react";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ReferenceLine,
  LabelList,
} from "recharts";
import { apiFetch } from "../api.js";
import StatTile from "../components/StatTile.jsx";
import DataTable from "../components/DataTable.jsx";
import ConfusionMatrix from "../components/ConfusionMatrix.jsx";
import useChartTokens from "../hooks/useChartTokens.js";

/*
 * Model performance — parity target index.html #modelPage. Two data sources:
 *   GET /model-metrics          (backend/main.py:494, ml/metrics.json) —
 *     offline eval: headline + per-model table, ROC arrays {fpr,tpr},
 *     feature_importances [{feature, importance}], confusion_matrix
 *     {tn,fp,fn,tp}, dataset info, generated_at.
 *   GET /model-metrics-realworld (main.py:535) — live eval: precision/recall/
 *     f1/FPR, scan-time percentiles, confusion matrix, FP/FN example URLs,
 *     counts, dataset_sources, generated_at.
 * Either file may be missing → {available:false} → friendly empty state.
 */
function pct(value, digits = 1) {
  return typeof value === "number" ? `${(value * 100).toFixed(digits)}%` : "—";
}

function Panel({ title, aside, children }) {
  return (
    <div className="rounded-lg border border-border bg-panel p-4">
      <div className="mb-3 flex items-baseline justify-between gap-2">
        <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">{title}</h3>
        {aside}
      </div>
      {children}
    </div>
  );
}

function EmptyCard({ children }) {
  return (
    <div className="rounded-lg border border-dashed border-border bg-panel/50 py-12 text-center text-sm text-muted">
      {children}
    </div>
  );
}

function tooltipStyle() {
  return {
    background: "var(--panel)",
    border: "1px solid var(--border)",
    borderRadius: 8,
    color: "var(--text)",
    fontSize: 12,
  };
}

function RocChart({ roc, tokens }) {
  const fpr = roc?.fpr || [];
  const tpr = roc?.tpr || [];
  if (fpr.length === 0) return <EmptyCard>No ROC curve recorded.</EmptyCard>;
  const data = fpr.map((f, i) => ({ fpr: f, tpr: tpr[i] ?? 0 }));

  return (
    <div className="h-64">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 8, right: 12, bottom: 4, left: -16 }}>
          <CartesianGrid stroke={tokens.border} vertical={false} />
          <XAxis
            dataKey="fpr"
            type="number"
            domain={[0, 1]}
            tickFormatter={(v) => v.toFixed(1)}
            tick={{ fill: tokens.muted, fontSize: 11 }}
            tickLine={false}
            axisLine={{ stroke: tokens.border }}
            label={{ value: "False-positive rate", position: "insideBottom", offset: -2, fill: tokens.muted, fontSize: 11 }}
          />
          <YAxis
            type="number"
            domain={[0, 1]}
            tickFormatter={(v) => v.toFixed(1)}
            tick={{ fill: tokens.muted, fontSize: 11 }}
            tickLine={false}
            axisLine={false}
          />
          <Tooltip
            contentStyle={tooltipStyle()}
            formatter={(value) => (typeof value === "number" ? value.toFixed(3) : value)}
            labelFormatter={(label) => `FPR ${Number(label).toFixed(3)}`}
          />
          <ReferenceLine
            segment={[
              { x: 0, y: 0 },
              { x: 1, y: 1 },
            ]}
            stroke={tokens.border}
            strokeDasharray="4 4"
          />
          <Line
            type="monotone"
            dataKey="tpr"
            name="TPR"
            stroke={tokens.accent}
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 4 }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

function FeatureImportance({ features, tokens }) {
  const rows = (features || []).slice(0, 10);
  if (rows.length === 0) return <EmptyCard>No feature importances recorded.</EmptyCard>;

  return (
    <div style={{ height: Math.max(140, rows.length * 30) }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={rows} layout="vertical" margin={{ top: 0, right: 40, bottom: 0, left: 24 }}>
          <XAxis type="number" hide />
          <YAxis
            type="category"
            dataKey="feature"
            width={120}
            tick={{ fill: tokens.muted, fontSize: 11 }}
            tickLine={false}
            axisLine={false}
          />
          <Tooltip
            contentStyle={tooltipStyle()}
            cursor={{ fill: "transparent" }}
            formatter={(value) => (typeof value === "number" ? value.toFixed(4) : value)}
          />
          <Bar dataKey="importance" name="Importance" fill={tokens.accent} barSize={12} radius={[0, 4, 4, 0]}>
            <LabelList
              dataKey="importance"
              position="right"
              formatter={(v) => (typeof v === "number" ? v.toFixed(3) : v)}
              style={{ fill: tokens.muted, fontSize: 10 }}
            />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function ExampleList({ title, urls }) {
  return (
    <div>
      <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">{title}</p>
      {(urls || []).length === 0 ? (
        <p className="text-xs text-muted">None 🎉</p>
      ) : (
        <ul className="space-y-1">
          {urls.map((url) => (
            <li key={url} className="truncate break-all font-mono text-xs text-text" title={url}>
              {url}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function Model() {
  const tokens = useChartTokens();
  const [offline, setOffline] = useState(null);
  const [realworld, setRealworld] = useState(null);

  useEffect(() => {
    let alive = true;
    (async () => {
      const [offRes, rwRes] = await Promise.allSettled([
        apiFetch("/model-metrics"),
        apiFetch("/model-metrics-realworld"),
      ]);
      if (!alive) return;
      if (offRes.status === "fulfilled") setOffline(offRes.value);
      if (rwRes.status === "fulfilled") setRealworld(rwRes.value);
    })();
    return () => {
      alive = false;
    };
  }, []);

  const hasOffline = offline?.available !== false && offline?.headline;
  const hasRealworld = realworld?.available !== false && typeof realworld?.precision === "number";

  const modelRows = hasOffline
    ? Object.entries(offline.models || {}).map(([name, m]) => ({ name, ...m }))
    : [];
  const modelColumns = [
    { key: "name", label: "Model" },
    { key: "accuracy", label: "Accuracy", render: (r) => pct(r.accuracy) },
    { key: "precision", label: "Precision", render: (r) => pct(r.precision) },
    { key: "recall", label: "Recall", render: (r) => pct(r.recall) },
    { key: "f1", label: "F1", render: (r) => pct(r.f1) },
    { key: "roc_auc", label: "ROC AUC", render: (r) => pct(r.roc_auc) },
  ];

  const cmOffline = offline?.confusion_matrix;
  const cmReal = realworld?.confusion_matrix;
  const counts = realworld?.counts;

  return (
    <div className="space-y-6">
      <header className="space-y-1">
        <h1 className="text-xl font-semibold">Model Performance</h1>
        <p className="text-sm text-muted">
          How the full scan pipeline performs on live URLs — plus the offline benchmark of its
          ML component.
        </p>
      </header>

      {/* ------------------- Real-world eval (headline) ---------------------- */}
      <section className="space-y-4">
        <div className="flex flex-wrap items-baseline gap-2">
          <h2 className="text-sm font-semibold text-text">Real-world evaluation</h2>
          <span className="rounded-full bg-accent/15 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-accent">
            Full pipeline
          </span>
          {hasRealworld && realworld.evaluated_on_date && (
            <span className="text-xs text-muted">evaluated {realworld.evaluated_on_date}</span>
          )}
        </div>
        <p className="text-xs text-muted">
          The number that matters: every scanner channel (reputation, content, heuristics, ML)
          working together on live phishing and legitimate URLs.
        </p>

        {!hasRealworld ? (
          <EmptyCard>
            Real-world metrics are not available yet. Run the live evaluation script to generate
            them.
          </EmptyCard>
        ) : (
          <>
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
              <StatTile label="Precision" value={pct(realworld.precision)} />
              <StatTile label="Recall" value={pct(realworld.recall)} />
              <StatTile label="F1" value={pct(realworld.f1)} />
              <StatTile label="False-positive rate" value={pct(realworld.false_positive_rate)} />
              <StatTile label="Median scan" value={realworld.median_scan_time_ms} suffix="ms" />
              <StatTile label="P95 scan" value={realworld.p95_scan_time_ms} suffix="ms" />
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              {cmReal && (
                <Panel title="Confusion matrix (live URLs)">
                  <ConfusionMatrix tp={cmReal.tp} fp={cmReal.fp} tn={cmReal.tn} fn={cmReal.fn} />
                  {counts && (
                    <p className="mt-3 text-xs text-muted">
                      {counts.legit_scored}/{counts.legit_total} legitimate and{" "}
                      {counts.phish_scored}/{counts.phish_total} phishing URLs scored
                      {counts.phish_dead_excluded
                        ? ` (${counts.phish_dead_excluded} dead phishing URLs excluded)`
                        : ""}
                      {realworld.dataset_sources
                        ? ` — sources: ${realworld.dataset_sources.legit} / ${realworld.dataset_sources.phish}`
                        : ""}
                      .
                    </p>
                  )}
                </Panel>
              )}
              <Panel title="Misclassified examples">
                <div className="space-y-4">
                  <ExampleList title="False positives" urls={realworld.examples?.false_positives} />
                  <ExampleList title="False negatives" urls={realworld.examples?.false_negatives} />
                </div>
              </Panel>
            </div>
          </>
        )}
      </section>

      {/* --------------- Offline ML component benchmark ---------------------- */}
      <section className="space-y-4">
        <div className="flex flex-wrap items-baseline gap-2">
          <h2 className="text-sm font-semibold text-text">Offline ML component benchmark</h2>
          {hasOffline && (
            <>
              <span className="rounded-full bg-panel-2 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-muted">
                {offline.model}
              </span>
              {offline.generated_at && (
                <span className="text-xs text-muted">
                  generated {String(offline.generated_at).slice(0, 10)}
                </span>
              )}
            </>
          )}
        </div>
        <p className="text-xs text-muted">
          This measures ONLY the machine-learning model, one channel inside the scanner — not the
          product. The full pipeline above is what users experience.
        </p>

        {!hasOffline ? (
          <EmptyCard>
            Offline metrics are not available yet. Train the model (backend/ml) to generate
            metrics.json.
          </EmptyCard>
        ) : (
          <>
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
              <StatTile label="Accuracy" value={pct(offline.headline.accuracy)} />
              <StatTile label="Precision" value={pct(offline.headline.precision)} />
              <StatTile label="Recall" value={pct(offline.headline.recall)} />
              <StatTile label="F1" value={pct(offline.headline.f1)} />
              <StatTile label="ROC AUC" value={pct(offline.headline.roc_auc)} />
            </div>

            <Panel title="Model comparison">
              <DataTable columns={modelColumns} rows={modelRows} rowKey={(r) => r.name} />
              {offline.dataset && (
                <p className="mt-2 text-xs text-muted">
                  Dataset: {offline.dataset.n_samples?.toLocaleString("en-US")} URLs (
                  {offline.dataset.n_phishing?.toLocaleString("en-US")} phishing /{" "}
                  {offline.dataset.n_legitimate?.toLocaleString("en-US")} legitimate),{" "}
                  {offline.dataset.n_features} features, {offline.dataset.n_test?.toLocaleString("en-US")}{" "}
                  test rows.
                </p>
              )}
            </Panel>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              <Panel title="ROC curve">
                <RocChart roc={offline.roc_curve} tokens={tokens} />
              </Panel>
              <Panel title="Feature importance · top 10">
                <FeatureImportance features={offline.feature_importances} tokens={tokens} />
              </Panel>
            </div>

            {cmOffline && (
              <Panel title="Confusion matrix (test set)">
                <ConfusionMatrix
                  tp={cmOffline.tp}
                  fp={cmOffline.fp}
                  tn={cmOffline.tn}
                  fn={cmOffline.fn}
                />
              </Panel>
            )}
          </>
        )}
      </section>
    </div>
  );
}
