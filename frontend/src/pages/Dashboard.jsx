import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  BarChart,
  Bar,
  LabelList,
} from "recharts";
import { apiFetch } from "../api.js";
import { useAuth } from "../auth/AuthContext.jsx";
import { useToast } from "../components/Toast.jsx";
import { VerdictBadge } from "../components/VerdictBadge.jsx";
import StatTile from "../components/StatTile.jsx";
import useLiveAlerts from "../hooks/useLiveAlerts.js";
import useChartTokens from "../hooks/useChartTokens.js";

/*
 * Dashboard — parity target index.html #dashboard (stats grid 1650-1667,
 * usage card 1669-1688, analytics 1730-1765, recent scans + live feed
 * 1767-1795). Data: GET /stats, GET /analytics, GET /live-threats seed +
 * /ws/live-alerts appends (backend/main.py:2011, 2103, 2290, 2318).
 *
 * Chart colors: the verdict green/amber/red is the app's STATUS palette —
 * every colored mark ships with a text label (legend rows, chips, tooltips),
 * never color alone (red↔amber is deutan-confusable by design-system choice;
 * labels are the mandated secondary encoding). Single-series charts use the
 * one accent hue. Token colors come from useChartTokens (SVG presentation
 * attributes don't resolve var()).
 */

const TOOL_SHORTCUTS = [
  { type: "url", icon: "🔗", title: "URL Scanner", blurb: "Phishing & malicious URL detection" },
  { type: "qr", icon: "▣", title: "QR Scanner", blurb: "Decode QR codes and scan the target" },
  { type: "email", icon: "✉️", title: "Email Security", blurb: "Upload a mail or scan your Gmail inbox" },
  { type: "voice", icon: "🎤", title: "Voice Analyzer", blurb: "Scam-call transcript scoring" },
  { type: "screenshot", icon: "🖼", title: "Screenshot Detector", blurb: "OCR fake pages & scam chats" },
  { type: "batch", icon: "🗂", title: "Batch Scanner", blurb: "Scan many URLs at once" },
];

function Panel({ title, aside, children }) {
  return (
    <div className="rounded-lg border border-border bg-panel p-4">
      <div className="mb-3 flex items-baseline justify-between gap-2">
        <h2 className="text-xs font-semibold uppercase tracking-wide text-muted">{title}</h2>
        {aside}
      </div>
      {children}
    </div>
  );
}

function EmptySlot({ children }) {
  return <p className="py-10 text-center text-sm text-muted">{children}</p>;
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

function VerdictDonut({ distribution, tokens }) {
  const data = [
    { name: "Safe", key: "safe", value: distribution.safe, color: tokens.safe },
    { name: "Suspicious", key: "suspicious", value: distribution.suspicious, color: tokens.warn },
    { name: "Malicious", key: "malicious", value: distribution.malicious, color: tokens.danger },
  ];
  const total = data.reduce((sum, d) => sum + d.value, 0);
  if (total === 0) return <EmptySlot>No scans yet.</EmptySlot>;

  return (
    <div className="flex flex-wrap items-center gap-4">
      <div className="h-44 w-44">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data.filter((d) => d.value > 0)}
              dataKey="value"
              nameKey="name"
              innerRadius="62%"
              outerRadius="100%"
              stroke="var(--panel)"
              strokeWidth={2}
            >
              {data
                .filter((d) => d.value > 0)
                .map((d) => (
                  <Cell key={d.key} fill={d.color} />
                ))}
            </Pie>
            <Tooltip contentStyle={tooltipStyle()} />
          </PieChart>
        </ResponsiveContainer>
      </div>
      {/* Legend: label + count next to each swatch — identity is never color-alone */}
      <ul className="space-y-1.5 text-sm">
        {data.map((d) => (
          <li key={d.key} className="flex items-center gap-2">
            <span
              aria-hidden="true"
              className="h-2.5 w-2.5 shrink-0 rounded-sm"
              style={{ background: d.color }}
            />
            <span className="text-text">{d.name}</span>
            <span className="tabular-nums text-muted">{d.value.toLocaleString("en-US")}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function ActivityBars({ series, tokens }) {
  // Stacked safe/suspicious/malicious per day (Task 4): useful even on
  // all-safe days, unlike the old threats-only line that sat at zero.
  const data = series.map((p) => ({ ...p, label: p.date.slice(5) }));
  const legend = [
    { name: "Safe", key: "safe", color: tokens.safe },
    { name: "Suspicious", key: "suspicious", color: tokens.warn },
    { name: "Malicious", key: "malicious", color: tokens.danger },
  ];
  return (
    <div>
      <div className="h-52">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -24 }}>
            <CartesianGrid stroke={tokens.border} vertical={false} />
            <XAxis
              dataKey="label"
              tick={{ fill: tokens.muted, fontSize: 11 }}
              tickLine={false}
              axisLine={{ stroke: tokens.border }}
              interval="preserveStartEnd"
            />
            <YAxis
              allowDecimals={false}
              tick={{ fill: tokens.muted, fontSize: 11 }}
              tickLine={false}
              axisLine={false}
            />
            <Tooltip contentStyle={tooltipStyle()} cursor={{ fill: "transparent" }} />
            <Bar dataKey="safe" name="Safe" stackId="a" fill={tokens.safe} />
            <Bar dataKey="suspicious" name="Suspicious" stackId="a" fill={tokens.warn} />
            <Bar dataKey="malicious" name="Malicious" stackId="a" fill={tokens.danger} radius={[3, 3, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
      {/* Legend: label next to each swatch — identity is never color-alone */}
      <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs">
        {legend.map((d) => (
          <li key={d.key} className="flex items-center gap-1.5">
            <span
              aria-hidden="true"
              className="h-2 w-2 shrink-0 rounded-sm"
              style={{ background: d.color }}
            />
            <span className="text-muted">{d.name}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function TopBars({ rows, nameKey, tokens }) {
  if (rows.length === 0) return <EmptySlot>No threat data yet.</EmptySlot>;
  const data = rows.slice(0, 6);
  return (
    <div style={{ height: Math.max(120, data.length * 34) }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ top: 0, right: 28, bottom: 0, left: 8 }}>
          <XAxis type="number" hide />
          <YAxis
            type="category"
            dataKey={nameKey}
            width={110}
            tick={{ fill: tokens.muted, fontSize: 12 }}
            tickLine={false}
            axisLine={false}
          />
          <Tooltip contentStyle={tooltipStyle()} cursor={{ fill: "transparent" }} />
          <Bar dataKey="count" name="Count" fill={tokens.accent} barSize={14} radius={[0, 4, 4, 0]}>
            <LabelList dataKey="count" position="right" style={{ fill: tokens.muted, fontSize: 11 }} />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

const SEVERITY_CLASS = {
  CRITICAL: "bg-danger/15 text-danger",
  HIGH: "bg-warn/15 text-warn",
};

// Severity color strip on the row's left edge (Task 5)
const SEVERITY_STRIP = {
  CRITICAL: "border-l-danger",
  HIGH: "border-l-warn",
};

function feedItemFromAlert(alert) {
  return {
    type: alert.verdict || alert.type || "THREAT",
    target: alert.target || "",
    severity: alert.severity || "HIGH",
    source: alert.source || "Live scan",
    time: alert.time || new Date().toISOString(),
  };
}

function domainOf(target) {
  try {
    return new URL(target).hostname;
  } catch {
    return String(target || "").split("/")[0];
  }
}

function minutesAgo(iso) {
  if (!iso) return null;
  const ms = Date.now() - new Date(iso).getTime();
  if (Number.isNaN(ms)) return null;
  const mins = Math.max(0, Math.round(ms / 60000));
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  return `${Math.round(mins / 60)} h ago`;
}

const FEED_REFRESH_SECONDS = 300; // matches the backend's 5-min feed cache

// The "auto-refresh in m:ss" text keeps its own seconds. Held in Dashboard,
// the tick re-rendered the whole page — all three charts — once a second,
// which is the lag the dashboard showed while open (2026-10-09,
// tests/dashboard-render-cost.test.jsx). The parent remounts this with a new
// key after each feed load, which restarts the count.
function FeedCountdown({ seconds, onElapsed }) {
  const [left, setLeft] = useState(seconds);

  useEffect(() => {
    const tick = setInterval(() => setLeft((s) => Math.max(0, s - 1)), 1000);
    return () => clearInterval(tick);
  }, []);

  useEffect(() => {
    if (left === 0) onElapsed();
  }, [left, onElapsed]);

  return ` · auto-refresh in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
}

export default function Dashboard() {
  const { user } = useAuth();
  const { push } = useToast();
  const tokens = useChartTokens();
  const [stats, setStats] = useState(null);
  const [analytics, setAnalytics] = useState(null);
  const [feed, setFeed] = useState([]);
  const [feedMeta, setFeedMeta] = useState(null); // {status, sources, fetched_at, detail}
  const [feedLoads, setFeedLoads] = useState(0); // restarts the countdown
  const [activityDays, setActivityDays] = useState(7);

  const applyThreatFeed = useCallback((value) => {
    // Honest feed object (Task 5); tolerate the old bare-array shape too.
    if (Array.isArray(value)) {
      setFeed(value.map(feedItemFromAlert));
      setFeedMeta({ status: "live", sources: [], fetched_at: null });
    } else if (value && typeof value === "object") {
      setFeed((value.threats || []).map(feedItemFromAlert));
      setFeedMeta(value);
    }
  }, []);

  const loadThreats = useCallback(async () => {
    try {
      applyThreatFeed(await apiFetch("/live-threats"));
    } catch {
      setFeedMeta({ status: "unavailable", detail: "Could not reach the backend." });
    }
    setFeedLoads((n) => n + 1);
  }, [applyThreatFeed]);

  const loadAnalytics = useCallback(async (days = 7) => {
    try {
      setAnalytics(await apiFetch(`/analytics?days=${days}`));
    } catch {
      setAnalytics(null);
    }
  }, []);

  function selectActivityDays(days) {
    setActivityDays(days);
    loadAnalytics(days);
  }

  useEffect(() => {
    let alive = true;
    (async () => {
      const [statsRes, analyticsRes, threatsRes] = await Promise.allSettled([
        apiFetch("/stats"),
        apiFetch("/analytics?days=7"),
        apiFetch("/live-threats"),
      ]);
      if (!alive) return;
      if (statsRes.status === "fulfilled") setStats(statsRes.value);
      if (analyticsRes.status === "fulfilled") setAnalytics(analyticsRes.value);
      if (threatsRes.status === "fulfilled") applyThreatFeed(threatsRes.value);
    })();
    return () => {
      alive = false;
    };
  }, []);

  useLiveAlerts(
    useCallback(
      (alert) => {
        setFeed((prev) => [feedItemFromAlert(alert), ...prev].slice(0, 30));
        push(
          alert.verdict === "MALICIOUS" ? "error" : "info",
          `Live alert: ${alert.verdict || "threat"} — ${alert.target || "unknown target"}`
        );
      },
      [push]
    )
  );

  const loggedIn = user && user !== "anonymous";
  const distribution = analytics?.verdict_distribution || { safe: 0, suspicious: 0, malicious: 0 };
  const activity = analytics?.scan_activity || [];
  const recent = analytics?.recent_scans || [];
  const geo = analytics?.threat_geo || [];
  const statsLoading = stats === null;

  // "Scans today vs your recent daily average" — a genuine trend from the
  // activity series (today's total vs the mean of the earlier days).
  const todayTrend = (() => {
    if (activity.length < 3) return null;
    const totals = activity.map((d) => (d.safe || 0) + (d.suspicious || 0) + (d.malicious || 0));
    const today = totals[totals.length - 1];
    const prior = totals.slice(0, -1);
    const avg = prior.reduce((s, n) => s + n, 0) / prior.length;
    if (avg === 0 && today === 0) return null;
    const dir = today > avg * 1.1 ? "up" : today < avg * 0.9 ? "down" : "flat";
    return { dir, label: "vs recent avg" };
  })();

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="space-y-1">
          <h1 className="text-xl font-semibold">Dashboard</h1>
          <p className="text-sm text-muted">
            Detect phishing URLs, fake QR codes, scam emails, voice scams and malicious links with
            AI-powered analysis.
          </p>
        </div>
        <button
          type="button"
          onClick={() => window.print()}
          className="no-print shrink-0 rounded-lg border border-border bg-panel-2 px-3 py-1.5 text-xs font-medium text-text transition-colors hover:text-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          ⭳ Export / print summary
        </button>
      </header>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile label="📊 Total scans" value={stats?.total_scans ?? null} loading={statsLoading} />
        <StatTile label="🚨 Threats blocked" value={stats?.threats_blocked ?? null} loading={statsLoading} />
        <StatTile
          label="📅 Scans today"
          value={stats?.scans_today ?? null}
          loading={statsLoading}
          trend={todayTrend}
        />
        <StatTile
          label="⚡ Avg response"
          value={stats?.avg_scan_time_ms ?? null}
          suffix="ms"
          loading={statsLoading}
        />
      </div>

      {loggedIn && (
        <Panel title="Your usage & plan">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div>
              <p className="text-xs text-muted">Plan</p>
              <p className="text-sm font-medium capitalize text-text">{user.tier}</p>
            </div>
            <div>
              <p className="text-xs text-muted">Scans 11 today</p>
              <p className="text-sm font-medium tabular-nums text-text">
                {stats?.scans_today ?? "—"}
              </p>
            </div>
            <div>
              <p className="text-xs text-muted">Role</p>
              <p className="text-sm font-medium capitalize text-text">{user.role}</p>
            </div>
          </div>
          {user.tier === "free" && (
            <div className="mt-4">
              <Link
                to="/settings"
                className="inline-flex rounded-full bg-accent px-4 py-2 text-sm font-semibold text-bg transition-opacity hover:opacity-90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                ⭐ Upgrade to Premium
              </Link>
            </div>
          )}
        </Panel>
      )}

      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {TOOL_SHORTCUTS.map((tool) => (
          <Link
            key={tool.type}
            to={`/scan?type=${tool.type}`}
            className="group rounded-lg border border-border bg-panel p-3 transition-colors hover:border-accent/60 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <div aria-hidden="true" className="text-lg">
              {tool.icon}
            </div>
            <p className="mt-1 text-sm font-medium text-text group-hover:text-accent">{tool.title}</p>
            <p className="mt-0.5 text-xs text-muted">{tool.blurb}</p>
          </Link>
        ))}
      </div>

      <div className="flex items-center gap-3">
        <h2 className="text-sm font-semibold text-text">📈 Analytics</h2>
        {analytics?.scope && analytics.scope !== "none" && (
          <span className="rounded-full bg-panel-2 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-muted">
            {analytics.scope}
          </span>
        )}
        <button
          type="button"
          onClick={() => loadAnalytics(activityDays)}
          className="ml-auto rounded-lg border border-border bg-panel-2 px-3 py-1.5 text-xs font-medium text-text transition-colors hover:text-accent focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          ↻ Refresh
        </button>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel title="Verdict distribution">
          <VerdictDonut distribution={distribution} tokens={tokens} />
        </Panel>
        <Panel
          title="Scan activity"
          aside={
            <div className="flex gap-1">
              {[7, 30].map((d) => (
                <button
                  key={d}
                  type="button"
                  onClick={() => selectActivityDays(d)}
                  className={[
                    "rounded-md px-2 py-0.5 text-[11px] font-medium transition-colors",
                    "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent",
                    activityDays === d
                      ? "bg-accent text-bg"
                      : "bg-panel-2 text-muted hover:text-text",
                  ].join(" ")}
                >
                  {d} days
                </button>
              ))}
            </div>
          }
        >
          {activity.length > 0 ? (
            <ActivityBars series={activity} tokens={tokens} />
          ) : (
            <EmptySlot>No scans yet.</EmptySlot>
          )}
        </Panel>
        <Panel title="Top threat types">
          <TopBars rows={analytics?.top_threat_types || []} nameKey="type" tokens={tokens} />
        </Panel>
        <Panel title="Top targeted brands">
          <TopBars rows={analytics?.top_targeted_brands || []} nameKey="brand" tokens={tokens} />
        </Panel>
      </div>

      <Panel
        title="Threat origins"
        aside={<span className="text-[10px] text-muted">from scan-time IP geolocation</span>}
      >
        {geo.length === 0 ? (
          <EmptySlot>
            No flagged scans yet — origins appear here when a scan is flagged.
          </EmptySlot>
        ) : (
          <ul className="divide-y divide-border">
            {geo.map((g) => (
              <li key={g.country} className="flex items-center justify-between py-2 text-sm">
                <span className="text-text">{g.country}</span>
                <span className="rounded-md bg-panel-2 px-2 py-0.5 text-xs font-medium tabular-nums text-muted">
                  {g.count} threat{g.count === 1 ? "" : "s"}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel title="Recent scans">
          {recent.length === 0 ? (
            <EmptySlot>No scans yet.</EmptySlot>
          ) : (
            <ul className="divide-y divide-border">
              {recent.map((scan, i) => (
                <li key={`${i}-${scan.time}`} className="flex items-center gap-3 py-2">
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm text-text">{scan.target || "—"}</p>
                    <p className="text-xs text-muted">
                      {scan.module} · {String(scan.time || "").replace("T", " ")}
                    </p>
                  </div>
                  <VerdictBadge verdict={scan.verdict} />
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel
          title="Live threat feed"
          aside={
            <span className="text-[10px] text-muted">
              {feedMeta?.sources?.length ? feedMeta.sources.join(" · ") : "URLHaus · OpenPhish"}
              {feedMeta?.fetched_at && minutesAgo(feedMeta.fetched_at)
                ? ` · updated ${minutesAgo(feedMeta.fetched_at)}`
                : ""}
              <FeedCountdown key={feedLoads} seconds={FEED_REFRESH_SECONDS} onElapsed={loadThreats} />
            </span>
          }
        >
          {feedMeta?.status === "unavailable" ? (
            <EmptySlot>
              Feed unavailable — retrying.{" "}
              <span className="block text-xs">{feedMeta.detail}</span>
            </EmptySlot>
          ) : feed.length === 0 ? (
            <EmptySlot>Fetching live threat intelligence…</EmptySlot>
          ) : (
            <ul className="max-h-80 space-y-2 overflow-y-auto pr-1">
              {feed.map((item, i) => (
                <li
                  key={`${i}-${item.target}`}
                  className={`rounded-lg border border-border border-l-4 bg-panel-2/50 p-2.5 ${
                    SEVERITY_STRIP[item.severity] || "border-l-border"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span
                      className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase ${
                        SEVERITY_CLASS[item.severity] || "bg-muted/15 text-muted"
                      }`}
                    >
                      {item.severity}
                    </span>
                    <span className="text-[10px] uppercase tracking-wide text-muted">
                      {item.source}
                      {item.time && minutesAgo(item.time) ? ` · ${minutesAgo(item.time)}` : ""}
                    </span>
                  </div>
                  <p className="mt-1.5 truncate text-xs font-semibold text-text">
                    {domainOf(item.target)}
                  </p>
                  <p className="truncate break-all text-[11px] text-muted" title={item.target}>
                    {item.target}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}
