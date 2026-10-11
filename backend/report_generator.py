"""
NexGuard AI — PDF forensic report generator.

generate_report(data, filename) accepts the full scan-result dict from
full_scan() (or any subset for email / voice / screenshot modules).

Sections rendered
-----------------
  1. Page header — NexGuard logo text + timestamp
  2. Verdict block — verdict (coloured), score, confidence, ML prob, scan time
  3. Network details — URL, domain, resolved IP, SSL
  4. Redirect chain
  5. Source verification table — VT / GSB / URLHaus / community blocklist
  6. Flags / indicators
  7. AI threat summary
  8. WHOIS / domain intelligence (python-whois, graceful fallback)
  9. Footer
"""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from typing import Any
from urllib.parse import urlparse

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ── Colour palette ────────────────────────────────────────────────────────────
_CYAN   = colors.HexColor("#00e5ff")
_NAVY   = colors.HexColor("#071226")
_DANGER = colors.HexColor("#ef4444")
_WARN   = colors.HexColor("#f59e0b")
_SAFE   = colors.HexColor("#22c55e")
_MUTED  = colors.HexColor("#64748b")
_LIGHT  = colors.HexColor("#f1f5f9")
_GRID   = colors.HexColor("#cbd5e1")
_WHITE  = colors.white

# Usable page width  (letter 612 pt − 42 pt × 2 margins = 528 pt)
_W2 = (160, 368)   # two-column tables
_W3 = (120, 80, 328)  # three-column source table


# ── Small helpers ─────────────────────────────────────────────────────────────

def _utcnow() -> datetime:
    """Naive UTC now. Replaces datetime.utcnow(), which is deprecated since
    Python 3.12. Returns a naive value, exactly as utcnow() did, because the
    stored rows and the WHOIS dates it is compared against are naive."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _s(v: Any) -> str:
    """HTML-escape a value; lists become comma-separated strings."""
    if v is None:
        return "—"
    if isinstance(v, (list, tuple)):
        joined = ", ".join(str(i) for i in v)
        return escape(joined) if joined else "—"
    return escape(str(v))


def _verdict_color(v: str) -> colors.Color:
    v = str(v).upper()
    return _DANGER if v == "MALICIOUS" else _WARN if v == "SUSPICIOUS" else _SAFE if v == "SAFE" else _MUTED


def _status_color(s: str) -> colors.Color:
    s = str(s).lower()
    return _DANGER if s == "flag" else _WARN if s == "warn" else _SAFE if s == "clean" else _MUTED


def _hr(story: list) -> None:
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=0.5, color=_GRID))
    story.append(Spacer(1, 6))


# ── Reusable table builders ───────────────────────────────────────────────────

def _kv_table(rows: list[tuple[str, str]],
              col_widths: tuple = _W2,
              extra_style: list | None = None) -> Table:
    """Alternating-row two-column key/value table."""
    data = [["Field", "Value"]] + [[r[0], r[1]] for r in rows]
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), _NAVY),
        ("TEXTCOLOR",  (0, 0), (-1, 0), _CYAN),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME",   (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("GRID",       (0, 0), (-1, -1), 0.5, _GRID),
        ("PADDING",    (0, 0), (-1, -1), 7),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
    ]
    for i in range(1, len(data)):
        style.append(("BACKGROUND", (0, i), (-1, i), _LIGHT if i % 2 == 0 else _WHITE))
    if extra_style:
        style.extend(extra_style)
    t = Table(data, colWidths=list(col_widths))
    t.setStyle(TableStyle(style))
    return t


def _src_table(sources: list[dict]) -> Table:
    """Source verification table with coloured status cells."""
    data = [["Source", "Status", "Detail"]]
    for src in sources:
        data.append([
            _s(src.get("name")),
            _s(src.get("status", "—")).upper(),
            _s(src.get("detail")),
        ])
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), _NAVY),
        ("TEXTCOLOR",  (0, 0), (-1, 0), _CYAN),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME",   (0, 1), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("GRID",       (0, 0), (-1, -1), 0.5, _GRID),
        ("PADDING",    (0, 0), (-1, -1), 7),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
    ]
    for i, src in enumerate(sources, start=1):
        sc = _status_color(src.get("status", ""))
        style.append(("BACKGROUND", (1, i), (1, i), sc))
        style.append(("TEXTCOLOR",  (1, i), (1, i), _WHITE))
        style.append(("FONTNAME",   (1, i), (1, i), "Helvetica-Bold"))
        row_bg = _LIGHT if i % 2 == 0 else _WHITE
        style.append(("BACKGROUND", (0, i), (0, i), row_bg))
        style.append(("BACKGROUND", (2, i), (2, i), row_bg))
    t = Table(data, colWidths=list(_W3))
    t.setStyle(TableStyle(style))
    return t


# ── WHOIS lookup (python-whois, optional) ────────────────────────────────────

def _whois_info(raw_target: str) -> dict | None:
    """
    Return WHOIS fields or None if the library is missing or the lookup fails.
    Never raises.
    """
    try:
        import whois  # python-whois; installed but import-guarded for safety
    except ImportError:
        return None

    try:
        # Normalise to bare domain
        parsed = urlparse(raw_target)
        domain = parsed.netloc or parsed.path or raw_target
        domain = domain.split(":")[0].lstrip("www.").strip()
        if not domain or "." not in domain:
            return None

        w = whois.whois(domain)

        def _first(val):
            return val[0] if isinstance(val, list) else val

        creation = _first(w.creation_date)
        expiry   = _first(w.expiration_date)
        age_days = (_utcnow() - creation).days if creation else None

        return {
            "domain":    domain,
            "registrar": str(w.registrar or "—")[:80],
            "country":   str(w.country   or "—"),
            "created":   creation.strftime("%d %b %Y") if creation else "—",
            "expires":   expiry.strftime("%d %b %Y")   if expiry   else "—",
            "age_days":  age_days,
        }
    except Exception:
        return None


# ── Main entry point ──────────────────────────────────────────────────────────

def generate_report(data: dict, filename: str = "threat_report.pdf") -> str:
    doc = SimpleDocTemplate(
        filename, pagesize=letter,
        rightMargin=42, leftMargin=42, topMargin=42, bottomMargin=42,
    )
    styles = getSampleStyleSheet()
    mono  = ParagraphStyle("Mono",  parent=styles["BodyText"], fontName="Courier",     fontSize=8)
    small = ParagraphStyle("Small", parent=styles["BodyText"], textColor=_MUTED,       fontSize=8)
    h2    = ParagraphStyle("H2",    parent=styles["Heading2"], textColor=_NAVY,        fontSize=11, spaceAfter=4)
    story: list = []

    # ── Extract fields ────────────────────────────────────────────────────────
    module     = data.get("module",        "Unknown")
    verdict    = str(data.get("verdict",   "UNKNOWN")).upper()
    score      = int(data.get("risk_score", data.get("score", 0)) or 0)
    confidence = data.get("confidence")
    ml_prob    = data.get("ml_probability")
    scan_ms    = data.get("scan_time_ms")
    url        = data.get("url",           data.get("target", ""))
    domain_val = data.get("domain",        "")
    ip         = data.get("resolved_ip")
    ssl        = data.get("ssl")
    redirects  = data.get("redirects",    []) or []
    sources    = data.get("sources",      []) or []
    flags      = (data.get("flags") or data.get("reasons") or data.get("indicators") or [])
    summary    = (data.get("ai_explanation") or data.get("summary") or "No AI summary available.")
    vc         = _verdict_color(verdict)

    # ── 1. Page header ────────────────────────────────────────────────────────
    story.append(Paragraph(
        "<font color='#00bcd4'><b>NexGuard AI</b></font>"
        "<font color='#475569'>  ·  Forensic Threat Report</font>",
        styles["Title"],
    ))
    story.append(Paragraph(
        f"Module: <b>{_s(module)}</b> &nbsp;·&nbsp; "
        f"Generated: <b>{_utcnow().strftime('%d %b %Y  %H:%M:%S UTC')}</b>",
        small,
    ))
    _hr(story)

    # ── 2. Verdict block ──────────────────────────────────────────────────────
    verdict_rows: list[tuple[str, str]] = [
        ("Verdict",    _s(verdict)),
        ("Risk Score", f"{score}%"),
    ]
    if confidence is not None:
        verdict_rows.append(("Confidence",      f"{confidence}%"))
    if ml_prob is not None:
        verdict_rows.append(("ML Probability",  f"{round(ml_prob * 100, 1)}%"))
    if scan_ms is not None:
        verdict_rows.append(("Scan Time",       f"{scan_ms} ms"))

    story.append(_kv_table(verdict_rows, extra_style=[
        ("BACKGROUND", (1, 1), (1, 1), vc),
        ("TEXTCOLOR",  (1, 1), (1, 1), _WHITE),
        ("FONTNAME",   (1, 1), (1, 1), "Helvetica-Bold"),
    ]))
    story.append(Spacer(1, 14))

    # ── 3. Network details ────────────────────────────────────────────────────
    net_rows = []
    if url:
        net_rows.append(("URL",         _s(url)))
    if domain_val:
        net_rows.append(("Domain",      _s(domain_val)))
    if ip:
        net_rows.append(("Resolved IP", _s(ip)))
    if ssl is not None:
        net_rows.append(("SSL / TLS",   "HTTPS  ✓" if ssl else "HTTP  (no TLS)"))

    if net_rows:
        story.append(Paragraph("Network Details", h2))
        story.append(_kv_table(net_rows))
        story.append(Spacer(1, 14))

    # ── 4. Redirect chain ─────────────────────────────────────────────────────
    if redirects:
        story.append(Paragraph("Redirect Chain", h2))
        story.append(Paragraph(" → ".join(_s(r) for r in redirects), mono))
        story.append(Spacer(1, 14))

    # ── 5. Source verification ────────────────────────────────────────────────
    if sources:
        story.append(Paragraph("Source Verification", h2))
        story.append(_src_table(sources))
        story.append(Spacer(1, 14))

    # ── 6. Flags / indicators ─────────────────────────────────────────────────
    story.append(Paragraph("Detected Flags / Indicators", h2))
    if flags:
        story.append(Paragraph(
            "<br/>".join(f"• {escape(str(f))}" for f in flags),
            styles["BodyText"],
        ))
    else:
        story.append(Paragraph("No suspicious indicators detected.", small))
    story.append(Spacer(1, 14))

    # ── 7. AI threat summary ──────────────────────────────────────────────────
    story.append(Paragraph("AI Threat Summary", h2))
    summary_text = "; ".join(summary) if isinstance(summary, list) else str(summary)
    story.append(Paragraph(_s(summary_text), styles["BodyText"]))
    story.append(Spacer(1, 14))

    # ── 7b. Explainability — per-feature "why" attribution ─────────────────────
    explain = data.get("explainability") or {}
    top_feats = explain.get("top_features") if isinstance(explain, dict) else None
    if top_feats:
        method = "SHAP" if explain.get("method") == "shap" else "feature-importance"
        prob = explain.get("ml_probability")
        story.append(Paragraph("Why This Verdict (Explainability)", h2))
        prob_txt = f" · ML phishing probability {round(prob * 100, 1)}%" if prob is not None else ""
        story.append(Paragraph(
            f"Top signals driving this URL's verdict ({method} attribution){prob_txt}. "
            "A positive contribution pushed the verdict toward phishing; negative toward safe.",
            small,
        ))
        rows = []
        for f in top_feats:
            c = f.get("contribution", 0) or 0
            sign = "+" if c >= 0 else "−"
            rows.append((
                _s(f.get("feature")),
                f"{_s(f.get('value'))}   ({sign}{abs(round(float(c), 3))})",
            ))
        story.append(_kv_table(rows))
        story.append(Spacer(1, 14))

    # ── 8. WHOIS / domain intelligence ────────────────────────────────────────
    whois_target = url or domain_val
    if whois_target:
        story.append(Paragraph("WHOIS / Domain Intelligence", h2))
        wi = _whois_info(whois_target)
        if wi:
            age_str = f"{wi['age_days']} days" if wi.get("age_days") is not None else "—"
            story.append(_kv_table([
                ("Domain",     wi["domain"]),
                ("Registrar",  wi["registrar"]),
                ("Country",    wi["country"]),
                ("Created",    wi["created"]),
                ("Expires",    wi["expires"]),
                ("Domain Age", age_str),
            ]))
        else:
            story.append(Paragraph(
                "WHOIS data unavailable for this target "
                "(network error, private registration, or unsupported TLD).",
                small,
            ))
        story.append(Spacer(1, 14))

    # ── 9. Footer ─────────────────────────────────────────────────────────────
    _hr(story)
    story.append(Paragraph(
        "Generated by <b>NexGuard AI Cyber Defense Platform</b>. "
        "For educational and defensive security analysis only. "
        "Threat intelligence sourced from VirusTotal, Google Safe Browsing, "
        "URLHaus, and OpenPhish.",
        small,
    ))

    doc.build(story)
    return filename


# ---------------------------------------------------------------------------
# Batch report — a summary + a results table for a bulk URL scan job.
# ---------------------------------------------------------------------------

# Verdicts that carry a risk number. UNKNOWN ("not checked") and ERROR have
# none — printing "0%" for them reads as "zero risk", which is the opposite.
_SCORED_VERDICTS = ("MALICIOUS", "SUSPICIOUS", "SAFE")


def build_batch_story(job: dict) -> list:
    """
    The flowables of a batch report: title, summary table, results table.

    `job` shape: {"id", "created_at", "total", "done", "invalid_count",
                  "over_limit", "results": [{"index", "target"/"url",
                  "verdict", "risk_score", ...}]}
    """
    styles = getSampleStyleSheet()
    small = ParagraphStyle("Small", parent=styles["BodyText"], textColor=_MUTED, fontSize=8)
    cell  = ParagraphStyle("Cell",  parent=styles["BodyText"], fontSize=8)
    # Cell text is a Paragraph, and a Paragraph ignores the table's TEXTCOLOR
    # command — so the header and the verdicts carry their colour in their
    # own style (the header used to render black on navy, i.e. invisible).
    head = ParagraphStyle("BatchHead", parent=cell, textColor=_WHITE)
    story: list = []

    results = sorted(job.get("results", []) or [], key=lambda r: r.get("index", 0))
    counts = {"MALICIOUS": 0, "SUSPICIOUS": 0, "SAFE": 0, "UNKNOWN": 0, "ERROR": 0}
    for r in results:
        v = str(r.get("verdict", "ERROR")).upper()
        counts[v] = counts.get(v, 0) + 1

    # ── Header ──
    story.append(Paragraph(
        "<font color='#00bcd4'><b>NexGuard AI</b></font>"
        "<font color='#475569'>  ·  Batch Scan Report</font>",
        styles["Title"],
    ))
    story.append(Paragraph(
        f"Job: <b>{_s(job.get('id'))}</b> &nbsp;·&nbsp; "
        f"Generated: <b>{_utcnow().strftime('%d %b %Y  %H:%M:%S UTC')}</b>",
        small,
    ))
    _hr(story)

    # ── Summary ──
    story.append(_kv_table([
        ("URLs scanned",          _s(job.get("done", len(results)))),
        ("Malicious",             _s(counts.get("MALICIOUS", 0))),
        ("Suspicious",            _s(counts.get("SUSPICIOUS", 0))),
        ("Safe",                  _s(counts.get("SAFE", 0))),
        ("Not checked (UNKNOWN)", _s(counts.get("UNKNOWN", 0))),
        ("Errors",                _s(counts.get("ERROR", 0))),
        ("Invalid lines skipped", _s(job.get("invalid_count", 0))),
        (f"Not scanned (over the {job.get('limit', 200)} limit)",
                                  _s(job.get("over_limit", 0))),
    ]))
    story.append(Spacer(1, 14))

    # ── Results table ──
    header = [Paragraph(f"<b>{h}</b>", head) for h in ("#", "URL", "Verdict", "Score")]
    data_rows = [header]
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), _NAVY),
        ("GRID",       (0, 0), (-1, -1), 0.5, _GRID),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_WHITE, _LIGHT]),
    ]
    verdict_styles: dict[str, ParagraphStyle] = {}
    for i, r in enumerate(results, start=1):
        verdict = str(r.get("verdict", "ERROR")).upper()
        target = r.get("target") or r.get("url") or ""
        score = int(r.get("risk_score", r.get("score", 0)) or 0)
        vstyle = verdict_styles.setdefault(verdict, ParagraphStyle(
            f"Verdict{verdict}", parent=cell, textColor=_verdict_color(verdict)))
        data_rows.append([
            Paragraph(str(i), cell),
            Paragraph(_s(target), cell),
            Paragraph(f"<b>{_s(verdict)}</b>", vstyle),
            Paragraph(f"{score}%" if verdict in _SCORED_VERDICTS else "—", cell),
        ])

    # '#' is wide enough for "200" plus the default 6 pt padding each side —
    # at 24 pt, row 100 wrapped to "10 / 0".
    table = Table(data_rows, colWidths=(32, 352, 76, 44), repeatRows=1)
    table.setStyle(TableStyle(style))
    story.append(table)

    _hr(story)
    story.append(Paragraph(
        "Generated by <b>NexGuard AI</b>. For educational and defensive security "
        "analysis only. UNKNOWN means no threat-intelligence source could be "
        "reached for that URL — it has not been cleared.", small,
    ))
    return story


def generate_batch_report(job: dict, filename: str = "batch_report.pdf") -> str:
    """Render a PDF for a batch scan job (see build_batch_story)."""
    doc = SimpleDocTemplate(
        filename, pagesize=letter,
        rightMargin=42, leftMargin=42, topMargin=42, bottomMargin=42,
    )
    doc.build(build_batch_story(job))
    return filename

