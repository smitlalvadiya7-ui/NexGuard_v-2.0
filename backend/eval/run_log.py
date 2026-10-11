"""
Benchmark run log — the third next-session item of ROAD_TO_90.md, made
mechanical.

    "Re-run the benchmark >= 3 times on different days before believing any
     recall figure."

Four runs of identical code produced recall 73.5%, 73.6%, 37.6% and 38.4%. The
36-point spread was corpus composition: one campaign flooded OpenPhish on the
day of the later runs. Crucially runs 1 and 2 were the same day, and so were 3
and 4 — two same-day pairs that each looked like solid agreement. Repetition
within a day measures the day, not the scanner, which is why the rule is
"different days" and not "three runs".

So every benchmark run appends one line here, and the LOG decides whether a
recall figure may be quoted:

  quotable  <=>  >= 3 non-circular runs on >= 3 distinct dates

Circular runs (--feed-assist over a feed-derived corpus — audit finding 1)
never count, however many there are: three measurements of a feed lookup are
still not a measurement of detection.

The spread is always reported, quotable or not. A disagreement between two runs
is itself the most useful thing the log knows.

Usage
-----
    python -m eval.run_log                  # print the report
    python -m eval.run_log --json           # machine-readable summary

realworld_eval appends automatically at the end of every run.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

DEFAULT_LOG = _BACKEND / "metrics_run_log.jsonl"

MIN_RUNS = 3
MIN_DISTINCT_DAYS = 3

_METRICS = ("recall", "precision", "false_positive_rate")


def append_run(payload: dict, path: Path = DEFAULT_LOG) -> dict:
    """
    Record one benchmark run. Takes realworld_eval's payload unchanged — a
    second format to keep in sync is a format that will drift.

    Fail-safe: a log that cannot be written must never abort a benchmark that
    has just spent an hour scanning.
    """
    entry = {
        "date": payload.get("evaluated_on_date") or (payload.get("generated_at") or "")[:10],
        "generated_at": payload.get("generated_at"),
        "recall": payload.get("recall"),
        "precision": payload.get("precision"),
        "false_positive_rate": payload.get("false_positive_rate"),
        "feed_assist": bool(payload.get("feed_assist")),
        "circular": "CIRCULAR" in (payload.get("scan_path_feeds") or "").upper(),
        # Which stack produced this number. Until 2026-07-28 the harness never
        # loaded backend/.env, so every run measured the local engine with
        # VirusTotal and Safe Browsing switched off while presenting itself as a
        # measurement of the product. Runs from different stacks cannot be
        # averaged — that would turn a config change into a trend.
        "intel_stack": payload.get("intel_stack") or "unrecorded",
        # WHICH legit corpus produced this. On 2026-07-29 the Tranco download
        # failed and the harness fell back to Cisco Umbrella, which ranks DNS
        # traffic rather than web popularity — a materially different corpus
        # that moved the false-positive rate 0% -> 1.9% on composition alone.
        # Recorded so two runs cannot be pooled across that swap.
        "legit_source": _corpus_family(
            (payload.get("dataset_sources") or {}).get("legit")),
        "phish_scored": (payload.get("counts") or {}).get("phish_scored"),
        "legit_scored": (payload.get("counts") or {}).get("legit_scored"),
    }
    try:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass
    return entry


def _corpus_family(source: str | None) -> str:
    """
    The corpus a run drew its legitimate URLs from, reduced to the part that
    matters for comparability: 'tranco', 'umbrella', 'bundled' or 'unrecorded'.
    The rank band and sample size vary run to run and are not the issue; which
    LIST it came from is.
    """
    text = (source or "").lower()
    for name in ("tranco", "umbrella", "bundled"):
        if name in text:
            return name
    return "unrecorded"


def load_runs(path: Path = DEFAULT_LOG) -> list[dict]:
    """Every recorded run. A corrupt line is skipped, never fatal — the log is
    append-only history and one bad write must not cost the rest."""
    path = Path(path)
    if not path.exists():
        return []
    out = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out


def _spread(values: list[float]) -> dict | None:
    vals = [v for v in values if isinstance(v, (int, float))]
    if not vals:
        return None
    return {
        "min": min(vals),
        "max": max(vals),
        "spread": round(max(vals) - min(vals), 6),
        "n": len(vals),
    }


def summarise(runs: list[dict]) -> dict:
    """
    What the log knows, and whether it is enough to quote.

    'honest_runs' counts only non-circular runs; a feed-assisted run over a
    feed-derived corpus measured feed membership, not detection.
    """
    honest = [r for r in runs
              if not (r.get("circular") or r.get("feed_assist"))]
    days = sorted({r.get("date") for r in honest if r.get("date")})
    stacks = sorted({r.get("intel_stack") or "unrecorded" for r in honest})
    corpora = sorted({r.get("legit_source") or "unrecorded" for r in honest})
    summary = {
        "runs": len(runs),
        "honest_runs": len(honest),
        "distinct_days": len(days),
        "days": days,
        "intel_stacks": stacks,
        "legit_corpora": corpora,
        "quotable": False,
        "reason": "",
    }
    for metric in _METRICS:
        summary[metric] = _spread([r.get(metric) for r in honest])

    if not runs:
        summary["reason"] = f"no runs recorded — need {MIN_RUNS} on different days"
        return summary
    if not honest:
        summary["reason"] = (
            "every recorded run is CIRCULAR (feed-assisted over a feed-derived "
            "corpus) — those measure a blocklist lookup, not detection"
        )
        return summary
    if len(honest) < MIN_RUNS:
        summary["reason"] = (
            f"only {len(honest)} honest run(s) — need {MIN_RUNS} on "
            f"{MIN_DISTINCT_DAYS} different days"
        )
        return summary
    if len(days) < MIN_DISTINCT_DAYS:
        summary["reason"] = (
            f"{len(honest)} runs but only {len(days)} distinct day(s) — runs "
            "within one day share that day's feed composition, which is the "
            "thing being controlled for"
        )
        return summary

    if len(stacks) > 1:
        summary["reason"] = (
            f"runs span {len(stacks)} different intel stacks ({', '.join(stacks)}) "
            "— a scan with VirusTotal and Safe Browsing reachable is not "
            "measuring the same system as one without them, so these cannot be "
            "pooled. Collect three days on one stack."
        )
        return summary

    known_corpora = [c for c in corpora if c != "unrecorded"]
    if len(known_corpora) > 1:
        summary["reason"] = (
            f"runs span {len(known_corpora)} different legit corpora "
            f"({', '.join(known_corpora)}) — Umbrella ranks DNS traffic and "
            "Tranco ranks web popularity, so they are not the same population "
            "and their false-positive rates are not comparable. Collect three "
            "days on one corpus."
        )
        return summary

    summary["quotable"] = True
    rec = summary.get("recall") or {}
    summary["reason"] = (
        f"{len(honest)} honest runs across {len(days)} days; "
        f"recall spread {rec.get('spread', 'n/a')}"
    )
    return summary


def format_report(summary: dict) -> str:
    lines = [
        "=" * 64,
        "BENCHMARK RUN LOG",
        "=" * 64,
        f"Runs recorded    : {summary['runs']} "
        f"({summary['honest_runs']} honest, "
        f"{summary['runs'] - summary['honest_runs']} circular)",
        f"Distinct days    : {summary['distinct_days']}  {summary['days']}",
        f"Intel stack      : {', '.join(summary.get('intel_stacks') or ['unrecorded'])}",
        f"Legit corpus     : {', '.join(summary.get('legit_corpora') or ['unrecorded'])}",
        "-" * 64,
    ]
    for metric in _METRICS:
        s = summary.get(metric)
        if not s:
            lines.append(f"{metric:20s}: no data")
            continue
        lines.append(
            f"{metric:20s}: {s['min'] * 100:.1f}% – {s['max'] * 100:.1f}%  "
            f"(spread {s['spread'] * 100:.1f} points, n={s['n']})"
        )
    lines.append("-" * 64)
    verdict = "QUOTABLE" if summary["quotable"] else "NOT QUOTABLE"
    lines.append(f"{verdict}: {summary['reason']}")
    if not summary["quotable"]:
        lines.append(
            "Do not publish a recall figure yet. Composition swung recall 36 "
            "points\nbetween identical runs once already."
        )
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="NexGuard benchmark run log")
    ap.add_argument("--log", default=str(DEFAULT_LOG))
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()
    summary = summarise(load_runs(Path(args.log)))
    print(json.dumps(summary, indent=2) if args.json else format_report(summary))


if __name__ == "__main__":
    main()
