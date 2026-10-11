"""
The third item of the plan's next-session list: "Re-run the benchmark >= 3 times
on different days before believing any recall figure."

That is a discipline, and disciplines that live only in a document stop being
followed. This makes it mechanical: every run appends to a log, and the log
itself decides whether a recall figure may be quoted.

The rule comes straight from what happened. Four runs of identical code gave
73.5%, 73.6%, 37.6%, 38.4% — a 36-point spread caused by one campaign flooding
the feed on the day of the later runs. Runs 1 and 2 were the SAME day, and so
were 3 and 4; two same-day pairs look like agreement and are not. Hence
"different days", not merely "three runs".
"""

import json

import pytest

from eval import run_log


def entry(recall, date, feed_assist=False, precision=0.98, fpr=0.0074):
    """A metrics payload of the shape realworld_eval writes."""
    return {
        "evaluated_on_date": date,
        "generated_at": f"{date}T12:00:00+00:00",
        "recall": recall,
        "precision": precision,
        "false_positive_rate": fpr,
        "feed_assist": feed_assist,
        "scan_path_feeds": ("scan-path community blocklist ENABLED over a "
                            "openphish corpus — CIRCULAR" if feed_assist
                            else "scan-path community blocklist DISABLED"),
        "counts": {"phish_scored": 151, "legit_scored": 216},
    }


@pytest.fixture
def log(tmp_path):
    return tmp_path / "runs.jsonl"


# ---------------------------------------------------------------------------
# Appending
# ---------------------------------------------------------------------------

class TestAppend:
    def test_run_is_recorded_with_its_date(self, log):
        run_log.append_run(entry(0.384, "2026-07-27"), path=log)
        runs = run_log.load_runs(log)
        assert len(runs) == 1
        assert runs[0]["date"] == "2026-07-27"
        assert runs[0]["recall"] == 0.384

    def test_appending_never_loses_earlier_runs(self, log):
        for i, d in enumerate(["2026-07-25", "2026-07-26", "2026-07-27"]):
            run_log.append_run(entry(0.3 + i / 10, d), path=log)
        assert len(run_log.load_runs(log)) == 3

    def test_missing_log_reads_as_empty(self, tmp_path):
        assert run_log.load_runs(tmp_path / "nope.jsonl") == []

    def test_a_corrupt_line_does_not_destroy_the_log(self, log):
        run_log.append_run(entry(0.384, "2026-07-27"), path=log)
        with open(log, "a", encoding="utf-8") as f:
            f.write("{not json\n")
        run_log.append_run(entry(0.735, "2026-07-28"), path=log)
        assert len(run_log.load_runs(log)) == 2


# ---------------------------------------------------------------------------
# When a number may be quoted
# ---------------------------------------------------------------------------

class TestQuotable:
    def test_one_run_is_never_quotable(self, log):
        run_log.append_run(entry(0.735, "2026-07-27"), path=log)
        s = run_log.summarise(run_log.load_runs(log))
        assert s["quotable"] is False
        assert "3" in s["reason"]

    def test_three_runs_on_the_same_day_are_not_quotable(self, log):
        """
        The exact trap the recorded history set. Three runs in one afternoon
        share one day's feed composition, so their agreement measures the feed,
        not the scanner.
        """
        for r in (0.735, 0.736, 0.740):
            run_log.append_run(entry(r, "2026-07-27"), path=log)
        s = run_log.summarise(run_log.load_runs(log))
        assert s["quotable"] is False
        assert s["distinct_days"] == 1

    def test_three_runs_on_different_days_are_quotable(self, log):
        for r, d in ((0.71, "2026-07-25"), (0.73, "2026-07-26"), (0.72, "2026-07-27")):
            run_log.append_run(entry(r, d), path=log)
        s = run_log.summarise(run_log.load_runs(log))
        assert s["quotable"] is True
        assert s["distinct_days"] == 3

    def test_circular_runs_are_never_quotable(self, log):
        """
        A feed-assisted run over a feed-derived corpus measures a lookup, not
        detection (audit finding 1). Three of them on three days is still three
        measurements of the wrong thing.
        """
        for d in ("2026-07-25", "2026-07-26", "2026-07-27"):
            run_log.append_run(entry(0.97, d, feed_assist=True), path=log)
        s = run_log.summarise(run_log.load_runs(log))
        assert s["quotable"] is False
        assert "circular" in s["reason"].lower()

    def test_circular_runs_do_not_count_toward_the_three(self, log):
        run_log.append_run(entry(0.97, "2026-07-25", feed_assist=True), path=log)
        for r, d in ((0.71, "2026-07-26"), (0.73, "2026-07-27")):
            run_log.append_run(entry(r, d), path=log)
        s = run_log.summarise(run_log.load_runs(log))
        assert s["quotable"] is False
        assert s["honest_runs"] == 2


# ---------------------------------------------------------------------------
# What the summary reports
# ---------------------------------------------------------------------------

class TestSummary:
    def test_spread_is_reported_even_when_not_quotable(self, log):
        """A single run still teaches you something once a second disagrees;
        the spread is the finding, so it is never withheld."""
        run_log.append_run(entry(0.735, "2026-07-27"), path=log)
        run_log.append_run(entry(0.384, "2026-07-28"), path=log)
        s = run_log.summarise(run_log.load_runs(log))
        assert s["recall"]["min"] == 0.384
        assert s["recall"]["max"] == 0.735
        assert s["recall"]["spread"] == pytest.approx(0.351, abs=1e-3)

    def test_recorded_history_reproduces_the_known_swing(self, log):
        """The four post-fix runs, replayed. If this ever stops showing a
        ~35-point spread, the recorded history has been edited."""
        for r, d in ((0.735, "2026-07-27"), (0.736, "2026-07-27"),
                     (0.376, "2026-07-28"), (0.384, "2026-07-28")):
            run_log.append_run(entry(r, d), path=log)
        s = run_log.summarise(run_log.load_runs(log))
        assert s["recall"]["spread"] == pytest.approx(0.36, abs=0.01)
        assert s["quotable"] is False, "two days is not three"

    def test_summary_of_an_empty_log_does_not_crash(self):
        s = run_log.summarise([])
        assert s["quotable"] is False
        assert s["runs"] == 0

    def test_precision_and_fpr_are_summarised_too(self, log):
        run_log.append_run(entry(0.7, "2026-07-26", precision=0.966, fpr=0.0147), path=log)
        run_log.append_run(entry(0.7, "2026-07-27", precision=1.0, fpr=0.0), path=log)
        s = run_log.summarise(run_log.load_runs(log))
        assert s["precision"]["min"] == 0.966
        assert s["false_positive_rate"]["max"] == 0.0147

    def test_report_is_human_readable(self, log):
        run_log.append_run(entry(0.384, "2026-07-28"), path=log)
        text = run_log.format_report(run_log.summarise(run_log.load_runs(log)))
        assert "NOT QUOTABLE" in text.upper()
        assert "38.4" in text


# ---------------------------------------------------------------------------
# The harness writes to it
# ---------------------------------------------------------------------------

class TestHarnessIntegration:
    def test_realworld_eval_payload_is_accepted_as_is(self, log):
        """The log must take realworld_eval's payload without reshaping — a
        second format to keep in sync is a format that will drift."""
        from eval.realworld_eval import compute_metrics
        metrics = compute_metrics(
            legit=[{"verdict": "SAFE", "scan_time_ms": 100, "reachable": True}],
            phish=[{"verdict": "MALICIOUS", "scan_time_ms": 100, "reachable": True}],
        )
        payload = {"evaluated_on_date": "2026-07-28", "feed_assist": False, **metrics}
        run_log.append_run(payload, path=log)
        assert run_log.load_runs(log)[0]["recall"] == 1.0

    def test_log_is_line_delimited_json(self, log):
        run_log.append_run(entry(0.384, "2026-07-28"), path=log)
        run_log.append_run(entry(0.735, "2026-07-29"), path=log)
        lines = log.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2
        assert all(json.loads(ln)["date"] for ln in lines)


# ---------------------------------------------------------------------------
# Runs from different stacks are not comparable
#
# Until 2026-07-28 the harness never loaded backend/.env, so every recorded run
# measured the local engine with VirusTotal and Safe Browsing switched off —
# while presenting itself as a measurement of the product. Fixing that made all
# later runs measure a different, stronger stack.
#
# Averaging across that boundary would manufacture a trend out of a config
# change, which is exactly the class of mistake this log exists to prevent.
# ---------------------------------------------------------------------------

def entry_stack(recall, date, stack):
    e = entry(recall, date)
    e["intel_stack"] = stack
    return e


class TestIntelStack:
    def test_stack_is_recorded_with_the_run(self, log):
        run_log.append_run(entry_stack(0.72, "2026-07-28", "own-engine-only"), path=log)
        assert run_log.load_runs(log)[0]["intel_stack"] == "own-engine-only"

    def test_runs_from_different_stacks_are_not_quotable_together(self, log):
        for r, d in ((0.71, "2026-07-26"), (0.72, "2026-07-27")):
            run_log.append_run(entry_stack(r, d, "own-engine-only"), path=log)
        run_log.append_run(entry_stack(0.96, "2026-07-28", "full"), path=log)
        s = run_log.summarise(run_log.load_runs(log))
        assert s["quotable"] is False
        assert "stack" in s["reason"].lower()

    def test_three_days_on_one_stack_is_quotable(self, log):
        for r, d in ((0.95, "2026-07-28"), (0.96, "2026-07-29"), (0.94, "2026-07-30")):
            run_log.append_run(entry_stack(r, d, "full"), path=log)
        s = run_log.summarise(run_log.load_runs(log))
        assert s["quotable"] is True

    def test_the_stacks_present_are_reported(self, log):
        run_log.append_run(entry_stack(0.72, "2026-07-27", "own-engine-only"), path=log)
        run_log.append_run(entry_stack(0.96, "2026-07-28", "full"), path=log)
        s = run_log.summarise(run_log.load_runs(log))
        assert set(s["intel_stacks"]) == {"own-engine-only", "full"}

    def test_older_runs_without_the_field_do_not_crash(self, log):
        """The two runs recorded before this field existed must still load."""
        run_log.append_run(entry(0.72, "2026-07-28"), path=log)
        s = run_log.summarise(run_log.load_runs(log))
        assert s["runs"] == 1


# ---------------------------------------------------------------------------
# A corpus swap is a stack change too
#
# On 2026-07-29 the Tranco download failed and the harness fell back to Cisco
# Umbrella. Umbrella ranks DNS traffic rather than web popularity, so it is a
# materially different legit corpus — the false-positive rate moved 0% -> 1.9%
# on composition alone. The run log recorded the intel stack and happily pooled
# the two anyway, because nothing told it the corpus had changed underneath.
# ---------------------------------------------------------------------------

def entry_source(recall, date, legit_source, stack="own-engine-only"):
    e = entry(recall, date)
    e["intel_stack"] = stack
    e["dataset_sources"] = {"legit": legit_source, "phish": "openphish eval-half"}
    return e


class TestCorpusSource:
    def test_the_legit_corpus_source_is_recorded(self, log):
        run_log.append_run(
            entry_source(0.72, "2026-07-28", "tranco[ranks 2000-10000] sample=200"),
            path=log)
        assert "tranco" in run_log.load_runs(log)[0]["legit_source"]

    def test_a_fallback_corpus_is_recorded_distinctly(self, log):
        run_log.append_run(
            entry_source(0.70, "2026-07-29", "umbrella(fallback)[ranks 2000-10000]"),
            path=log)
        assert "umbrella" in run_log.load_runs(log)[0]["legit_source"]

    def test_runs_on_different_legit_corpora_are_not_quotable_together(self, log):
        for r, d in ((0.71, "2026-07-26"), (0.72, "2026-07-27")):
            run_log.append_run(entry_source(r, d, "tranco[ranks 2000-10000]"), path=log)
        run_log.append_run(
            entry_source(0.70, "2026-07-28", "umbrella(fallback)[ranks 2000-10000]"),
            path=log)
        s = run_log.summarise(run_log.load_runs(log))
        assert s["quotable"] is False
        assert "corpus" in s["reason"].lower()

    def test_three_days_on_one_corpus_is_quotable(self, log):
        for r, d in ((0.71, "2026-07-27"), (0.72, "2026-07-28"), (0.73, "2026-07-29")):
            run_log.append_run(entry_source(r, d, "tranco[ranks 2000-10000]"), path=log)
        s = run_log.summarise(run_log.load_runs(log))
        assert s["quotable"] is True

    def test_older_runs_without_the_field_still_load(self, log):
        run_log.append_run(entry(0.72, "2026-07-28"), path=log)
        s = run_log.summarise(run_log.load_runs(log))
        assert s["runs"] == 1
