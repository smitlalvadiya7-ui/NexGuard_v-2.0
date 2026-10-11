"""
Batch scanner input, bookkeeping and report.

Found on 2026-09-29 by uploading the 200-URL test pack (urls_testpack.txt):
  * the parser kept inline '# expected: ...' comments, so every target was
    'https://www.apple.com    # expected: SAFE ml=0.001' — the host did not
    resolve, reputable-domain lookups missed, and the heuristic read the word
    MALICIOUS out of the label (+60 risk on 60 rows);
  * it split comment lines on commas and scanned the pieces as URLs
    ('https://rules and (if keys are set) ...' came back SAFE);
  * a CSV upload turned every ml= number into a target ('https://0.001');
  * the 200 cap silently dropped the last three real URLs;
  * UNKNOWN rows were in no counter, so 89 of 200 vanished from the summary,
    which read 'Errors 0';
  * rows were listed in completion order, not file order;
  * the PDF table header was black text on navy, and '100' wrapped in the
    '#' column.
"""

import asyncio
import io

import pytest

main = pytest.importorskip("main")

from fastapi.testclient import TestClient  # noqa: E402

import report_generator as rg  # noqa: E402

PACK_HEADER = (
    "# NexGuard URL test pack — 200 URLs. 'ml=' is the offline char-model phishing probability (0..1),\n"
    "# computed with backend/ml/predict.py at build time. The final verdict is the FUSED engine's:\n"
    "# reputation, rules and (if keys are set) VirusTotal / Safe Browsing / feeds also weigh in.\n"
    "\n"
    "# ===== SAFE — reputable domains (expected SAFE; see README) =====\n"
)


def parse(raw):
    return main._parse_batch(raw)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

class TestParsing:
    def test_comment_lines_are_not_targets(self):
        out = parse(PACK_HEADER + "https://www.google.com\n")
        assert out["targets"] == ["https://www.google.com"]

    def test_inline_comment_is_stripped(self):
        out = parse("https://www.apple.com    # expected: SAFE ml=0.001\n")
        assert out["targets"] == ["https://www.apple.com"]

    def test_a_real_fragment_is_kept(self):
        out = parse("https://example.com/docs#install\n")
        assert out["targets"] == ["https://example.com/docs#install"]

    def test_csv_with_a_url_header_reads_only_that_column(self):
        csv_text = (
            "url,bucket,expected,ml,why,needs\n"
            "https://www.google.com,SAFE,SAFE,0.0,reputation,none\n"
            "http://paypal-secure-login.xyz/verify,PHISHY-LEXICAL,SUSPICIOUS or MALICIOUS,1.0,"
            "ml-lexical (high),none (ML/rules on structure)\n"
        )
        out = parse(csv_text)
        assert out["targets"] == ["https://www.google.com",
                                  "http://paypal-secure-login.xyz/verify"]
        assert out["invalid_count"] == 0

    def test_a_headerless_rank_domain_csv_still_works(self):
        out = parse("1,google.com\n2,bing.com\n")
        assert out["targets"] == ["https://google.com", "https://bing.com"]

    def test_non_url_tokens_are_rejected_and_counted(self):
        out = parse("https://0.001\nnot a url.\nhttp://exa mple.com\nhttps://ok.example\n")
        assert out["targets"] == ["https://ok.example"]
        assert out["invalid_count"] == 3

    @pytest.mark.parametrize("url", [
        "http://45.83.122.9/secure/appleid/verify.html",
        "http://192.168.10.45/wp-admin/paypal/login.php",
        "http://xn--pypal-4ve.com/signin",
        "https://пример.рф/вход",
        "https://secure-login.account-update.verify.hdfcbank.com.badsite.ru/",
        "http://bit.ly/3xF4kzQ-verify-account",
    ])
    def test_real_target_shapes_are_accepted(self, url):
        assert parse(url + "\n")["targets"] == [url]

    def test_the_cap_is_reported_not_silent(self):
        lines = "".join(f"https://site{i}.example\n" for i in range(203))
        out = parse(PACK_HEADER + lines)
        assert len(out["targets"]) == main._BATCH_MAX
        assert out["over_limit"] == 3

    def test_duplicates_are_scanned_once(self):
        out = parse("https://a.example\nhttps://A.example\nhttps://a.example\n")
        assert out["targets"] == ["https://a.example"]

    def test_the_old_name_still_returns_the_list(self):
        assert main._parse_batch_targets("https://a.example\n") == ["https://a.example"]


# ---------------------------------------------------------------------------
# Job bookkeeping
# ---------------------------------------------------------------------------

def _new_job(targets):
    job_id = "t" + str(len(main._BATCH_JOBS)) + str(id(targets))[-6:]
    main._BATCH_JOBS[job_id] = main._new_batch_job(job_id, user_id=1, targets=targets)
    return job_id


class TestJob:
    def test_results_follow_input_order(self, monkeypatch):
        targets = [f"https://site{i}.example" for i in range(6)]

        async def fake_scan(url, **kw):
            # later targets finish first
            await asyncio.sleep(0.01 * (6 - targets.index(url)))
            return {"url": url, "verdict": "SAFE", "risk_score": 0}

        monkeypatch.setattr(main, "full_scan", fake_scan)
        monkeypatch.setattr(main, "save_scan", lambda *a, **k: None)
        jid = _new_job(targets)
        asyncio.run(main._run_batch(jid, targets, 1))
        view = main._batch_view(main._BATCH_JOBS[jid])
        assert [r["url"] for r in view["results"]] == targets

    def test_unknown_is_counted(self, monkeypatch):
        verdicts = {"https://a.example": "SAFE", "https://b.example": "UNKNOWN",
                    "https://c.example": "MALICIOUS"}

        async def fake_scan(url, **kw):
            return {"url": url, "verdict": verdicts[url], "risk_score": 0}

        monkeypatch.setattr(main, "full_scan", fake_scan)
        monkeypatch.setattr(main, "save_scan", lambda *a, **k: None)
        jid = _new_job(list(verdicts))
        asyncio.run(main._run_batch(jid, list(verdicts), 1))
        counts = main._batch_view(main._BATCH_JOBS[jid])["counts"]
        assert counts["UNKNOWN"] == 1
        assert sum(counts.values()) == 3

    def test_a_new_job_has_every_counter(self):
        job = main._new_batch_job("x", user_id=1, targets=["https://a.example"])
        assert set(job["counts"]) == {"MALICIOUS", "SUSPICIOUS", "SAFE", "UNKNOWN", "ERROR"}


class _User:
    id = 1
    role = "admin"
    tier = "premium"


@pytest.fixture()
def client(monkeypatch):
    async def no_run(*a, **k):
        return None

    monkeypatch.setattr(main, "_run_batch", no_run)
    main.app.dependency_overrides[main.require_premium] = lambda: _User()
    with TestClient(main.app) as c:
        yield c
    main.app.dependency_overrides.pop(main.require_premium, None)


def test_the_endpoint_reports_skipped_and_over_limit_lines(client):
    body = PACK_HEADER + "https://0.001\n" + "".join(
        f"https://site{i}.example  # expected: SAFE\n" for i in range(201))
    r = client.post("/scan-batch",
                    files={"file": ("urls.txt", io.BytesIO(body.encode()), "text/plain")})
    data = r.json()
    assert r.status_code == 200, data
    assert data["total"] == main._BATCH_MAX
    assert data["invalid_count"] == 1
    assert data["over_limit"] == 1
    view = client.get(f"/scan-batch/{data['job_id']}").json()
    assert view["invalid_count"] == 1 and view["over_limit"] == 1


# ---------------------------------------------------------------------------
# PDF report
# ---------------------------------------------------------------------------

def _job_for_pdf():
    results = []
    for i, v in enumerate(["SAFE", "UNKNOWN", "MALICIOUS"] * 34):
        results.append({"index": i, "target": f"https://site{i}.example", "url": f"https://site{i}.example",
                        "verdict": v, "risk_score": 90 if v == "MALICIOUS" else 0})
    return {"id": "abc", "created_at": "2026-10-01T00:00:00", "total": len(results),
            "done": len(results), "results": results, "invalid_count": 2, "over_limit": 3}


def _tables(story):
    from reportlab.platypus import Table
    return [f for f in story if isinstance(f, Table)]


def _cell_text(cell):
    return cell.getPlainText() if hasattr(cell, "getPlainText") else str(cell)


class TestPdf:
    def test_summary_counts_unknown_and_skipped_lines(self):
        summary = _tables(rg.build_batch_story(_job_for_pdf()))[0]
        rows = {str(r[0]): str(r[1]) for r in summary._cellvalues[1:]}
        assert rows["Not checked (UNKNOWN)"] == "34"
        assert rows["Invalid lines skipped"] == "2"
        assert rows["Not scanned (over the 200 limit)"] == "3"

    def test_results_header_is_readable(self):
        results = _tables(rg.build_batch_story(_job_for_pdf()))[1]
        for cell in results._cellvalues[0]:
            assert cell.style.textColor == rg._WHITE

    def test_three_digit_row_numbers_fit(self):
        from reportlab.pdfbase.pdfmetrics import stringWidth
        results = _tables(rg.build_batch_story(_job_for_pdf()))[1]
        width = results._colWidths[0]
        assert stringWidth("200", "Helvetica", 8) + 12 <= width  # 6pt padding each side

    def test_unknown_rows_show_no_risk_number(self):
        results = _tables(rg.build_batch_story(_job_for_pdf()))[1]
        unknown_row = next(r for r in results._cellvalues[1:] if _cell_text(r[2]) == "UNKNOWN")
        assert _cell_text(unknown_row[3]) == "—"

    def test_verdict_cells_are_coloured(self):
        results = _tables(rg.build_batch_story(_job_for_pdf()))[1]
        mal_row = next(r for r in results._cellvalues[1:] if _cell_text(r[2]) == "MALICIOUS")
        assert mal_row[2].style.textColor == rg._DANGER

    def test_the_pdf_still_renders(self, tmp_path):
        out = tmp_path / "b.pdf"
        rg.generate_batch_report(_job_for_pdf(), str(out))
        assert out.read_bytes()[:4] == b"%PDF"
