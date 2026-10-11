"""
The reason a corpus of 190,542 known-malicious domains scanned as SAFE.

Found 2026-07-28 by scanning romainmarcoux/malicious-domains through the
pipeline. The top 60 entries — the most-corroborated, most-confident domains in
the list — came back 73% SAFE. Direct API calls told a completely different
story for the same hosts:

    VirusTotal      23/92 engines · malicious          (HTTP 200)
    Safe Browsing   SOCIAL_ENGINEERING match          (HTTP 200)

Both keys were valid and present in backend/.env the whole time. The pipeline
simply never read them:

    load_dotenv() was called in main.py and telegram_bot.py — the ENTRY POINTS.
    Anything else that imports aggregator (eval/realworld_eval.py, the audit
    scripts, any CLI tool, any test) got no keys at all.

And a missing key does not fail loudly. Every source returns
`{"status": "clean", "detail": "unavailable"}`, so "we could not check" is
reported with the same status as "we checked and it was clean". Reputation then
contributes nothing, the verdict falls back to the local engine, and the URL
reads SAFE.

Measured on the same 20 domains, same code, same corpus:

    without keys   26.7% flagged, 73.3% SAFE
    with keys     100.0% flagged,  0.0% SAFE

This is the same defect class as audit finding 3, where a throttled RDAP lookup
was being read as evidence of reputability. A source that did not answer must
never be indistinguishable from a source that answered "clean".
"""

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]


def run_in_subprocess(code: str) -> str:
    """
    Run code in a CLEAN interpreter.

    It has to be a subprocess: the whole bug is about what a fresh process sees
    at import time, and this test session has already imported half the app.
    """
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        cwd=str(BACKEND), capture_output=True, text=True, timeout=120,
        env={**os.environ, "NEXGUARD_DEBUG": "1", "NEXGUARD_DISABLE_FEEDS": "1"},
    )
    assert result.returncode == 0, f"subprocess failed:\n{result.stderr[-2000:]}"
    return result.stdout.strip()


# ---------------------------------------------------------------------------
# The root cause: keys must not depend on which entry point you came through
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not (BACKEND / ".env").exists(),
                    reason="no backend/.env on this machine")
class TestKeysReachEveryEntryPoint:
    def test_importing_aggregator_alone_loads_the_api_keys(self):
        """
        The regression itself. Importing aggregator WITHOUT main.py used to
        leave VIRUSTOTAL_API_KEY empty, which silently disabled VirusTotal for
        every CLI tool, every eval script and every batch job.
        """
        out = run_in_subprocess("""
            import os, sys
            sys.path.insert(0, ".")
            import aggregator                      # noqa: F401
            print("VT=" + ("SET" if os.getenv("VIRUSTOTAL_API_KEY", "").strip() else "EMPTY"))
            print("GSB=" + ("SET" if os.getenv("GOOGLE_SAFEBROWSING_API_KEY", "").strip() else "EMPTY"))
        """)
        assert "VT=SET" in out, out
        assert "GSB=SET" in out, out

    def test_importing_a_single_api_module_loads_the_keys(self):
        """Each apis/* module reads its key at call time, so importing one on
        its own must be enough."""
        out = run_in_subprocess("""
            import os, sys
            sys.path.insert(0, ".")
            from apis.virustotal import check_virustotal   # noqa: F401
            print("VT=" + ("SET" if os.getenv("VIRUSTOTAL_API_KEY", "").strip() else "EMPTY"))
        """)
        assert "VT=SET" in out, out

    def test_the_eval_harness_sees_the_keys(self):
        """
        eval/realworld_eval.py is the benchmark every accuracy figure comes
        from. Without keys it was measuring the local engine only while
        reporting itself as a measurement of the product.
        """
        out = run_in_subprocess("""
            import os, sys
            sys.path.insert(0, ".")
            import eval.realworld_eval               # noqa: F401
            print("VT=" + ("SET" if os.getenv("VIRUSTOTAL_API_KEY", "").strip() else "EMPTY"))
        """)
        assert "VT=SET" in out, out

    def test_real_environment_variables_win_over_the_env_file(self):
        """
        Deployment sets real environment variables and there is no .env file in
        the image. A loader that overrode them would break production, so the
        file may only FILL GAPS.
        """
        result = subprocess.run(
            [sys.executable, "-c", textwrap.dedent("""
                import os, sys
                sys.path.insert(0, ".")
                import aggregator                    # noqa: F401
                print("VT=" + os.getenv("VIRUSTOTAL_API_KEY", ""))
            """)],
            cwd=str(BACKEND), capture_output=True, text=True, timeout=120,
            env={**os.environ, "NEXGUARD_DEBUG": "1", "NEXGUARD_DISABLE_FEEDS": "1",
                 "VIRUSTOTAL_API_KEY": "from-the-real-environment"},
        )
        assert result.returncode == 0, result.stderr[-2000:]
        assert "VT=from-the-real-environment" in result.stdout


# ---------------------------------------------------------------------------
# The defect class: "did not answer" must never look like "answered clean"
# ---------------------------------------------------------------------------

class TestUnavailableIsNotClean:
    def test_virustotal_without_a_key_is_reported_unavailable(self, monkeypatch):
        # Non-commercial, so the licence gate does not answer first — this test
        # is about a MISSING KEY, which is a different failure with the same
        # requirement: never report it as "clean".
        import deployment_profile as dp
        monkeypatch.setenv("NEXGUARD_DEPLOYMENT_PROFILE", "noncommercial")
        dp.profile.cache_clear()
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "")
        from apis.virustotal import check_virustotal
        res = check_virustotal("http://example.com/")
        assert res["detail"] == "unavailable"
        assert res["status"] != "clean", (
            "a source that never ran must not report the same status as one "
            "that ran and found nothing"
        )

    def test_safe_browsing_without_a_key_is_reported_unavailable(self, monkeypatch):
        import asyncio
        import deployment_profile as dp
        monkeypatch.setenv("NEXGUARD_DEPLOYMENT_PROFILE", "noncommercial")
        dp.profile.cache_clear()
        monkeypatch.setenv("GOOGLE_SAFEBROWSING_API_KEY", "")
        from apis.safe_browsing import check_safe_browsing
        res = asyncio.run(check_safe_browsing("http://example.com/"))
        assert res["detail"] == "unavailable"
        assert res["status"] != "clean"

    def test_unavailable_still_adds_no_risk(self):
        """
        The point is honesty, not alarm. An unavailable source must stay
        NEUTRAL in scoring — it may not raise a score any more than it may
        lower one.
        """
        import aggregator as agg
        unavailable = {"status": "unavailable", "detail": "unavailable"}
        score, n, active = agg._reputation_score(
            vt={**unavailable, "raw_positives": 0},
            gsb=dict(unavailable), urlhaus=dict(unavailable),
            feeds={**unavailable, "match": None},
        )
        assert score == 0
        assert n == 0
        assert active is False

    def test_a_clean_answer_is_still_clean(self):
        """The control: a source that really did answer must be unaffected."""
        from apis.virustotal import _normalize
        assert _normalize({"malicious": 0, "harmless": 70})["status"] == "clean"


# ---------------------------------------------------------------------------
# The second cause: a SAFE verdict that no reputation source stood behind
#
# VirusTotal's free tier allows 4 requests/minute. Scanning a file of links
# blows through that in seconds, the circuit breaker opens, and every scan after
# it runs with no VirusTotal and no Safe Browsing. Measured on a random sample
# of 60 domains from the known-malicious corpus: VT was unavailable for 41 of
# them, and ALL TEN of the live-but-SAFE results were in that group.
#
# The fix is not to pretend the sources answered. It is to stop presenting
# "nothing checked this" as a clean bill of health.
# ---------------------------------------------------------------------------

class TestIncompleteIntelIsDisclosed:
    def _scan(self, monkeypatch, vt_status, gsb_status):
        import asyncio
        import aggregator as agg

        monkeypatch.setattr(agg, "_resolve_chain",
                            lambda url, **kw: {"chain": [url], "final": url,
                                               "loop": False, "truncated": False,
                                               "html": None, "blocked_scheme": False})
        monkeypatch.setattr(agg, "_resolve_ip", lambda d: "203.0.113.10")
        monkeypatch.setattr(agg, "check_virustotal",
                            lambda u: {"status": vt_status, "detail": vt_status,
                                       "raw_positives": 0})

        async def _gsb(u):
            return {"status": gsb_status, "detail": gsb_status}

        async def _uh(u):
            return {"status": "clean", "detail": "not listed"}

        async def _feeds(u):
            return {"status": "clean", "detail": "clean", "match": None}

        async def _geo(d):
            return dict(agg._FB_GEO)

        async def _ssl(d):
            return dict(agg._FB_SSL)

        async def _us(u):
            return dict(agg._FB_URLSCAN)

        async def _whois(d):
            return dict(agg._FB_WHOIS)

        # Google's corpus arrives via Safe Browsing v4 or Web Risk depending on
        # the build's licence; stub both so the test states an intent about
        # reputation rather than about a vendor endpoint.
        monkeypatch.setattr(agg, "check_safe_browsing", _gsb)
        monkeypatch.setattr(agg, "check_web_risk", _gsb)
        monkeypatch.setattr(agg, "check_urlhaus", _uh)
        monkeypatch.setattr(agg, "check_phish_feeds", _feeds)
        monkeypatch.setattr(agg, "check_geo", _geo)
        monkeypatch.setattr(agg, "check_ssl_cert", _ssl)
        monkeypatch.setattr(agg, "check_urlscan", _us)
        monkeypatch.setattr(agg, "check_whois", _whois)
        monkeypatch.setattr(agg, "analyze_page_content",
                            lambda u, html=None: dict(agg._FB_CONTENT))
        monkeypatch.setattr(agg, "_explain_url", lambda u, top_n=5: None)
        monkeypatch.setattr(agg, "cache_get", lambda k: None)
        monkeypatch.setattr(agg, "cache_put", lambda k, v, ttl=None: None)
        return asyncio.run(agg.full_scan("https://ordinary-looking-site.example/"))

    def test_unchecked_verdict_says_so_when_the_sources_never_answered(self, monkeypatch):
        """
        Originally asserted the verdict stayed SAFE and merely carried a flag.
        It no longer does: a URL no primary source could check now returns
        UNKNOWN (see test_unchecked_is_not_safe.py). A batch of 200
        known-malicious domains reported 125 of them "SAFE 0%" under the old
        behaviour, and the flag was not enough to stop a user acting on the word
        SAFE. The disclosure this test was written for is still asserted.
        """
        r = self._scan(monkeypatch, "unavailable", "unavailable")
        assert r["verdict"] == "UNKNOWN"
        assert any("could not be checked" in f.lower() or "incomplete" in f.lower()
                   or "not checked" in f.lower()
                   for f in r["flags"]), (
            f"an unchecked verdict must say why; flags were {r['flags']}")

    def test_the_unavailable_sources_are_named(self, monkeypatch):
        r = self._scan(monkeypatch, "unavailable", "unavailable")
        blob = " ".join(r["flags"])
        assert "VirusTotal" in blob and "Safe Browsing" in blob

    def test_no_such_flag_when_the_sources_did_answer(self, monkeypatch):
        """The control. A genuinely checked-and-clean URL must not be
        cluttered with a warning that does not apply."""
        r = self._scan(monkeypatch, "clean", "clean")
        assert not any("could not be checked" in f.lower() or "incomplete" in f.lower()
                       for f in r["flags"]), r["flags"]

    def test_confidence_drops_when_the_intel_was_incomplete(self, monkeypatch):
        complete = self._scan(monkeypatch, "clean", "clean")
        incomplete = self._scan(monkeypatch, "unavailable", "unavailable")
        assert incomplete["confidence"] < complete["confidence"], (
            "a verdict resting on fewer sources cannot be as confident")

    def test_payload_reports_intel_completeness_for_callers(self, monkeypatch):
        """Batch jobs and the extension need this as a field, not prose."""
        incomplete = self._scan(monkeypatch, "unavailable", "unavailable")
        complete = self._scan(monkeypatch, "clean", "clean")
        assert incomplete["intel_complete"] is False
        assert complete["intel_complete"] is True
        assert set(incomplete["intel_unavailable"]) == {"VirusTotal", "Safe Browsing"}
