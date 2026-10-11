"""
full_scan regressions from the 2026-09-29 test-pack batch.

1. Invalid input is an ERROR, never SAFE. 'https://rules and (if keys are set)
   VirusTotal / Safe Browsing / feeds also weigh in.' — a comment fragment —
   was graded SAFE 0% because Safe Browsing answered 'not listed' for it.

2. The local engine must run even when the shared thread pool is saturated.
   Rate-limited sources sleeping in worker threads starved heuristic_scan, it
   hit its 8 s budget and fell back to score 0 / no ML — which is how
   free-gift-card-claim.tk (ML 0.74) and amazon-account-locked-verify.xyz
   (ML 0.997) came back UNKNOWN 0% with not even the 'insecure HTTP' flag.

3. A bank's own login page is not 'login combined with financial terms'.
   secure.bankofamerica.com/login scored SUSPICIOUS 62: the rule matched the
   'bank' inside the bank's own domain name, and because that rule counts as a
   strong flag it switched off the reputable-host cap.
"""

import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

import aggregator as agg
from ai_engine import heuristic_scan
from test_full_scan_integration import patched_sources, scan  # noqa: F401  (fixture)


# ---------------------------------------------------------------------------
# 1. invalid input
# ---------------------------------------------------------------------------

class TestInvalidInput:
    @pytest.mark.parametrize("raw", [
        "https://rules and (if keys are set) VirusTotal / Safe Browsing / feeds also weigh in.",
        "https://# computed with backend/ml/predict.py at build time.",
        "https://0.001",
        "https://www.apple.com    # expected: SAFE ml=0.001",
    ])
    def test_is_an_error_not_safe(self, patched_sources, raw):
        r = scan(raw)
        assert r["verdict"] == "ERROR", (r["verdict"], r.get("flags"))
        assert "Invalid URL" in " ".join(r["flags"])

    def test_a_normal_url_is_not_affected(self, patched_sources):
        assert scan("https://www.wikipedia.org")["verdict"] != "ERROR"


# ---------------------------------------------------------------------------
# 2. local engine isolation
# ---------------------------------------------------------------------------

def test_local_engine_runs_when_the_shared_pool_is_saturated(patched_sources):
    release = threading.Event()

    async def run():
        loop = asyncio.get_running_loop()
        pool = ThreadPoolExecutor(max_workers=2)
        loop.set_default_executor(pool)
        # Two sleepers own the whole default pool for longer than the 8 s
        # local budget — exactly what 45 s quota waits did in production.
        for _ in range(2):
            loop.run_in_executor(None, release.wait, 30)
        await asyncio.sleep(0.05)
        try:
            return await agg.full_scan("http://free-gift-card-claim.tk/amazon-500")
        finally:
            release.set()

    t0 = time.monotonic()
    r = asyncio.run(run())
    assert "URL uses insecure HTTP" in r["flags"], r["flags"]
    assert "Suspicious domain extension" in r["flags"]
    assert time.monotonic() - t0 < 20


# ---------------------------------------------------------------------------
# 3. brand's own domain
# ---------------------------------------------------------------------------

class TestBrandOwnDomain:
    def test_rule_ignores_the_bank_in_the_banks_own_domain(self):
        flags = heuristic_scan("https://secure.bankofamerica.com/login")["flags"]
        assert "Login combined with financial terms" not in flags

    def test_the_bank_login_page_is_safe(self, patched_sources):
        r = scan("https://secure.bankofamerica.com/login")
        assert r["verdict"] == "SAFE", (r["risk_score"], r["flags"])

    @pytest.mark.parametrize("url", [
        "http://bankofamerica-login-verify.xyz/secure",      # attacker's own domain
        "https://old-shop-example.com/login-bank-verify-account",  # value word in the path
        "http://secure.bankofamerica.com.verify-account.tk/login",  # brand as a subdomain
    ])
    def test_rule_still_fires_where_an_attacker_chose_the_words(self, url):
        assert "Login combined with financial terms" in heuristic_scan(url)["flags"]
