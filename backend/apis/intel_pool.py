"""
Threads reserved for the reputation lookups that decide a verdict.

VirusTotal, Safe Browsing / Web Risk and URLHaus used to run through
asyncio.to_thread(), which is the event loop's one default pool (CPU count + 4
threads, 20 here). That pool also carries page fetches, DNS lookups, RDAP
retries and urlscan polls. Those keep their thread after full_scan stops
waiting for them. On 2026-10-09 a full pool kept these lookups queued past
full_scan's 2.2 s budget. They were cancelled before they started, and rows
read UNKNOWN ("not checked") although no source had failed
(tests/test_intel_pool.py).

These lookups are short: a quota wait under 1 s, an open breaker answers at
once, and a request has a timeout. So a modest pool of their own is enough,
and nothing slow ever lands here. Same idea as aggregator._LOCAL_POOL, which
the rules and the ML model got for the same reason.
"""

from __future__ import annotations

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor

# Eight batch scans x three lookups, plus room for single scans and a second
# job. NEXGUARD_INTEL_THREADS overrides it.
_THREADS = int(os.getenv("NEXGUARD_INTEL_THREADS", "") or 32)

_POOL = ThreadPoolExecutor(max_workers=_THREADS, thread_name_prefix="nexguard-intel")


def run(fn, *args):
    """Run a blocking reputation lookup on the reserved threads (await the result)."""
    return asyncio.get_running_loop().run_in_executor(_POOL, fn, *args)
