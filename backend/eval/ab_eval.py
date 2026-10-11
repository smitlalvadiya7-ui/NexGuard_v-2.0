"""
Controlled A/B harness for the reputable-host / shared-hosting / RDAP fixes.

Freezes ONE corpus (so feed drift can't contaminate the comparison) then scans
it with whatever version of aggregator.py is on disk. Run it twice — once on the
new code, once on the stashed old code — against the SAME frozen corpus.

    python -m eval.ab_eval build  eval/_corpus.json
    python -m eval.ab_eval scan   eval/_corpus.json  eval/_after.json
    # (git stash the aggregator)
    python -m eval.ab_eval scan   eval/_corpus.json  eval/_before.json
    python -m eval.ab_eval diff   eval/_before.json  eval/_after.json

Legit = Tranco top-N + bundled security pages + the documented baseline FPs
(all genuinely legitimate). Phish = current OpenPhish feed.
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

_BACKEND = Path(__file__).resolve().parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from eval.realworld_eval import (  # noqa: E402
    fetch_tranco, fetch_openphish, SAFE_SECURITY_PAGES, FALLBACK_LEGIT, _is_threat,
    select_eval_legit, select_eval_phish, load_training_urls,
)

# Exact false positives recorded in the committed metrics_realworld.json — all
# legitimate. Seeded into the legit corpus so the A/B measures the fix on them.
BASELINE_FPS = [
    "https://googleapis.com", "https://dzen.ru", "https://googletagmanager.com",
    "https://googlevideo.com", "https://googleusercontent.com", "https://bing.com",
    "https://doubleclick.net", "https://microsoftonline.com", "https://apple-dns.net",
    "https://skype.com", "https://krebsonsecurity.com",
    "https://support.google.com/accounts/answer/6010255", "https://www.schneier.com",
]
# Shared-hosting phishing-style hosts from the baseline false-negatives — used to
# confirm the cap no longer blanket-suppresses tenant pages (live; may be dead).
BASELINE_SHARED_FNS = [
    "http://cerdeirahugo139-alt.github.io/orange-mobilier",
    "https://concessioninvert.wasmer.app/", "https://chestermainres.wasmer.app/",
    "http://truistwirestop.web.app/", "https://verificarms365.pages.dev/",
    "http://www.tommbtaq.vercel.app/",
]


def build(out_path: str, n_legit: int = 150, n_phish: int = 150) -> None:
    # Same honest selection as realworld_eval (M1): deeper Tranco ranks,
    # exemption-list excluded, eval-half only, no training URLs in the phish set.
    ranked = fetch_tranco(10000)
    legit = (select_eval_legit(ranked, n_legit, 2000, 10000) if ranked
             else list(FALLBACK_LEGIT))
    legit = [f"https://{d}" for d in legit[:n_legit]]
    legit = legit + SAFE_SECURITY_PAGES + BASELINE_FPS
    phish = select_eval_phish(fetch_openphish(n_phish * 3), n_phish,
                              load_training_urls())
    # de-dup, preserve order
    def dedup(xs):
        seen, out = set(), []
        for x in xs:
            if x not in seen:
                out.append(x); seen.add(x)
        return out
    corpus = {"legit": dedup(legit), "phish": dedup(phish + BASELINE_SHARED_FNS)}
    Path(out_path).write_text(json.dumps(corpus, indent=2), encoding="utf-8")
    print(f"corpus: {len(corpus['legit'])} legit, {len(corpus['phish'])} phish -> {out_path}")


async def _scan(targets, concurrency=16, timeout=30.0):
    from aggregator import full_scan
    sem = asyncio.Semaphore(concurrency)
    async def one(t):
        async with sem:
            try:
                r = await asyncio.wait_for(full_scan(t), timeout=timeout)
                return {"target": t, "verdict": (r.get("verdict") or "ERROR").upper(),
                        "score": int(r.get("risk_score", 0) or 0),
                        "reachable": bool(r.get("resolved_ip"))}
            except Exception as e:
                return {"target": t, "verdict": "ERROR", "score": 0,
                        "reachable": False, "error": type(e).__name__}
    return await asyncio.gather(*[one(t) for t in targets])


def scan(corpus_path: str, out_path: str) -> None:
    corpus = json.loads(Path(corpus_path).read_text(encoding="utf-8"))
    t0 = time.perf_counter()
    legit = asyncio.run(_scan(corpus["legit"]))
    phish = asyncio.run(_scan(corpus["phish"]))
    Path(out_path).write_text(json.dumps({"legit": legit, "phish": phish}, indent=2),
                              encoding="utf-8")
    print(f"scanned {len(legit)} legit + {len(phish)} phish in "
          f"{time.perf_counter()-t0:.0f}s -> {out_path}")


def _metrics(res: dict) -> dict:
    legit_ok = [r for r in res["legit"] if r["verdict"] != "ERROR"]
    phish_ok = [r for r in res["phish"] if r["verdict"] != "ERROR" and r.get("reachable")]
    fp = sum(1 for r in legit_ok if _is_threat(r["verdict"]))
    tn = len(legit_ok) - fp
    tp = sum(1 for r in phish_ok if _is_threat(r["verdict"]))
    fn = len(phish_ok) - tp
    div = lambda a, b: (a / b) if b else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "legit_scored": len(legit_ok), "phish_scored_live": len(phish_ok),
            "precision": round(div(tp, tp + fp), 4),
            "recall": round(div(tp, tp + fn), 4),
            "fpr": round(div(fp, fp + tn), 4),
            "fnr": round(div(fn, fn + tp), 4)}


def diff(before_path: str, after_path: str) -> None:
    before = json.loads(Path(before_path).read_text(encoding="utf-8"))
    after = json.loads(Path(after_path).read_text(encoding="utf-8"))
    mb, ma = _metrics(before), _metrics(after)
    print("\n" + "=" * 64)
    print("A/B  (same frozen corpus; before = old code, after = new code)")
    print("=" * 64)
    row = "{:<14}{:>14}{:>14}{:>12}"
    print(row.format("metric", "before", "after", "delta"))
    print("-" * 64)
    for k in ("precision", "recall", "fpr", "fnr"):
        d = ma[k] - mb[k]
        print(row.format(k, f"{mb[k]*100:.2f}%", f"{ma[k]*100:.2f}%", f"{d*100:+.2f}pp"))
    print("-" * 64)
    for k in ("tp", "fp", "tn", "fn"):
        print(row.format(k.upper(), mb[k], ma[k], f"{ma[k]-mb[k]:+d}"))
    print("-" * 64)
    # Which legit URLs flipped FP->clean (fixed) or clean->FP (regressed)?
    bmap = {r["target"]: r for r in before["legit"]}
    amap = {r["target"]: r for r in after["legit"]}
    fixed, regressed = [], []
    for t in bmap:
        if t not in amap:
            continue
        b_thr = _is_threat(bmap[t]["verdict"]) and bmap[t]["verdict"] != "ERROR"
        a_thr = _is_threat(amap[t]["verdict"]) and amap[t]["verdict"] != "ERROR"
        if b_thr and not a_thr:
            fixed.append((t, bmap[t]["verdict"], amap[t]["verdict"]))
        elif a_thr and not b_thr:
            regressed.append((t, bmap[t]["verdict"], amap[t]["verdict"]))
    print(f"LEGIT fixed (FP -> clean): {len(fixed)}")
    for t, bv, av in fixed:
        print(f"   + {t}   {bv} -> {av}")
    print(f"LEGIT regressed (clean -> FP): {len(regressed)}")
    for t, bv, av in regressed:
        print(f"   - {t}   {bv} -> {av}")
    # Phish that flipped (caught now / missed now)
    bpm = {r["target"]: r for r in before["phish"]}
    apm = {r["target"]: r for r in after["phish"]}
    newly_caught, newly_missed = [], []
    for t in bpm:
        if t not in apm or not apm[t].get("reachable"):
            continue
        b_thr = _is_threat(bpm[t]["verdict"])
        a_thr = _is_threat(apm[t]["verdict"])
        if a_thr and not b_thr:
            newly_caught.append((t, bpm[t]["verdict"], apm[t]["verdict"]))
        elif b_thr and not a_thr:
            newly_missed.append((t, bpm[t]["verdict"], apm[t]["verdict"]))
    print(f"PHISH newly caught: {len(newly_caught)}")
    for t, bv, av in newly_caught:
        print(f"   + {t}   {bv} -> {av}")
    print(f"PHISH newly missed: {len(newly_missed)}")
    for t, bv, av in newly_missed:
        print(f"   - {t}   {bv} -> {av}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    if cmd == "build":
        build(sys.argv[2])
    elif cmd == "scan":
        scan(sys.argv[2], sys.argv[3])
    elif cmd == "diff":
        diff(sys.argv[2], sys.argv[3])
    else:
        print(__doc__)
