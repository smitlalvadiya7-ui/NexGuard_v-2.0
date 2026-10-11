"""
Login-page bias of the URL model — measured, one fix tried, the outcome recorded.

Why this exists
---------------
The 2026-09-29 test pack showed the char model scoring genuine sign-in pages as
phishing: accounts.google.com/signin 0.95, appleid.apple.com/sign-in 0.93,
secure.bankofamerica.com/login 1.0. The training data explains it: legitimate
rows are mostly bare Tranco domains, so login vocabulary is ~29x more common in
the phishing class (937/10,715 rows) than the legitimate one (33/10,712).

What it does
------------
1. Measures the bias: ML-only phishing rate on login-style URLs built from
   legitimate Tranco domains in the EVAL half of the permanent hash split
   (never trained on), plus a fixed list of real sign-in pages.
2. Tries the obvious fix: add login-path URLs on TRAIN-half legitimate domains
   as extra negatives (paths only — putting login words in hostnames taught the
   model that 'my-facebook-account-log-in.blogspot.com' is benign), retrain
   with the same pipeline and split as train_char_model.py.
3. Compares deployed vs candidate on the original held-out split, the frozen
   real-world corpus (eval/_corpus_m4.json) and the URL test pack
   (testdata/urls_testpack.csv) — first ML-only, then through the FULL
   full_scan pipeline with every network source stubbed clean (rules +
   typosquat + ML only; reputation cannot rescue a miss).

The candidate is written to the scratch path given by --out and is NEVER
deployed by this script. Results go to eval/login_bias_result.json.

Run (from backend/):  py -m eval.login_bias_experiment
"""

import argparse
import asyncio
import csv
import json
import os
import random
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
REPO = os.path.dirname(BACKEND)
sys.path.insert(0, BACKEND)

RESULT_PATH = os.path.join(HERE, "login_bias_result.json")
CORPUS = os.path.join(HERE, "_corpus_m4.json")
PACK = os.path.join(REPO, "testdata", "urls_testpack.csv")
DATASET = os.path.join(BACKEND, "ml", "raw_dataset.csv")
LIVE_MODEL = os.path.join(BACKEND, "ml", "phishing_model.joblib")
ESTABLISHED = os.path.join(BACKEND, "data", "established_domains.txt")

# First-party sign-in pages of real services (all on the test pack's SAFE list).
REAL_SIGNIN_PAGES = [
    "https://accounts.google.com/signin",
    "https://login.microsoftonline.com",
    "https://appleid.apple.com/sign-in",
    "https://signin.aws.amazon.com/console",
    "https://secure.bankofamerica.com/login",
    "https://www.paypal.com/uk/signin",
    "https://netbanking.hdfcbank.com",
    "https://web.telegram.org",
]

LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/account/login", "/accounts/login", "/user/login",
    "/users/sign_in", "/auth/login", "/customer/account/login", "/secure/login",
    "/session/new", "/sso/login", "/online-banking/login", "/password/reset",
    "/oauth/authorize", "/login?next=%2Fdashboard",
]
HOST_PREFIXES = ["", "www."]


def _host(url):
    try:
        return (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
    except ValueError:
        return ""


def login_negatives(domains, split, n, exclude, seed):
    """n login-path URLs on legitimate domains from one side of the hash split."""
    from ml.dataset_utils import feed_split
    pool = [d for d in domains if feed_split(d) == split and d not in exclude]
    rnd = random.Random(seed)
    return [f"https://{rnd.choice(HOST_PREFIXES)}{d}{rnd.choice(LOGIN_PATHS)}"
            for d in rnd.sample(pool, min(n, len(pool)))]


def _rate(model, urls):
    if not urls:
        return None
    return round(float((model.predict_proba(urls)[:, 1] >= 0.5).mean()), 4)


def _heldout(model, X, y):
    from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
    p = model.predict_proba(X)[:, 1]
    pred = (p >= 0.5).astype(int)
    return {"roc_auc": round(float(roc_auc_score(y, p)), 4),
            "f1": round(float(f1_score(y, pred)), 4),
            "precision": round(float(precision_score(y, pred)), 4),
            "recall": round(float(recall_score(y, pred)), 4)}


def _pipeline_child(label):
    """Child process: full_scan every corpus URL with the network stubbed clean."""
    import aggregator as A

    async def _clean(*a, **k):
        return {"status": "clean", "detail": "not listed", "match": None, "raw_positives": 0}

    A.check_virustotal = lambda u: {"status": "clean", "detail": "stub", "raw_positives": 0}
    for name in ("check_safe_browsing", "check_web_risk", "check_urlhaus", "check_phish_feeds"):
        setattr(A, name, _clean)
    for name in ("check_whois", "check_geo", "check_ssl_cert", "check_urlscan"):
        setattr(A, name, lambda *_: _clean())
    A._resolve_chain = lambda u, **k: {"chain": [u], "final": u, "loop": False,
                                       "truncated": False, "html": None, "blocked_scheme": False}
    A._resolve_ip = lambda d: "203.0.113.10"
    A.analyze_page_content = lambda u, html=None: dict(A._FB_CONTENT)
    A._explain_url = lambda u, top_n=5: None
    A.cache_get = lambda k: None
    A.cache_put = lambda k, v, ttl=None: None

    groups = _groups()

    async def run():
        out = {}
        for group, urls in groups.items():
            flagged = []
            for u in urls:
                r = await A.full_scan(u)
                flagged.append(r["verdict"] in ("SUSPICIOUS", "MALICIOUS"))
            out[group] = {"n": len(urls), "flagged": sum(flagged),
                          "flagged_urls": [u for u, f in zip(urls, flagged) if f]
                          if group.endswith(("legit", "SAFE")) else
                          [u for u, f in zip(urls, flagged) if not f]}
        return out

    print(json.dumps({"label": label, "result": asyncio.run(run())}))


def _groups():
    m4 = json.load(open(CORPUS, encoding="utf-8"))
    pick = (lambda x: x if isinstance(x, str) else x["url"])
    groups = {"m4-legit": [pick(x) for x in m4["legit"]],
              "m4-phish": [pick(x) for x in m4["phish"]]}
    for r in csv.DictReader(open(PACK, encoding="utf-8")):
        groups.setdefault("pack-" + r["bucket"], []).append(r["url"])
    return groups


def _pipeline(model_path, label):
    env = dict(os.environ, NEXGUARD_MODEL_PATH=model_path, NEXGUARD_DISABLE_FEEDS="1")
    proc = subprocess.run([sys.executable, "-m", "eval.login_bias_experiment", "--pipeline-child", label],
                          cwd=BACKEND, env=env, capture_output=True, text=True, encoding="utf-8")
    line = [ln for ln in proc.stdout.splitlines() if ln.startswith('{"label"')]
    if not line:
        raise SystemExit(f"pipeline run for {label} failed:\n{proc.stderr[-2000:]}")
    return json.loads(line[-1])["result"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=3000, help="login negatives added to training")
    ap.add_argument("--out", default=os.path.join(tempfile.gettempdir(), "nexguard_login_candidate.joblib"))
    ap.add_argument("--pipeline-child", default=None, help=argparse.SUPPRESS)
    args = ap.parse_args()
    if args.pipeline_child:
        _pipeline_child(args.pipeline_child)
        return

    import joblib
    import numpy as np
    import pandas as pd
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import Pipeline
    from top_domains import registrable_of

    df = pd.read_csv(DATASET)
    urls = df["url"].astype(str).tolist()
    y = df["status"].astype(str).str.lower().str.contains("phish").astype(int).values
    X_train, X_test, y_train, y_test = train_test_split(
        urls, y, test_size=0.2, random_state=42, stratify=y)

    groups = _groups()
    exclude = {registrable_of(_host(u)) for g in groups.values() for u in g}
    exclude |= {registrable_of(_host(u)) for u in X_test + REAL_SIGNIN_PAGES}
    domains = [ln.strip() for ln in open(ESTABLISHED, encoding="utf-8")
               if ln.strip() and not ln.startswith("#")]
    train_neg = login_negatives(domains, "train", args.n, exclude, seed=7)
    probe_neg = login_negatives(domains, "eval", 1000, exclude, seed=99)

    legit_login = sum(1 for u, lab in zip(urls, y) if lab == 0 and any(
        w in u.lower() for w in ("login", "log-in", "signin", "sign-in", "account")))
    phish_login = sum(1 for u, lab in zip(urls, y) if lab == 1 and any(
        w in u.lower() for w in ("login", "log-in", "signin", "sign-in", "account")))

    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), max_features=200_000,
                                  sublinear_tf=True, min_df=2)),
        ("clf", LogisticRegression(max_iter=2000, C=10.0, solver="liblinear",
                                   class_weight="balanced")),
    ])
    pipe.fit(X_train + train_neg, np.concatenate([y_train, np.zeros(len(train_neg), int)]))
    joblib.dump({"model": pipe, "features": [], "name": "char_tfidf_logreg",
                 "calibrated": False, "input_mode": "raw_url"}, args.out, compress=3)
    deployed = joblib.load(LIVE_MODEL)["model"]

    def ml_only(model):
        return {
            "heldout": _heldout(model, X_test, y_test),
            "login_urls_on_unseen_legit_domains_flagged": _rate(model, probe_neg),
            "real_signin_pages_flagged": _rate(model, REAL_SIGNIN_PAGES),
            **{f"{g}_flagged": _rate(model, u) for g, u in groups.items()},
        }

    result = {
        "run_at": datetime.now(timezone.utc).isoformat(),
        "training_rows_with_login_words": {"legitimate": legit_login, "phishing": phish_login},
        "candidate": f"deployed recipe + {len(train_neg)} login-path negatives on train-half "
                     "Tranco domains, class_weight=balanced",
        "ml_only": {"deployed": ml_only(deployed), "candidate": ml_only(pipe)},
        "full_pipeline_network_stubbed": {"deployed": _pipeline(LIVE_MODEL, "deployed"),
                                          "candidate": _pipeline(args.out, "candidate")},
    }
    dep = result["full_pipeline_network_stubbed"]["deployed"]
    cand = result["full_pipeline_network_stubbed"]["candidate"]
    worse = [g for g in dep if (g.endswith(("legit", "SAFE")) and cand[g]["flagged"] > dep[g]["flagged"])
             or (not g.endswith(("legit", "SAFE")) and cand[g]["flagged"] < dep[g]["flagged"])]
    better = [g for g in dep if (g.endswith(("legit", "SAFE")) and cand[g]["flagged"] < dep[g]["flagged"])
              or (not g.endswith(("legit", "SAFE")) and cand[g]["flagged"] > dep[g]["flagged"])]
    result["decision"] = ("KEEP DEPLOYED — the candidate is worse at the verdict level on: "
                          + ", ".join(worse)) if worse else (
        "candidate is no worse at the verdict level" + (f" and better on {', '.join(better)}" if better else "")
        + " — judge it on the live A/B (eval/ab_eval) before promoting")
    with open(RESULT_PATH, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(json.dumps({k: result[k] for k in ("training_rows_with_login_words", "decision")}, indent=2))
    print(f"full result -> {RESULT_PATH}")


if __name__ == "__main__":
    main()
