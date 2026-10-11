#!/usr/bin/env bash
# ============================================================================
# NexGuard — is it running?
#
#   ./health.sh                    check http://127.0.0.1:8000
#   ./health.sh 8001               check a different port
#   ./health.sh https://api.x.com  check a deployed instance
#
# Exit code 0 = up and healthy, 1 = not. Safe in a monitor or a deploy gate.
#
# Checks more than "did the port answer". A process can be listening while the
# scanner is blind — no reputation source reachable — and "running" and
# "working" are different questions.
# ============================================================================

set -uo pipefail

TARGET="${1:-http://127.0.0.1:8000}"
[[ "$TARGET" =~ ^[0-9]+$ ]] && TARGET="http://127.0.0.1:$TARGET"
TARGET="${TARGET%/}"

if command -v python3 >/dev/null 2>&1; then PY=python3; else PY=python; fi

green() { printf '\033[92m%s\033[0m\n' "$1"; }
yellow() { printf '\033[93m%s\033[0m\n' "$1"; }
red() { printf '\033[91m%s\033[0m\n' "$1"; }

echo "============================================================"
echo " NexGuard health  --  $TARGET"
echo "============================================================"

# --- 1. Is it answering at all? ---------------------------------------------
if ! HEALTH=$(curl -fsS -m 6 "$TARGET/health" 2>&1); then
    echo
    red " STATUS: DOWN"
    echo
    echo " $TARGET/health did not answer."
    echo " $HEALTH"
    echo
    case "$TARGET" in
        *127.0.0.1*|*localhost*)
            yellow " Start it with:  ./run.sh    (or  npm start)" ;;
    esac
    exit 1
fi

if ! echo "$HEALTH" | grep -q '"status": *"ok"'; then
    echo
    red " STATUS: UNHEALTHY -- /health did not report ok"
    echo " $HEALTH"
    exit 1
fi

echo
green " STATUS: UP"
echo "$HEALTH" | "$PY" -c "
import json,sys
d=json.load(sys.stdin)
print('   modules:', ', '.join(d.get('modules') or []))
" 2>/dev/null || true

# --- 2. Can it actually scan? -----------------------------------------------
echo
echo " Running one live scan to check the pipeline..."
if ! SCAN=$(curl -fsS -m 60 -X POST "$TARGET/scan" \
        -H "Content-Type: application/json" \
        -d '{"url":"http://example.com"}' 2>&1); then
    red "   scan FAILED: $SCAN"
    red "   The port answers but the scan pipeline is broken."
    exit 1
fi

echo "$SCAN" | "$PY" - <<'PYEOF'
import json, sys
raw = sys.stdin.read()
try:
    d = json.loads(raw)
except Exception:
    print("   could not parse the scan response:", raw[:200]); sys.exit(0)

if d.get("error"):
    print(f"   scan refused: {d['error']} -- {d.get('message','')}")
    print("   (a quota limit is not a fault; the app is working)")
    sys.exit(0)

print(f"   verdict   : {d.get('verdict')}  (score {d.get('risk_score')})")
complete = d.get("intel_complete")
if complete is True:
    print("   intel     : all sources answered")
elif complete is False:
    print("   intel     : INCOMPLETE -- " + ", ".join(d.get("intel_unavailable") or []))
    print("               verdicts rest on local analysis only.")
for s in d.get("sources") or []:
    print("   {:<22} {}".format(s.get("name", "?"), s.get("status", "?")))
sys.exit(2 if complete is False else 0)
PYEOF
DEGRADED=$?

echo
echo "------------------------------------------------------------"
if [ "$DEGRADED" = "2" ]; then
    yellow " UP, BUT DEGRADED."
    echo " It is serving requests with some sources unreachable, so a SAFE"
    echo " verdict means less than it looks. Check the missing keys with:"
    yellow "     cd backend && python check_env.py"
else
    green " HEALTHY -- up, and every intelligence source answered."
fi
exit 0
