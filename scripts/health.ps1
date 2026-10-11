<#
Is NexGuard up, and is it actually usable?

    powershell -File scripts\health.ps1
    powershell -File scripts\health.ps1 -Target https://api.example.com

Exit code 0 = healthy, 1 = not — usable in a monitor or a deploy gate.

Checks more than "did the port answer". A process can be listening while the
scanner is blind: no reputation source reachable, or a build that is missing the
one API key it depends on. Those are reported, because "running" and "working"
are different questions.
#>

param(
    [string]$Target = "http://127.0.0.1:8000"
)

$ErrorActionPreference = "Stop"
$Target = $Target.TrimEnd('/')

function Line($text, $colour = "Gray") { Write-Host $text -ForegroundColor $colour }

Line "============================================================"
Line " NexGuard health  --  $Target"
Line "============================================================"

# --- 1. Is it answering at all? --------------------------------------------
$health = $null
try {
    $health = Invoke-RestMethod -Uri "$Target/health" -TimeoutSec 6
} catch {
    Line ""
    Line " STATUS: DOWN" Red
    Line ""
    Line " $Target/health did not answer." Red
    Line " $($_.Exception.Message)" DarkGray
    Line ""
    if ($Target -like "*127.0.0.1*" -or $Target -like "*localhost*") {
        Line " Start it with:  START.cmd    (or  run.cmd  /  npm start)" Yellow
    }
    exit 1
}

if ($health.status -ne "ok") {
    Line ""
    Line " STATUS: UNHEALTHY -- /health returned '$($health.status)'" Red
    exit 1
}

Line ""
Line " STATUS: UP" Green
Line "   modules: $($health.modules -join ', ')"

# --- 2. Can it actually scan? ----------------------------------------------
# A listening process is not the same as a working scanner. This runs one real
# scan of a harmless URL and reports which intelligence sources answered.
Line ""
Line " Running one live scan to check the pipeline..."
$scanOk = $true
try {
    $body = @{ url = "http://example.com" } | ConvertTo-Json
    $scan = Invoke-RestMethod -Uri "$Target/scan" -Method Post -Body $body `
        -ContentType "application/json" -TimeoutSec 60

    if ($scan.error) {
        Line "   scan refused: $($scan.error) -- $($scan.message)" Yellow
        Line "   (a quota limit is not a fault; the app is working)" DarkGray
    } else {
        Line "   verdict   : $($scan.verdict)  (score $($scan.risk_score))"
        if ($null -ne $scan.intel_complete) {
            if ($scan.intel_complete) {
                Line "   intel     : all sources answered" Green
            } else {
                $missing = $scan.intel_unavailable -join ', '
                Line "   intel     : INCOMPLETE -- $missing" Yellow
                Line "               verdicts rest on local analysis only." DarkGray
                $scanOk = $false
            }
        }
        if ($scan.sources) {
            foreach ($s in $scan.sources) {
                $c = switch ($s.status) {
                    "flag"        { "Red" }
                    "warn"        { "Yellow" }
                    "clean"       { "Green" }
                    "unavailable" { "DarkYellow" }
                    default       { "Gray" }
                }
                Line ("   {0,-22} {1}" -f $s.name, $s.status) $c
            }
        }
    }
} catch {
    Line "   scan FAILED: $($_.Exception.Message)" Red
    Line "   The port answers but the scan pipeline is broken." Red
    exit 1
}

Line ""
Line "------------------------------------------------------------"
if ($scanOk) {
    Line " HEALTHY -- up, and every intelligence source answered." Green
} else {
    Line " UP, BUT DEGRADED." Yellow
    Line " It is serving requests with some sources unreachable, so a SAFE"
    Line " verdict means less than it looks. Check the missing keys with:"
    Line "     cd backend && py check_env.py" Yellow
}
exit 0
