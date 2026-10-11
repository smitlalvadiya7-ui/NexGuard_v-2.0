# NexGuard AI — build the Chrome Web Store zip (E9).
# Includes ONLY shipping files (manifest, scripts, pages, icons) — no tests,
# docs or this script. Output: extension/dist/nexguard-extension.zip
$ErrorActionPreference = "Stop"

$ext = $PSScriptRoot
$dist = Join-Path $ext "dist"
$zip = Join-Path $dist "nexguard-extension.zip"

# Shipping allowlist — everything the manifest references, nothing else.
$files = @(
    "manifest.json",
    "background.js", "config.js", "auth.js", "settings.js", "context_scan.js",
    "content.js", "hover_scan.js", "webmail_scan.js", "tab_state.js",
    "popup.html", "popup.js", "popup_render.js", "chat.js",
    "options.html", "options.js",
    "result.html", "result.js", "image_origin_line.js",
    "warning.html", "warning.js"
)

# Every allowlisted file must exist — a missing one means a broken zip.
$missing = $files | Where-Object { -not (Test-Path (Join-Path $ext $_)) }
if ($missing) { throw "Missing shipping files: $($missing -join ', ')" }

New-Item -ItemType Directory -Force $dist | Out-Null
if (Test-Path $zip) { Remove-Item $zip -Force -Confirm:$false }

# Stage into a temp folder so the zip root is the extension root.
$stage = Join-Path $dist "_stage"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force -Confirm:$false }
New-Item -ItemType Directory -Force $stage | Out-Null
foreach ($f in $files) { Copy-Item (Join-Path $ext $f) (Join-Path $stage $f) }
New-Item -ItemType Directory -Force (Join-Path $stage "icons") | Out-Null
Copy-Item (Join-Path $ext "icons\*.png") (Join-Path $stage "icons\")

Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip
Remove-Item $stage -Recurse -Force -Confirm:$false

$size = [math]::Round((Get-Item $zip).Length / 1KB, 1)
Write-Output "Built $zip ($size KB)"
Write-Output "Upload it at https://chrome.google.com/webstore/devconsole"
