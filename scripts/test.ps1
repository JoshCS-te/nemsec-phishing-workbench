# Runs the backend test suite, and optionally the browser walkthrough (needs start.ps1 -Demo running).
param([switch]$Browser)
$root = Split-Path -Parent $PSScriptRoot
$py = "$root\backend\.venv\Scripts\python.exe"
Set-Location "$root\backend"
& $py -m pytest -q
if ($Browser) {
    & $py -m playwright install chromium
    & $py "$root\frontend\e2e\ui_flow.py"
}
