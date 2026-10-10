# NEMSEC Phishing Investigation Workbench - one-time setup (Windows PowerShell 5.1+ or PowerShell 7)
# Run from the repository root:  powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot

function Require($cmd, $hint) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "$cmd not found. $hint" }
}
Require "py" "Install Python 3.11+ from https://www.python.org/downloads/windows/ (tick 'Add python.exe to PATH' and the py launcher)."
Require "node" "Install Node.js 20.9+ LTS from https://nodejs.org/"
Require "npm" "npm ships with Node.js."

Write-Host "== Backend: virtual environment and dependencies" -ForegroundColor Cyan
Set-Location "$root\backend"
if (-not (Test-Path ".venv")) { py -3 -m venv .venv }
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
if (-not (Test-Path ".env")) { Copy-Item ".env.example" ".env"; Write-Host "Created backend\.env from .env.example" }
& .\.venv\Scripts\python.exe -c "from app.db import migrate; print('migrations applied:', migrate() or 'none needed')"

Write-Host "== Synthetic sample emails" -ForegroundColor Cyan
& .\.venv\Scripts\python.exe "$root\samples\build_samples.py"

Write-Host "== Frontend dependencies and production build" -ForegroundColor Cyan
Set-Location "$root\frontend"
npm ci
if ($LASTEXITCODE -ne 0) { npm install }
npm run build

if (Test-Path "$root\branding\nemsec-logo.png") {
    Copy-Item "$root\branding\nemsec-logo.png" "$root\frontend\public\nemsec-logo.png" -Force
    Write-Host "NEMSEC logo copied into the UI."
}
Write-Host "`nSetup complete. Start with:  powershell -ExecutionPolicy Bypass -File scripts\start.ps1" -ForegroundColor Green
