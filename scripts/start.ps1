# Starts API, background worker and UI, each in its own window. All bind to 127.0.0.1.
#   powershell -ExecutionPolicy Bypass -File scripts\start.ps1            (sandbox mode from backend\.env)
#   powershell -ExecutionPolicy Bypass -File scripts\start.ps1 -Demo      (synthetic sandbox results)
param([switch]$Demo, [switch]$Dev)
$root = Split-Path -Parent $PSScriptRoot
$py = "$root\backend\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) { throw "Run scripts\setup.ps1 first." }
$mode = if ($Demo) { '$env:PHB_SANDBOX_MODE="demo";' } else { '' }

Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$root\backend'; $mode `$Host.UI.RawUI.WindowTitle='NEMSEC API'; & '$py' -m uvicorn app.main:app --host 127.0.0.1 --port 8000"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$root\backend'; $mode `$Host.UI.RawUI.WindowTitle='NEMSEC worker'; & '$py' -m app.worker"
$ui = if ($Dev) { "npm run dev" } else { "npm run start" }
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$root\frontend'; `$Host.UI.RawUI.WindowTitle='NEMSEC UI'; $ui"

Start-Sleep -Seconds 6
Start-Process "http://127.0.0.1:3000"
Write-Host "Workbench: http://127.0.0.1:3000   API docs: http://127.0.0.1:8000/docs"
