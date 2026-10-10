#!/usr/bin/env bash
# Linux/macOS equivalent of start.ps1 (single terminal). Usage: scripts/start.sh [--demo]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ "${1:-}" == "--demo" ]] && export PHB_SANDBOX_MODE=demo
cd "$ROOT/backend"
PY="${PY:-.venv/bin/python}"
"$PY" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 & API=$!
"$PY" -m app.worker & WORKER=$!
cd "$ROOT/frontend" && npm run start & UI=$!
trap 'kill $API $WORKER $UI 2>/dev/null' EXIT
wait
