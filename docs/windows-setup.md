# Windows setup

## Supported hosts

| Role | Supported |
|---|---|
| Workbench (UI + API + worker) | Windows 10 22H2 / Windows 11, x64. Also Linux and macOS (`scripts/start.sh`). |
| Sandbox engine | Separate Linux host with KVM — see [sandbox-deployment.md](sandbox-deployment.md). Not the analyst PC. |

No virtualisation is needed on the workbench machine itself; only the sandbox host needs VT-x/AMD-V.

## Prerequisites

- **Python 3.11 or newer** (3.13 used in development) from python.org — tick *Add python.exe to PATH*; keep the `py` launcher.
- **Node.js 20.9 or newer** (LTS) from nodejs.org.
- Optional: Git.

Antivirus note: `samples/harmless/nemsec_sandbox_demo.exe` is a harmless program (source alongside) but some AV products flag unknown unsigned executables. If yours quarantines it, exclude the `samples\harmless` folder or delete the sample — everything else works without it.

## Install

From the repository root in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
```

This creates `backend\.venv`, installs pinned Python dependencies, creates `backend\.env` from `.env.example`, applies database migrations, builds the sample emails, installs frontend dependencies with `npm ci`, builds the UI, and copies `branding\nemsec-logo.png` into the UI if present.

## Run

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start.ps1          # sandbox mode from backend\.env (default: disabled)
powershell -ExecutionPolicy Bypass -File scripts\start.ps1 -Demo    # synthetic sandbox results, clearly labelled
powershell -ExecutionPolicy Bypass -File scripts\start.ps1 -Dev     # Next.js dev server with hot reload
```

Three windows open: **NEMSEC API** (127.0.0.1:8000, API docs at /docs), **NEMSEC worker**, **NEMSEC UI** (127.0.0.1:3000). Close them to stop.

Manual equivalent:

```powershell
cd backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
.\.venv\Scripts\python.exe -m app.worker            # second terminal
cd ..\frontend; npm run start                        # third terminal
```

For a single-process demo you can set `PHB_INLINE_WORKER=1` and skip the separate worker.

## Configuration

Edit `backend\.env` (all keys documented in `backend\.env.example`). Real environment variables override the file. Relative `PHB_DATA_DIR` paths are resolved from `backend\`.

Data lives in `backend\data\` by default:

```
data\phishbench.sqlite3     database
data\evidence\              original emails and attachments (generated names, read-only)
data\artifacts\             sandbox screenshots
data\reports\               exported PDFs
```

Back it up as a unit. Treat it as sensitive: it contains real email content.

## Security defaults

- API and UI bind to `127.0.0.1` only. The API rejects requests whose Host header isn't a local name (DNS-rebinding protection). Changing `PHB_HOST` logs a warning.
- No authentication is built in because nothing is exposed beyond the local machine. Don't publish the ports.
- No outbound network requests are made by the workbench except to the CAPE URL you configure.

## Tests

```powershell
powershell -ExecutionPolicy Bypass -File scripts\test.ps1
# Browser walkthrough (needs start.ps1 -Demo running in another window):
powershell -ExecutionPolicy Bypass -File scripts\test.ps1 -Browser
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| UI says "Can't reach the backend" | The API window isn't running or port 8000 is taken. `netstat -ano | findstr :8000` |
| Attachments stay "Queued" | The worker window isn't running (or set `PHB_INLINE_WORKER=1`). |
| `py` not found | Reinstall Python with the launcher, or edit setup.ps1 to use `python`. |
| Static analysis always "Partial — stopped early" | Slow machine or AV scanning the child process; raise `PHB_STATIC_TIMEOUT_S`. |
| PDF shows boxes for non-Latin text | The PDF uses Segoe UI/Arial from `C:\Windows\Fonts`; if neither exists it falls back to Helvetica (Latin only). |
| Execution policy error | Use the `powershell -ExecutionPolicy Bypass -File …` form shown above. |
