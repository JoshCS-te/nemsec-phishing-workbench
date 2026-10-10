# Architecture

## Components

```
 Analyst's Windows machine (everything bound to 127.0.0.1)                 Separate sandbox host (Linux + KVM)
┌──────────────────────────────────────────────────────────────────┐     ┌──────────────────────────────────────┐
│  Browser ── http://127.0.0.1:3000                                │     │  CAPEv2 (REST API v2, token auth)    │
│     │   Next.js UI (rewrites /api/* to the backend)              │     │     │                                │
│     ▼                                                            │     │     ▼ revert snapshot, run, power off│
│  FastAPI  127.0.0.1:8000 ─── SQLite (cases, findings, jobs …)    │     │  Disposable Windows guest            │
│     │           │                                                │     │  host-only net → INetSim (fake svcs) │
│     │           └── evidence/  artifacts/  reports/  (generated   │     └──────────────▲───────────────────────┘
│     │               names, SHA-256, read-only after write)       │                    │
│     ▼                                                            │                    │ only on explicit analyst
│  Worker process (python -m app.worker)                           │                    │ submission (HTTP, one
│     ├─ static analysis → child process per attachment            │                    │ dedicated NIC/VLAN)
│     │    (timeout, memory cap, size cap, checkpoints)            │                    │
│     └─ sandbox state machine ── SandboxAdapter ──────────────────┼────────────────────┘
│                                 (CapeAdapter | DemoAdapter)      │
└──────────────────────────────────────────────────────────────────┘
```

Nothing on the analyst machine executes attachment content. The only path to execution is the sandbox adapter, which only acts on a `sandbox_jobs` row created by an explicit, confirmed analyst request.

### Tradeoffs chosen

| Decision | Why | Cost |
|---|---|---|
| SQLite-backed job queue instead of Redis/Celery | One fewer service to install on Windows; jobs survive restarts; single analyst | Not built for many concurrent workers |
| Static analysis in a child process per file | A hostile file that hangs or bloats a parser is killed without taking down the worker; partial results kept via checkpoints | ~150 ms process start per attachment |
| Magic-byte identification instead of libmagic | No native DLL to install on Windows; behaviour is documented and testable | Fewer formats identified than libmagic |
| nh3 + CSP sandbox + iframe sandbox | Three independent layers; any one alone blocks scripts | Some legitimate formatting (CSS from `<style>`) is lost in preview |
| CAPEv2 for execution | Free, maintained, real REST API, per-task snapshot revert, process/file/registry/network capture | Needs a Linux/KVM host; not runnable inside this repo's CI |
| ReportLab for PDF | Pure Python, works offline on Windows, no headless browser | Layout is code, not HTML/CSS |
| No numeric risk score | Scores read as verdicts and hide reasoning | Analyst must weigh indicators (intended) |

## Evidence flow

```
upload .eml
  │ size check (PHB_MAX_UPLOAD_BYTES), .eml only
  ▼
sha256(bytes) ── already stored? ──yes──► record evidence_imports(duplicate=1), link to case, stop
  │ no
  ▼
write bytes → evidence/<ab>/<random>.bin (O_EXCL, then read-only)       evidence row EV-…
  ▼
parse (compat32, never raises) → emails row: raw+decoded headers, warnings, errors, MIME tree
  ├─ each attachment → evidence row AT-… (parent EV-…, MIME part ref), bytes stored, static job queued
  ├─ links from text + raw HTML → urls rows (original string kept)
  └─ header / link / language rules → findings rows
worker: static job
  ├─ verify stored hash, read bytes
  ├─ child process: identify → strings → format-specific (checkpoint after each)
  └─ attachment rules → findings rows (re-generated; analyst review state kept)
analyst: case → review findings → notes → (optional) sandbox submit → report draft → reviewed → PDF
```

## Trust boundaries

1. **Uploaded file → workbench.** Everything in the `.eml` is attacker-controlled, including Received and Authentication-Results headers. The UI shows them as claims; findings based on them are low weight and say so.
2. **Preview frame → UI.** The preview is a separate document with a CSP `sandbox` directive (unique origin, no scripts) loaded in a sandboxed iframe; it cannot reach the UI, the API or the network.
3. **Static parser → worker.** Parsers run in a child process with wall-clock and memory limits. Archives are read in memory; entry names never touch the filesystem.
4. **Workbench → sandbox host.** One HTTP API (token) on a dedicated interface. The guest has no route to the workbench, the host's LAN, or the internet.
5. **Sandbox results → workbench.** Reports from the engine are data: screenshots are accepted only if they are PNG/JPEG by magic bytes and are served with `default-src 'none'; sandbox`. Demo-mode flags are set by the workbench, never trusted from the adapter payload.

## Data model (SQLite, `backend/app/migrations/`)

| Table | Purpose |
|---|---|
| `evidence` | Every preserved byte stream: emails (EV-) and attachments (AT-), hash, size, generated stored name, parent, MIME part |
| `evidence_imports` | Every upload, including duplicates |
| `emails` | Parse status, indexed summary columns, full structured parse (JSON with raw values), warnings, errors |
| `attachments` | Declared vs detected type, static analysis status and result |
| `urls` | Extracted links with original string, visible text, host, warnings |
| `findings` | Rule inferences with evidence, weight, uncertainty, benign explanations |
| `cases`, `case_evidence`, `case_findings` | Cases, evidence selection for report, per-case review status and comments |
| `notes` | Facts, interpretations, questions, working notes, with evidence references |
| `reference_identities` | Names/addresses for impersonation checks (per case or global) |
| `jobs` | Work queue (static analysis, sandbox polling) |
| `sandbox_workers`, `sandbox_jobs`, `sandbox_artifacts` | Guest state (available/busy/quarantined), job lifecycle, observations, coverage, screenshots |
| `reports`, `report_revisions` | Revisions with generated snapshot + analyst content, review status, PDF hash |
| `history` | Audit trail of case changes, submissions and report revisions (secrets redacted) |

## Folder structure

```
nemsec-phishbench/
├── backend/
│   ├── app/
│   │   ├── main.py              FastAPI app and routes
│   │   ├── config.py            PHB_* settings (+ backend/.env)
│   │   ├── db.py                SQLite, migrations runner, history
│   │   ├── evidence.py          generated-name store, hashing, verification
│   │   ├── logsafe.py           secret redaction for logs/history
│   │   ├── services.py          import pipeline, finding generation
│   │   ├── cases.py             cases, notes, reviews, references
│   │   ├── worker.py            job queue worker
│   │   ├── parsing/             email_parser.py, sanitize.py
│   │   ├── analysis/            urls.py, findings.py, filetype.py, static.py, static_worker.py, runner.py
│   │   ├── sandbox/             base.py (adapter contract), cape.py, demo.py, service.py (state machine)
│   │   ├── reports/             builder.py (revisions), pdf.py (ReportLab)
│   │   └── migrations/          001_init.sql, 002_sandbox_reset.sql
│   ├── tests/                   pytest suite (70 tests)
│   ├── requirements*.txt, .env.example, pytest.ini
├── frontend/
│   ├── src/app/                 pages: / , /import, /emails, /emails/[id], /attachments/[id],
│   │                            /cases/[id], /cases/[id]/report, /sandbox, /sandbox/jobs/[id]
│   ├── src/components/          Shell, FindingCard, ui (provenance tags, badges, states)
│   ├── src/lib/api.ts
│   └── e2e/ui_flow.py           Playwright walkthrough
├── samples/                     build_samples.py, emails/*.eml, harmless/ (demo program + source)
├── sandbox/                     CAPE config snippets for the sandbox host
├── branding/                    put nemsec-logo.png here
├── scripts/                     setup.ps1, start.ps1, test.ps1, start.sh
└── docs/
```
