# Verification status

Precise record of what was actually run during development (Linux, Python 3.13.16, Node 22.22, 2026-10-05), what was only tested against mocks, and what needs checking on your machine.

## Actually run

| Area | How |
|---|---|
| Backend unit + integration tests | `pytest`: **70 passed** (parser, URLs, preview, evidence, static analysis, findings, cases/reports/PDF, sandbox state machine, API end-to-end) |
| Static analysis worker limits | Real child processes: timeout (forced slow stage) → partial result kept; size limit; zip bomb ratio; entry/depth/budget limits; traversal + symlink entries flagged with nothing written to disk |
| Synthetic dataset | All 8 samples imported; each produces exactly the findings in `samples/EXPECTED_FINDINGS.md` (enforced by a test) |
| Safe preview | Sanitiser tests against scripts, event handlers, forms, iframes/objects/embeds, meta refresh, `<base>`, `<link>`, CSS `url()`, `srcset`, `poster`, tracking pixels; preview endpoint CSP asserted |
| PDF export | Draft and reviewed PDFs generated and text-extracted with pypdf; markup in analyst text is escaped; pages visually inspected |
| Frontend | `next build` (Next.js 16.3.8, TypeScript 5.9) succeeds; pages screenshotted in headless Chromium at 1400 px and 390 px |
| Browser end-to-end | `frontend/e2e/ui_flow.py` passed: create case → upload → review finding → notes → demo sandbox submission (confirmation required) → draft → reviewed → PDF download |
| Harmless demo program | Cross-compiled with `zig cc -target x86_64-windows-gnu`; parsed with pefile. **Not executed** in development (no Windows). |

## Tested with mocks only

| Area | Mock |
|---|---|
| CAPEv2 adapter | `httpx.MockTransport` imitating `apiv2` endpoints and response shapes taken from CAPE's `web/apiv2/views.py`: submission, status progression, report normalisation, screenshot zip, failed analysis, rejected submission, cancel, timeout, reset failure → quarantine, reset grace timeout, snapshot mismatch, token never stored/logged |
| Demo adapter | Synthetic by design; tests prove results are always flagged demo even if an adapter claims otherwise |

## Needs verification on your machine

1. **Windows setup** — `scripts\setup.ps1` / `start.ps1` were written for Windows PowerShell but not run on Windows here. Watch for: `py` launcher availability, `npm ci`, AV interference with the static worker or the demo `.exe`.
2. **ReportLab fonts on Windows** — Segoe UI/Arial registration paths.
3. **Live CAPEv2** — follow `docs/sandbox-deployment.md`, then run the harmless sample. Confirm especially: `machines/view` status strings on your CAPE version (`poweroff` expected after a task), `user_stop` cancel behaviour, report JSON field names (`behavior.summary.write_files`, etc.), screenshot zip layout.
4. **Guest isolation** — the checklist in the deployment guide must be verified by hand; software can't prove your network is isolated.
5. **Demo exe execution** — that it creates `NEMSEC_SANDBOX_DEMO_<pid>.txt` in `%TEMP%` on Windows 10/11 (it needs the Universal C Runtime, present on Windows 10+).
