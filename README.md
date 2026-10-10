# NEMSEC Phishing Investigation Workbench

A local workbench for investigating suspicious email: preserve the evidence, look at it safely, explain what is suspicious and why, analyse attachments without running them, optionally detonate an attachment in an isolated sandbox VM, and write an evidence-backed report.

Built by **[NEMSEC](https://nemsec.com.ng)**.

The workbench always keeps four things apart:

| | Meaning | Shown as |
|---|---|---|
| **Observed** | What the evidence contains, as written | solid square tag, blue rule |
| **Rule inference** | What a rule concluded from it | hollow diamond tag, double amber rule |
| **Analyst** | What you concluded | filled circle tag, green rule |
| **Not established** | What could not be determined | dashed ring tag, dashed grey rule |

There is no phishing "score". A single indicator, a number, or a quiet sandbox run is never presented as proof either way.

## What it does

- **Evidence import** — `.eml` upload, original bytes preserved under generated names, SHA-256, duplicate detection, upload limits, every attachment preserved byte-for-byte with its MIME part reference.
- **Parsing** — encoded headers, multipart, duplicate headers, malformed dates and charsets; raw values kept next to decoded ones; nothing invented. Received and Authentication-Results are shown as **reported claims** behind a trust-boundary note.
- **Safe preview** — sanitised HTML (nh3) served with `default-src 'none'; sandbox` CSP inside `<iframe sandbox="">`. No scripts, forms, embeds or remote loads; links show their real destination (look-alike hosts in punycode) and cannot be clicked.
- **URL investigation** — text and HTML links, visible text vs destination, IP and obfuscated-IP hosts, IDN/mixed-script look-alikes, odd schemes, `user@host` tricks, malformed URLs. No link is ever visited.
- **Explainable findings** — every finding has evidence, weight, uncertainty and benign explanations; analysts mark them relevant, benign or unresolved.
- **Static attachment analysis** — magic-byte identification, extension mismatch, double extensions, strings and URLs, ZIP/gzip contents (depth, entry, size, ratio limits, no extraction to disk), Office macros (oletools, never run), external templates, PDF action keywords, PE headers. Runs in a separate process with time and memory limits; incomplete results are marked *partial*, never clean.
- **Sandbox** — CAPEv2 adapter (live) and a clearly labelled demo adapter. Explicit analyst submission only, job states (queued → running → completed / failed / timed out / cancelled / reset failed), post-run reset verification, automatic quarantine of a guest that can't be verified clean.
- **Cases and reports** — notes classified as facts, interpretations and questions; evidence and finding selection; full history; report revisions where generated observations and analyst writing are separate; reviewed revisions are frozen; NEMSEC-branded PDF with a DRAFT watermark until reviewed.

## Quick start (Windows)

Requirements: Windows 10/11, Python 3.11+ (with the `py` launcher), Node.js 20.9+.

```powershell
git clone <this repo> nemsec-phishbench
cd nemsec-phishbench
powershell -ExecutionPolicy Bypass -File scripts\setup.ps1
powershell -ExecutionPolicy Bypass -File scripts\start.ps1 -Demo
```

Open http://127.0.0.1:3000 and press **Load synthetic demo case**. Full instructions: [docs/windows-setup.md](docs/windows-setup.md). Live sandbox: [docs/sandbox-deployment.md](docs/sandbox-deployment.md).

To use your NEMSEC logo, save it as `branding/nemsec-logo.png` (square PNG, transparent background) and re-run setup — it appears in the UI rail and the PDF header. Until then a letter mark is shown.

## Documentation

| Document | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Components, evidence flow, data model, trust boundaries, folder structure |
| [docs/rules.md](docs/rules.md) | Every rule, what it looks at, weight, and benign explanations |
| [docs/static-analysis.md](docs/static-analysis.md) | Supported formats and worker limits |
| [docs/sandbox-deployment.md](docs/sandbox-deployment.md) | CAPEv2 host + Windows guest, isolation checklist, adapter contract |
| [docs/windows-setup.md](docs/windows-setup.md) | Local setup, configuration, troubleshooting |
| [docs/limitations.md](docs/limitations.md) | Known limitations |
| [docs/portfolio-walkthrough.md](docs/portfolio-walkthrough.md) | A 10-minute demo script |
| [docs/verification-status.md](docs/verification-status.md) | What was actually run, what used mocks, what to verify on your machine |
| [samples/EXPECTED_FINDINGS.md](samples/EXPECTED_FINDINGS.md) | The synthetic dataset and what each sample should produce |

## Tests

```powershell
powershell -ExecutionPolicy Bypass -File scripts\test.ps1            # 70 backend tests
powershell -ExecutionPolicy Bypass -File scripts\test.ps1 -Browser   # + browser walkthrough (start.ps1 -Demo must be running)
```

## Stack

Next.js 16 + TypeScript (UI) · FastAPI on Python 3.11+ (API) · SQLite · local evidence store · SQLite-backed job queue with a separate worker process · ReportLab (PDF) · CAPEv2 (sandbox engine, separate Linux/KVM host).
