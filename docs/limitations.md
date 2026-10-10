# Known limitations

## Email authenticity
- SPF, DKIM and DMARC are **not** evaluated. Authentication-Results and Received headers are displayed as claims; anyone could have written them. Historical DNS state can't be reconstructed, so re-checking later would not be meaningful either.
- DKIM signatures are listed, not cryptographically verified.
- Only `.eml` (RFC 5322) is imported. Outlook `.msg` files must be saved as `.eml` first.

## Parsing and preview
- Python's `email` package (compat32 policy) is lenient; some malformed structures are interpreted the way Python reads them, which may differ from Outlook or Gmail. Defects are reported as warnings.
- The preview drops `<style>` blocks and remote CSS, so styled emails look plainer than in a mail client. That is deliberate.
- Inline `cid:` images are not shown in the preview (they are preserved as attachments).

## Rules
- Registrable-domain comparison uses a small built-in suffix list, not the full Public Suffix List, to stay offline. Unusual multi-label suffixes may be compared wrongly.
- Urgency/sensitive-request matching is English keyword lists; it doesn't understand negation, quotes or other languages.
- Impersonation checks only work against reference identities you add.
- Confusable-character detection flags mixed or confusable scripts; it is not a full Unicode TR39 skeleton comparison.

## Static analysis
- Supported deep formats are listed in [static-analysis.md](static-analysis.md). RAR, 7z, tar, CAB, ISO, LNK, MSI, ELF and Mach-O are identified only.
- PDF analysis counts keywords in raw bytes; content inside compressed object streams or encrypted objects is invisible (the report says so).
- Macro detection depends on oletools; heavily obfuscated or malformed VBA may evade keyword scans. No sample with real VBA ships with the dataset (generating a valid `vbaProject.bin` needs Office), so the macro path is covered by oletools' own behaviour rather than a bundled sample.
- Authenticode signatures are not validated.
- On Windows, memory limits are enforced by polling (every 50 ms), so a parser can briefly exceed the limit before being killed.

## Sandbox
- The CAPEv2 adapter has been tested against a mock of CAPE's API built from its source code, not a live CAPE host. See [verification-status.md](verification-status.md).
- Reset verification trusts CAPE/libvirt state reporting; it does not hash the VM disk.
- Partial results from cancelled or timed-out CAPE tasks are not retrieved.
- Only one guest VM is managed (multi-guest scheduling isn't implemented).
- A quiet run is never evidence of safety: documents need the right application, phishing pages need a human, and malware may detect the VM or wait.

## Platform
- Single analyst, local only; no authentication or multi-user permissions.
- SQLite job queue is not intended for many parallel workers.
- No AI features (by design for the initial version).
