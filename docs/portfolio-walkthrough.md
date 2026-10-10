# Portfolio walkthrough (about 10 minutes)

Setup: `scripts\start.ps1 -Demo`, browser at http://127.0.0.1:3000. Say up front that the sandbox is in **demo mode** and the UI labels every synthetic result; if you have a CAPE host, run without `-Demo` and use the harmless `.exe`.

**1. The idea (30 s).** Open the dashboard. Point at the provenance legend: observed, rule inference, analyst, not established. "The tool never gives a score. It shows evidence, explains indicators, and leaves the verdict to the analyst."

**2. Load the dataset (30 s).** *Load synthetic demo case.* Nine synthetic emails, findings counted and unreviewed.

**3. Safe preview (1.5 min).** Open *Action required: your mailbox will be suspended*.
- The preview: tracking pixel shown as "[image blocked]", every link shows its real destination and can't be clicked, the Cyrillic look-alike host is revealed as punycode.
- "Removed from this message: 7 remote resources, 3 script indicators, 1 form…"
- Mention the three layers: nh3 sanitiser, `default-src 'none'; sandbox` CSP, `<iframe sandbox="">`.

**4. Headers and trust (1 min).** *Headers & evidence* tab on the CFO email: the trust-boundary note, authentication results as "Reported claim, not verified", raw vs decoded subject, Received path. Press *Re-check stored bytes*: "A hash proves the stored copy hasn't changed — not that the email is genuine."

**5. Links (45 s).** *Links* tab on the suspension email: visible text vs actual destination, IP host, `user@host` trick, `javascript:` link — all read as text, none visited.

**6. Findings and review (1.5 min).** Case → *Findings*. Expand *Display name resembles a reference identity*: exact evidence, weight, uncertainty, "could be benign if…". Mark it relevant with a comment. Mark *Return-Path domain differs* benign ("bulk mail providers do this").

**7. Attachments (1.5 min).**
- `Invoice_INV-2026-1043.pdf`: identified as a Windows PE by magic bytes; extension mismatch; imports; "timestamp as written can be faked".
- `Statement_October.zip`: **Encrypted — not inspected** banner: "incomplete analysis is never shown as clean."
- `Shipping_Label.zip`: `.pdf.bat` double extension, `../../` traversal entry, nested ZIP — listed in memory, nothing extracted.

**8. Sandbox (1.5 min).** On `nemsec_sandbox_demo.exe`: the execute button stays disabled until you type your name and tick the explicit confirmation. Submit, open the run: queued → running → completed → reset check. Read the banner: "Execution finished … not a verdict that the file is safe." Show *What this run could not show*. Optionally submit `nemsec_demo-reset-fail.bat` from *Demo-mode failure paths* to show **Reset failed** and the guest quarantine (new submissions are refused), then release the guest with a note on the Sandbox page.

**9. Notes and report (2 min).** Notes tab: add a confirmed fact and an unanswered question. *Report* → *Create draft report*: generated sections (scope with hashes, findings with review status and evidence refs, sandbox runs with DEMO flag, *Could not be established*) vs analyst sections. Fill summary, assessment, rationale; save; export the draft PDF (watermarked DRAFT). Mark reviewed, export again, show the frozen revision and *Start revision 2*.

**10. Engineering close (30 s).** Static analysis in a resource-limited child process with checkpoints; SQLite job queue; CAPEv2 adapter behind a documented interface; 70 automated tests plus a Playwright walkthrough; `docs/verification-status.md` states exactly what was verified live versus with mocks.
