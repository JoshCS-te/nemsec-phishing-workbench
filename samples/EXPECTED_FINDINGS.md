# Synthetic demonstration dataset

Rebuild with `python samples/build_samples.py`. Every sample is synthetic: domains use the reserved `.example` / `.invalid` TLDs, IPs come from the documentation range `192.0.2.0/24`, account numbers are zeros, and attachments are harmless (see `harmless/README.md`). No link can reach a real site and no payload is malicious.

`backend/tests/test_findings.py` asserts each sample produces **exactly** the rule ids below (with the reference identity "Adaeze Okafor (CFO)" `<adaeze.okafor@contoso-demo.example>` added to the case, as the demo loader does).

| File | Scenario | Expected parse | Expected findings (rule ids) | Other expected observations |
|---|---|---|---|---|
| `01_legitimate.eml` | Ordinary colleague email, matching link text, auth claims all `pass` | parsed | *none* | Auth results shown as reported claims; one link whose text matches its destination |
| `02_reply_to_mismatch.eml` | "CFO" asks for an urgent wire transfer; Reply-To on an unrelated domain | parsed | `reply_to_differs` (medium), `return_path_differs`, `auth_results_claim_fail`, `urgent_sensitive_request`, `display_name_impersonation` (high) | Base64-encoded Subject decoded to "URGENT: vendor payment today", raw kept |
| `03_misleading_link.eml` | Mailbox-suspension lure with hostile HTML | parsed | `link_text_mismatch` ×3, `ip_destination`, `idn_confusable`, `url_userinfo`, `html_form`, `meta_refresh`, `dangerous_scheme`, `urgent_sensitive_request` | Preview removes script, form, iframe, tracking pixel, meta refresh; Cyrillic "о" host shown as punycode |
| `04_misleading_extension.eml` | Invoice attachment named `.pdf` that is a Windows executable | parsed | `extension_mismatch` (high), `executable_attachment`, `urgent_sensitive_request` | Static: PE x64, imports KERNEL32 + UCRT |
| `05_malformed.eml` | Two From headers, impossible date, unknown charsets, unterminated multipart, bad base64 | **partial** | `duplicate_from` | Warnings for duplicate From, unparseable Date (raw kept, no date assumed), unknown charset, missing Message-ID, base64 length, missing closing boundary |
| `06_encrypted_unsupported.eml` | Password-protected ZIP (password in body) + a 7z stub | parsed | `encrypted_content` | ZIP status **encrypted** (names visible, contents not); 7z status **unsupported** |
| `07_archive_with_script.eml` | Courier lure; ZIP with `Shipping_Label.pdf.bat`, a `../../` entry and a nested ZIP | parsed | `archive_executable`, `archive_unsafe_paths` | Nested ZIP opened at depth 2; nothing extracted to disk |
| `08_sandbox_verification.eml` | Harmless sandbox test programs, honestly named | parsed | `executable_attachment`, `script_attachment` | Use these for sandbox submissions |
| `09_demo_failure_paths.eml` | The harmless script under names that trigger demo-mode failure paths | parsed | `script_attachment` | In demo mode: `nemsec_demo-reset-fail.bat` → Reset failed + guest quarantined; `nemsec_demo-fail.bat` → engine failure |

## Sandbox expectations

| Attachment | Live CAPE expected behaviour | Demo mode |
|---|---|---|
| `nemsec_sandbox_demo.exe` | process `nemsec_sandbox_demo.exe`; file created `%TEMP%\NEMSEC_SANDBOX_DEMO_<pid>.txt`; no network; reset verified | synthetic process + file labelled DEMO |
| `nemsec_sandbox_demo.bat` | `cmd.exe` running the script; file `%TEMP%\NEMSEC_SANDBOX_DEMO_BAT.txt` | as above |
| any filename containing `demo-fail` / `demo-reset-fail` / `demo-hang` | — | demo engine failure / reset failure (guest quarantined) / timeout, to show those states |
