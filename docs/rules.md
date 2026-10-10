# Rule catalogue

Rules live in `backend/app/analysis/findings.py`. Each produces findings with: name, category, explanation, exact supporting evidence, a **weight** (`low` / `medium` / `high` — how strongly the indicator *on its own* is associated with malicious mail), an uncertainty statement, and benign explanations. There is no aggregation into a score.

| Rule id | Category | Looks at | Weight | Common benign explanations |
|---|---|---|---|---|
| `reply_to_differs` | sender | Reply-To vs From | low (same org) / medium (other domain) | mailing lists, ticketing, delegated senders, marketing platforms |
| `return_path_differs` | sender | Return-Path domain vs From domain | low | bulk mail providers, bounce domains, forwarding |
| `display_name_has_other_address` | impersonation | an email address inside the display name that isn't the sending address | medium | "on behalf of" relays |
| `display_name_impersonation` | impersonation | display name ≈ an analyst-provided reference identity (difflib ≥ 0.85 or containment) from a different address | high (other domain) / medium (same domain) | same name, personal address, outdated reference list |
| `duplicate_from` / `duplicate_subject` / `duplicate_date` | structure | more than one of these headers | medium (From) / low | buggy mailers |
| `auth_results_claim_fail` | header_claims | Authentication-Results **claims** spf/dkim/dmarc fail/softfail/none/permerror | low | forwarding, lists, unauthenticated small senders; header itself may be forged |
| `link_text_mismatch` | links | visible text looks like a URL/domain whose registrable domain differs from the href's | medium | click tracking, link protection rewriting |
| `ip_destination` | links | IPv4/IPv6 host, including decimal/hex/octal obfuscation | medium | internal tools, devices |
| `idn_confusable` | links | IDN host with mixed scripts or confusable scripts (Cyrillic, Greek, …) | medium | legitimate non-Latin domains |
| `dangerous_scheme` | links | `javascript:`, `data:`, `vbscript:`, `file:`, `ms-*` | medium | editor placeholders |
| `url_userinfo` | links | `user[:pass]@host` in a URL (password never displayed) | medium | FTP/internal links |
| `malformed_url` | links | unparseable URL, bad port, no host | low | broken templates |
| `html_form` | links | `<form action=…>` in the body | high | embedded surveys (rare) |
| `meta_refresh` | links | `<meta http-equiv=refresh>` | medium | — |
| `urgent_sensitive_request` | content | urgency phrase **and** a credentials/payment/personal-data request (English keyword lists) | medium | genuine security notices, invoices, payroll |
| `extension_mismatch` | attachments | extension's expected types vs magic-byte identification | high (executable/script content) / medium | renamed exports |
| `filename_deception` | attachments | double extension ending in executable/script, bidi override characters, long space padding | high | — |
| `executable_attachment` | attachments | PE/ELF/Mach-O/MSI content or executable extension | high | software distribution |
| `script_attachment` | attachments | script content or script/shortcut extension (.js, .vbs, .ps1, .bat, .lnk, .hta, …) | high | admins exchanging scripts |
| `html_attachment` | attachments | .htm/.html/.svg attachments with HTML/SVG content | medium | receipts, exported reports |
| `office_macros` | attachments | VBA present (oletools static scan); AutoExec/Suspicious keywords raise weight | high (auto-run/suspicious) / medium | finance spreadsheets, old templates |
| `office_external_reference` | attachments | OOXML relationships with `TargetMode="External"` (e.g. remote templates) | medium | linked images and hyperlinks |
| `office_embedded_objects` | attachments | embedded OLE objects / packages | low | charts, embedded sheets |
| `pdf_active_content` | attachments | /JavaScript, /JS, /OpenAction, /AA, /Launch, /EmbeddedFile, /RichMedia, /SubmitForm | medium (JS/Launch/EmbeddedFile) / low | interactive forms |
| `archive_executable` | attachments | executable/script entries inside archives (any depth analysed) | high | zipped installers |
| `archive_unsafe_paths` | attachments | `..`, absolute, drive-letter, NUL names or symlink entries | medium | badly built archives |
| `encrypted_content` | coverage | password-protected archive entries or encrypted Office files | medium | legitimately protected documents |

Re-running rules (new reference identity, re-analysed attachment) keeps the analyst's review state for any finding whose rule, subject and evidence are unchanged.

To add a rule: return `_f(...)` from the relevant function in `findings.py`, add a sample or unit test, and update `samples/EXPECTED_FINDINGS.md` — `tests/test_findings.py::test_every_sample_produces_exactly_the_documented_findings` will fail until the documentation and behaviour agree.
