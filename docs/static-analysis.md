# Static attachment analysis

Static analysis reads attachment bytes. It never runs scripts or macros, never renders content, and never writes extracted content to disk.

## How it runs

`app/analysis/runner.py` starts `python -m app.analysis.static_worker` per attachment and streams the bytes on stdin.

| Limit | Default | Setting | Enforced by |
|---|---|---|---|
| Wall-clock time | 20 s | `PHB_STATIC_TIMEOUT_S` | parent kills child |
| Resident memory | 512 MB | `PHB_STATIC_MEMORY_MB` | parent polls with psutil (all OSes); child also sets `RLIMIT_AS` on Linux/macOS |
| Attachment size | 20 MB | `PHB_MAX_ATTACHMENT_BYTES` | checked before the child starts → status `too_large` |
| Archive nesting depth | 3 | `PHB_ARCHIVE_MAX_DEPTH` | analyser |
| Archive entries examined | 500 | `PHB_ARCHIVE_MAX_ENTRIES` | analyser |
| Total expanded bytes | 100 MB | `PHB_ARCHIVE_MAX_TOTAL_BYTES` | shared budget across nested archives |
| Compression ratio | 100 : 1 | `PHB_ARCHIVE_MAX_RATIO` | entry skipped, flagged as possible bomb |

The child prints a JSON checkpoint after each stage (`identify` → `strings` → `format`). If it is killed, the last checkpoint is kept, marked `partial`, and the first limitation says which stages finished. On Windows the child runs at below-normal priority with no console window. The child receives no sandbox credentials in its environment.

## Statuses

| Status | Meaning |
|---|---|
| `complete` | Every supported stage for this format finished. Still not a safety verdict. |
| `partial` | Something was skipped or stopped (limits hit, some entries encrypted, worker timed out, parser error). |
| `encrypted` | Content is encrypted (all archive entries, or an encrypted Office container). |
| `unsupported` | Identified, hashed and string-scanned only; no format parser. |
| `failed` | Analysis could not run or the format parser rejected the file. |
| `too_large` | Above the size limit; not analysed. |

The UI shows every status other than `complete` with an "Analysis is incomplete — this is not a clean result" banner, and the report lists them under *Could not be established*.

## Supported formats (initial set)

| Format | Identification | Deeper analysis |
|---|---|---|
| Windows PE (exe/dll/scr) | `MZ` | pefile: machine, DLL flag, timestamp (as written), sections + entropy, imports, signature blob presence (not validated) |
| ZIP | `PK\x03\x04` | entries, sizes, ratio, encryption flag, symlink and path-traversal flags, per-entry hash and identification, nested ZIP recursion, macro scan of nested Office files |
| gzip | `1f 8b` | bounded decompression, inner type and hash |
| OOXML (docx/docm/xlsx/xlsm/pptx/pptm) | ZIP + `[Content_Types].xml` + part names | oletools VBA scan, external relationships, embedded parts, core metadata |
| OLE2 (doc/xls/ppt/msg) | `D0 CF 11 E0` | oletools VBA scan, embedded object streams, summary metadata |
| Encrypted Office | OLE with `EncryptionInfo` / `EncryptedPackage` | status `encrypted` |
| RTF | `{\rt` | oletools VBA/OLE scan where possible |
| PDF | `%PDF-` | version, action/script/embedded keyword counts, `/URI` targets, encryption flag |
| Scripts (js, vbs, ps1, bat, cmd, hta, wsf, sh) | text + script markers | text excerpt, strings |
| HTML / SVG | text + tags | text excerpt, strings |
| Images (png/jpeg/gif/bmp) | magic | hashed and identified only |
| Text / eml | heuristics | strings |
| RAR, 7z, tar, CAB, ISO, Mach-O, ELF, MSI, LNK | magic | **unsupported** for deep analysis (identification, hash, strings only) |

All formats get SHA-256, size, ASCII + UTF-16LE strings (capped), "interesting" strings (commands, LOLBins, registry run keys, URLs) and URLs extracted from strings (analysed with the same URL rules, never visited).
