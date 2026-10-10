"""Static attachment analysis.

This module only *reads* bytes. It never writes extracted content to disk,
never follows archive paths, and never runs scripts or macros. VBA source is
decompressed by oletools and scanned as text for keywords.

It is designed to be run inside ``static_worker`` (a separate, resource
limited process). ``analyse`` calls ``checkpoint(result)`` after each stage so
the parent can keep partial results if the worker is killed.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import re
import zipfile
from typing import Any, Callable

from . import filetype
from .urls import TEXT_URL_RE, analyse_url

Checkpoint = Callable[[dict[str, Any]], None]

ASCII_STR_RE = re.compile(rb"[\x20-\x7e]{6,}")
UTF16_STR_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
INTERESTING_STR_RE = re.compile(
    r"(?i)(https?://|powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|"
    r"CreateObject|Shell|URLDownloadToFile|VirtualAlloc|WinExec|HKEY_|\\Run\\|schtasks|FromBase64String|"
    r"password|login|verify|invoice)"
)
PDF_KEYS = ["/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile", "/RichMedia", "/XFA",
            "/AcroForm", "/SubmitForm", "/URI", "/ObjStm", "/Encrypt"]


class Limits:
    def __init__(self, max_depth: int = 3, max_entries: int = 500, max_total: int = 100 * 1024 * 1024,
                 max_ratio: int = 100, max_strings: int = 300) -> None:
        self.max_depth = max_depth
        self.max_entries = max_entries
        self.max_total = max_total
        self.max_ratio = max_ratio
        self.max_strings = max_strings


def extract_strings(data: bytes, limit: int) -> dict[str, Any]:
    window = data[: 16 * 1024 * 1024]
    out: list[str] = []
    interesting: list[str] = []
    total = 0
    for rx, enc in ((ASCII_STR_RE, "ascii"), (UTF16_STR_RE, "utf-16-le")):
        for m in rx.finditer(window):
            total += 1
            s = m.group(0).decode(enc, "replace")
            if INTERESTING_STR_RE.search(s) and len(interesting) < limit:
                interesting.append(s[:400])
            if len(out) < limit:
                out.append(s[:200])
    return {
        "total_found": total,
        "sample": out,
        "interesting": interesting,
        "truncated": total > limit or len(data) > len(window),
        "scanned_bytes": len(window),
    }


def urls_from_strings(strings: list[str]) -> list[dict[str, Any]]:
    seen, res = set(), []
    for s in strings:
        for m in TEXT_URL_RE.finditer(s):
            url = m.group(1).rstrip(".,;:!?)'\"")
            if url not in seen and len(res) < 200:
                seen.add(url)
                res.append(analyse_url(url, "attachment").to_dict())
    return res


def _unsafe_path(name: str) -> str | None:
    n = name.replace("\\", "/")
    if n.startswith("/"):
        return "absolute path"
    if re.match(r"^[a-zA-Z]:", n):
        return "drive-letter path"
    if any(part == ".." for part in n.split("/")):
        return "parent-directory traversal ('..')"
    if "\x00" in n:
        return "NUL byte in name"
    return None


def analyse_zip(data: bytes, limits: Limits, depth: int, budget: dict[str, int]) -> dict[str, Any]:
    res: dict[str, Any] = {"entries": [], "limits_hit": [], "encrypted_entries": 0, "unsafe_entries": 0, "nested": []}
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except zipfile.BadZipFile as exc:
        res["error"] = f"Not a readable ZIP: {exc}"
        return res
    if len(infos) > limits.max_entries:
        res["limits_hit"].append(f"Archive lists {len(infos)} entries; only the first {limits.max_entries} were examined.")
        infos = infos[: limits.max_entries]
    for info in infos:
        entry: dict[str, Any] = {
            "name": info.filename,
            "compressed_size": info.compress_size,
            "uncompressed_size": info.file_size,
            "is_dir": info.is_dir(),
            "encrypted": bool(info.flag_bits & 0x1),
            "symlink": ((info.external_attr >> 16) & 0o170000) == 0o120000,
            "path_issue": _unsafe_path(info.filename),
            "detected": None,
            "sha256": None,
            "status": "listed",
        }
        if entry["path_issue"] or entry["symlink"]:
            res["unsafe_entries"] += 1
        if entry["encrypted"]:
            res["encrypted_entries"] += 1
            entry["status"] = "encrypted"
        ratio = (info.file_size / info.compress_size) if info.compress_size else (0 if info.file_size == 0 else float("inf"))
        entry["ratio"] = round(ratio, 1) if ratio != float("inf") else None
        res["entries"].append(entry)
        if info.is_dir() or entry["encrypted"] or entry["symlink"]:
            continue
        if ratio > limits.max_ratio:
            entry["status"] = "skipped_ratio"
            res["limits_hit"].append(f"'{info.filename}': compression ratio {entry['ratio']} exceeds {limits.max_ratio} (possible decompression bomb); not expanded.")
            continue
        if budget["remaining"] - info.file_size < 0:
            entry["status"] = "skipped_budget"
            res["limits_hit"].append(f"'{info.filename}': total expansion budget exhausted; not expanded.")
            continue
        try:
            with zf.open(info) as fh:
                content = fh.read(min(info.file_size, budget["remaining"]) + 1)
        except (RuntimeError, zipfile.BadZipFile, NotImplementedError, OSError, EOFError) as exc:
            entry["status"] = "read_error"
            entry["error"] = str(exc)[:200]
            continue
        if len(content) > info.file_size:
            entry["status"] = "size_lied"
            res["limits_hit"].append(f"'{info.filename}': expands beyond its declared size; stopped reading.")
            content = content[: info.file_size]
        budget["remaining"] -= len(content)
        entry["sha256"] = hashlib.sha256(content).hexdigest()
        det = filetype.detect(content, info.filename)
        entry["detected"] = det
        entry["extension"] = filetype.extension_assessment(info.filename, det["type"])
        entry["status"] = "examined"
        if det["type"] in ("zip",) and depth + 1 <= limits.max_depth:
            nested = analyse_zip(content, limits, depth + 1, budget)
            res["nested"].append({"name": info.filename, "depth": depth + 1, "result": nested})
        elif det["type"] in ("zip",):
            res["limits_hit"].append(f"'{info.filename}': nested archive beyond depth {limits.max_depth}; not opened.")
        elif det["family"] in ("document",) and det["type"] in ("docm", "xlsm", "pptm", "ole"):
            entry["macro_scan"] = analyse_office(content, info.filename).get("macros")
    return res


def analyse_office(data: bytes, filename: str | None) -> dict[str, Any]:
    out: dict[str, Any] = {"macros": None, "embedded_objects": [], "external_relationships": [], "metadata": {}, "notes": []}
    try:
        from oletools.olevba import VBA_Parser  # type: ignore
    except Exception as exc:  # pragma: no cover
        out["notes"].append(f"oletools unavailable: {exc}")
        return out
    try:
        vp = VBA_Parser(filename or "attachment", data=data)
        try:
            has = vp.detect_vba_macros()
            macros: dict[str, Any] = {"present": bool(has), "modules": [], "keywords": [], "note": "Macro code was decompressed and read as text. It was not executed."}
            if has:
                for (_f, stream, vba_name, code) in vp.extract_macros():
                    code_s = code if isinstance(code, str) else code.decode("latin-1", "replace")
                    macros["modules"].append({"stream": stream, "name": vba_name, "lines": code_s.count("\n") + 1,
                                              "excerpt": code_s[:1500]})
                for kw_type, keyword, description in vp.analyze_macros():
                    macros["keywords"].append({"type": kw_type, "keyword": str(keyword)[:200], "description": description})
            if getattr(vp, "detect_xlm_macros", None):
                try:
                    macros["xlm_macros"] = bool(vp.detect_xlm_macros())
                except Exception:
                    pass
            out["macros"] = macros
        finally:
            vp.close()
    except Exception as exc:
        out["notes"].append(f"Macro scan could not complete: {exc.__class__.__name__}: {str(exc)[:200]}")

    if data.startswith(b"PK"):
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            for n in zf.namelist():
                if "/embeddings/" in n or n.endswith(".bin") and "vbaProject" not in n:
                    out["embedded_objects"].append(n)
                if n.endswith(".rels"):
                    try:
                        rel = zf.read(n)[:500_000].decode("utf-8", "replace")
                    except Exception:
                        continue
                    for m in re.finditer(r"<Relationship\b[^>]*>", rel):
                        tag = m.group(0)
                        if 'TargetMode="External"' in tag:
                            target = re.search(r'Target="([^"]*)"', tag)
                            rtype = re.search(r'Type="([^"]*)"', tag)
                            out["external_relationships"].append({
                                "part": n, "target": target.group(1) if target else None,
                                "type": (rtype.group(1).rsplit("/", 1)[-1] if rtype else None),
                            })
            if "docProps/core.xml" in zf.namelist():
                core = zf.read("docProps/core.xml")[:200_000].decode("utf-8", "replace")
                for key in ("creator", "lastModifiedBy", "created", "modified", "title"):
                    m = re.search(rf"<[^>]*:{key}[^>]*>([^<]*)<", core)
                    if m:
                        out["metadata"][key] = m.group(1)[:200]
        except zipfile.BadZipFile:
            out["notes"].append("OOXML container could not be opened as ZIP.")
    elif data.startswith(b"\xd0\xcf\x11\xe0"):
        try:
            import olefile  # type: ignore

            ole = olefile.OleFileIO(data)
            try:
                for entry in ole.listdir():
                    path = "/".join(entry)
                    if any(k in path for k in ("Ole10Native", "ObjectPool", "Package", "\x01Ole")):
                        out["embedded_objects"].append(path)
                meta = ole.get_metadata()
                for key in ("author", "last_saved_by", "create_time", "last_saved_time", "title"):
                    v = getattr(meta, key, None)
                    if v:
                        out["metadata"][key] = (v.decode("latin-1", "replace") if isinstance(v, bytes) else str(v))[:200]
            finally:
                ole.close()
        except Exception as exc:
            out["notes"].append(f"OLE structure read failed: {exc.__class__.__name__}")
    return out


def analyse_pdf(data: bytes) -> dict[str, Any]:
    counts = {}
    for key in PDF_KEYS:
        # match the key not followed by a letter (so /JS does not count /JSON etc.)
        counts[key] = len(re.findall(re.escape(key.encode()) + rb"(?![A-Za-z])", data))
    uris = [m.decode("latin-1", "replace") for m in re.findall(rb"/URI\s*\(([^)]{1,2000})\)", data)][:100]
    version = re.match(rb"%PDF-(\d\.\d)", data[data.find(b"%PDF-"):][:16])
    return {
        "version": version.group(1).decode() if version else None,
        "keyword_counts": counts,
        "encrypted": counts["/Encrypt"] > 0,
        "uris": uris,
        "note": "Keyword counts come from the raw file. Compressed object streams (/ObjStm) can hide keywords, "
                "so a zero count is not proof of absence.",
    }


def analyse_pe(data: bytes) -> dict[str, Any]:
    try:
        import pefile  # type: ignore
    except Exception as exc:  # pragma: no cover
        return {"error": f"pefile unavailable: {exc}"}
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except Exception as exc:
        return {"error": f"Not a valid PE: {exc.__class__.__name__}: {str(exc)[:200]}"}
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        imports = []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])[:50]:
            imports.append({"dll": entry.dll.decode("latin-1", "replace"),
                            "functions": [i.name.decode("latin-1", "replace") for i in entry.imports[:40] if i.name]})
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        return {
            "machine": hex(pe.FILE_HEADER.Machine),
            "is_dll": pe.is_dll(),
            "compile_timestamp": pe.FILE_HEADER.TimeDateStamp,
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "sections": [{"name": s.Name.rstrip(b"\x00").decode("latin-1", "replace"), "raw_size": s.SizeOfRawData,
                          "virtual_size": s.Misc_VirtualSize, "entropy": round(s.get_entropy(), 2)} for s in pe.sections[:30]],
            "imports": imports,
            "has_authenticode_blob": sec_dir.Size > 0,
            "signature_note": "Presence of a signature blob is reported only; the signature was not validated.",
        }
    finally:
        pe.close()


def analyse(data: bytes, filename: str | None, declared_mime: str | None, limits: Limits,
            checkpoint: Checkpoint = lambda r: None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "running",
        "filename": filename,
        "declared_mime": declared_mime,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "stages_completed": [],
        "limitations": [],
        "never_executed": True,
    }
    det = filetype.detect(data, filename)
    result["detected"] = det
    result["extension"] = filetype.extension_assessment(filename, det["type"])
    result["stages_completed"].append("identify")
    checkpoint(result)

    strings = extract_strings(data, limits.max_strings)
    result["strings"] = strings
    result["urls"] = urls_from_strings(strings["sample"] + strings["interesting"])
    if strings["truncated"]:
        result["limitations"].append("String extraction was capped; not every string is listed.")
    result["stages_completed"].append("strings")
    checkpoint(result)

    t = det["type"]
    status = "complete"
    if t == "zip":
        budget = {"remaining": limits.max_total}
        z = analyse_zip(data, limits, 1, budget)
        result["archive"] = z
        if z.get("error"):
            status = "failed"
            result["limitations"].append(z["error"])
        elif z["entries"] and z["encrypted_entries"] == len([e for e in z["entries"] if not e["is_dir"]]):
            status = "encrypted"
            result["limitations"].append("All archive entries are encrypted. Names and sizes are visible; contents could not be examined.")
        elif z["encrypted_entries"]:
            status = "partial"
            result["limitations"].append(f"{z['encrypted_entries']} archive entries are encrypted and were not examined.")
        if z["limits_hit"] and status == "complete":
            status = "partial"
        result["limitations"].extend(z["limits_hit"])
        for nested in z["nested"]:
            if nested["result"].get("limits_hit") or nested["result"].get("encrypted_entries"):
                if status == "complete":
                    status = "partial"
                result["limitations"].extend(nested["result"].get("limits_hit", []))
    elif t == "gzip":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
                inner = gz.read(limits.max_total + 1)
            if len(inner) > limits.max_total:
                status = "partial"
                result["limitations"].append("gzip content exceeds expansion budget; only the first part was examined.")
                inner = inner[: limits.max_total]
            ratio = len(inner) / max(len(data), 1)
            idet = filetype.detect(inner)
            result["archive"] = {"gzip_inner": {"size": len(inner), "ratio": round(ratio, 1), "detected": idet,
                                                "sha256": hashlib.sha256(inner).hexdigest()}}
        except (OSError, EOFError, gzip.BadGzipFile) as exc:
            status = "failed"
            result["limitations"].append(f"gzip stream could not be decompressed: {exc}")
    elif t in ("docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "ooxml_other", "ole", "rtf"):
        result["office"] = analyse_office(data, filename)
        if result["office"]["notes"]:
            status = "partial"
            result["limitations"].extend(result["office"]["notes"])
    elif t == "ole_encrypted":
        status = "encrypted"
        result["limitations"].append("Office document is password-encrypted. Its contents (including any macros) could not be inspected.")
    elif t == "pdf":
        result["pdf"] = analyse_pdf(data)
        if result["pdf"]["encrypted"]:
            status = "partial"
            result["limitations"].append("PDF uses encryption; strings and keywords inside encrypted objects were not visible.")
        if result["pdf"]["keyword_counts"].get("/ObjStm"):
            result["limitations"].append(result["pdf"]["note"])
    elif t == "pe":
        result["pe"] = analyse_pe(data)
        if "error" in result["pe"]:
            status = "partial"
            result["limitations"].append(result["pe"]["error"])
    elif t in ("rar", "7z", "tar", "cab", "iso", "macho", "msi", "lnk", "unknown"):
        status = "unsupported"
        result["limitations"].append(f"Deep analysis of {det['label']} is not supported in this version. Only identification, hashing and strings were done.")
    elif t == "empty":
        status = "complete"
        result["limitations"].append("File is empty.")
    # text, html, svg, script_text, images, eml: identification + strings is the supported depth
    if t in ("png", "jpeg", "gif", "bmp"):
        result["limitations"].append("Images are identified and hashed only; image content is not interpreted.")
    if t in ("script_text", "html", "svg"):
        try:
            result["text_excerpt"] = data[:4000].decode("utf-8", "replace")
        except Exception:
            pass
    result["stages_completed"].append("format")
    result["status"] = status
    checkpoint(result)
    return result
