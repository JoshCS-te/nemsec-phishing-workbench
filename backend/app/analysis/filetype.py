"""Magic-byte file type identification (no libmagic dependency).

Supported identification set is documented in docs/static-analysis.md.
Identification answers "what does the content look like", independent of the
filename. The extension is compared separately.
"""
from __future__ import annotations

import io
import re
import zipfile
from typing import Any

# type -> (label, family)
TYPES: dict[str, tuple[str, str]] = {
    "pe": ("Windows PE executable/library", "executable"),
    "elf": ("ELF executable (Linux/Unix)", "executable"),
    "macho": ("Mach-O executable (macOS)", "executable"),
    "msi": ("Windows Installer package (OLE)", "executable"),
    "lnk": ("Windows shortcut (.lnk)", "script"),
    "script_text": ("Script source (text)", "script"),
    "zip": ("ZIP archive", "archive"),
    "gzip": ("gzip compressed data", "archive"),
    "rar": ("RAR archive", "archive"),
    "7z": ("7-Zip archive", "archive"),
    "tar": ("tar archive", "archive"),
    "cab": ("Microsoft Cabinet archive", "archive"),
    "iso": ("ISO 9660 disk image", "archive"),
    "docx": ("Word document (OOXML)", "document"),
    "docm": ("Word macro-enabled document (OOXML)", "document"),
    "xlsx": ("Excel workbook (OOXML)", "document"),
    "xlsm": ("Excel macro-enabled workbook (OOXML)", "document"),
    "pptx": ("PowerPoint presentation (OOXML)", "document"),
    "pptm": ("PowerPoint macro-enabled presentation (OOXML)", "document"),
    "ooxml_other": ("Office Open XML package", "document"),
    "ole_encrypted": ("Encrypted Office document (OLE container)", "document"),
    "ole": ("OLE2 compound file (legacy Office: doc/xls/ppt)", "document"),
    "pdf": ("PDF document", "document"),
    "rtf": ("Rich Text Format document", "document"),
    "html": ("HTML document", "markup"),
    "svg": ("SVG image (XML; may contain script)", "markup"),
    "eml": ("Email message (RFC 5322)", "email"),
    "png": ("PNG image", "image"),
    "jpeg": ("JPEG image", "image"),
    "gif": ("GIF image", "image"),
    "bmp": ("BMP image", "image"),
    "text": ("Plain text", "text"),
    "empty": ("Empty file", "unknown"),
    "unknown": ("Unrecognised binary data", "unknown"),
}

# What each extension is expected to contain.
EXTENSION_EXPECT: dict[str, set[str]] = {
    "exe": {"pe"}, "dll": {"pe"}, "scr": {"pe"}, "com": {"pe"}, "cpl": {"pe"}, "sys": {"pe"},
    "msi": {"msi", "ole"},
    "lnk": {"lnk"},
    "zip": {"zip"}, "gz": {"gzip"}, "tgz": {"gzip"}, "rar": {"rar"}, "7z": {"7z"}, "tar": {"tar"}, "cab": {"cab"},
    "iso": {"iso"}, "img": {"iso", "unknown"},
    "docx": {"docx"}, "docm": {"docm"}, "xlsx": {"xlsx"}, "xlsm": {"xlsm"}, "pptx": {"pptx"}, "pptm": {"pptm"},
    "doc": {"ole", "ole_encrypted", "rtf"}, "xls": {"ole", "ole_encrypted"}, "ppt": {"ole", "ole_encrypted"},
    "pdf": {"pdf"}, "rtf": {"rtf"},
    "htm": {"html"}, "html": {"html"}, "hta": {"html", "script_text"}, "svg": {"svg"},
    "eml": {"eml", "text"}, "msg": {"ole"},
    "png": {"png"}, "jpg": {"jpeg"}, "jpeg": {"jpeg"}, "gif": {"gif"}, "bmp": {"bmp"},
    "txt": {"text"}, "csv": {"text"}, "log": {"text"},
    "js": {"script_text", "text"}, "jse": {"script_text", "text", "unknown"}, "vbs": {"script_text", "text"},
    "vbe": {"script_text", "text", "unknown"}, "wsf": {"script_text", "text"}, "ps1": {"script_text", "text"},
    "bat": {"script_text", "text"}, "cmd": {"script_text", "text"}, "sh": {"script_text", "text"},
    "py": {"script_text", "text"},
}
# Encrypted or macro-enabled variants that are legitimately stored inside another container type.
ENCRYPTED_OOXML_EXTS = {"docx", "docm", "xlsx", "xlsm", "pptx", "pptm"}
SCRIPT_EXTENSIONS = {"js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1", "psm1", "bat", "cmd", "hta", "sh", "py", "lnk",
                     "scr", "pif", "com", "cpl", "msi", "jar", "reg", "vb", "sct", "iqy", "slk", "url", "appref-ms", "chm"}
EXECUTABLE_EXTENSIONS = {"exe", "dll", "scr", "com", "cpl", "sys", "msi", "pif"}

SCRIPT_CONTENT_RE = re.compile(
    rb"(?i)(WScript\.|CreateObject\s*\(|ActiveXObject|powershell|Invoke-Expression|IEX\s*\(|"
    rb"FromBase64String|cmd(\.exe)?\s*/c|^#!\s*/|<\s*job\b|Set-ExecutionPolicy|eval\s*\(|function\s+\w+\s*\(|"
    rb"^\s*@?echo\s+off\b|^\s*rem\s|^\s*exit\s+/b\b|%TEMP%|%APPDATA%|^\s*set\s+\w+=)",
    re.M,
)


def extension_of(filename: str | None) -> str | None:
    if not filename or "." not in filename:
        return None
    ext = filename.rsplit(".", 1)[1].strip().lower()
    return ext or None


def _ooxml_kind(data: bytes) -> str | None:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        names = set(zf.namelist())
    except Exception:
        return None
    if "[Content_Types].xml" not in names:
        return None
    try:
        ct = zf.read("[Content_Types].xml")[:200_000].decode("utf-8", "replace")
    except Exception:
        ct = ""
    has_vba = any(n.lower().endswith("vbaproject.bin") for n in names)
    if any(n.startswith("word/") for n in names):
        return "docm" if has_vba or "macroEnabled" in ct else "docx"
    if any(n.startswith("xl/") for n in names):
        return "xlsm" if has_vba or "macroEnabled" in ct else "xlsx"
    if any(n.startswith("ppt/") for n in names):
        return "pptm" if has_vba or "macroEnabled" in ct else "pptx"
    return "ooxml_other"


def _ole_kind(data: bytes) -> str:
    # Avoid full OLE parsing here; look for well-known stream names (UTF-16LE).
    window = data[:4 * 1024 * 1024]
    if "EncryptionInfo".encode("utf-16-le") in window or "EncryptedPackage".encode("utf-16-le") in window:
        return "ole_encrypted"
    if b"\x84\x10\x0c\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46" in window:  # MSI CLSID
        return "msi"
    return "ole"


def _looks_text(sample: bytes) -> bool:
    if not sample:
        return False
    if sample.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff")):
        return True
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13) or b >= 0x80)
    return printable / len(sample) > 0.95


def detect(data: bytes, filename: str | None = None) -> dict[str, Any]:
    head = data[:4096]
    t = "unknown"
    if not data:
        t = "empty"
    elif head.startswith(b"MZ"):
        t = "pe"
    elif head.startswith(b"\x7fELF"):
        t = "elf"
    elif head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        t = "macho"
    elif head.startswith(b"L\x00\x00\x00\x01\x14\x02\x00"):
        t = "lnk"
    elif head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        t = _ooxml_kind(data) or "zip"
    elif head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        t = _ole_kind(data)
    elif head.startswith(b"%PDF-") or b"%PDF-" in head[:1024]:
        t = "pdf"
    elif head.startswith(b"{\\rt"):
        t = "rtf"
    elif head.startswith(b"\x1f\x8b"):
        t = "gzip"
    elif head.startswith(b"Rar!\x1a\x07"):
        t = "rar"
    elif head.startswith(b"7z\xbc\xaf\x27\x1c"):
        t = "7z"
    elif head.startswith(b"MSCF"):
        t = "cab"
    elif len(data) > 262 and data[257:262] == b"ustar":
        t = "tar"
    elif len(data) > 0x8006 and data[0x8001:0x8006] == b"CD001":
        t = "iso"
    elif head.startswith(b"\x89PNG\r\n\x1a\n"):
        t = "png"
    elif head.startswith(b"\xff\xd8\xff"):
        t = "jpeg"
    elif head.startswith((b"GIF87a", b"GIF89a")):
        t = "gif"
    elif head.startswith(b"BM") and len(data) > 14:
        t = "bmp"
    elif _looks_text(head):
        low = head.lower()
        if re.search(rb"<\s*svg\b", low):
            t = "svg"
        elif re.search(rb"<\s*(!doctype\s+html|html|head|body|script|hta:application)\b", low):
            t = "html"
        elif re.search(rb"(?m)^(received|from|return-path|message-id|mime-version|subject|date):", low) and b"\n\n" in data[:65536].replace(b"\r\n", b"\n"):
            t = "eml"
        elif SCRIPT_CONTENT_RE.search(data[:65536]):
            t = "script_text"
        else:
            t = "text"
    label, family = TYPES[t]
    return {"type": t, "label": label, "family": family}


def extension_assessment(filename: str | None, detected_type: str) -> dict[str, Any]:
    ext = extension_of(filename)
    out: dict[str, Any] = {"extension": ext, "expected_types": None, "mismatch": False, "notes": []}
    if filename:
        parts = filename.lower().split(".")
        if len(parts) >= 3 and parts[-1] in (SCRIPT_EXTENSIONS | EXECUTABLE_EXTENSIONS):
            out["notes"].append(f"Double extension: name ends '.{parts[-2]}.{parts[-1]}'. Windows hides known extensions by default, so this can display as '.{parts[-2]}'.")
        if re.search("[‪-‮⁦-⁩]", filename):
            out["notes"].append("Filename contains Unicode bidirectional control characters, which can make the displayed extension differ from the real one.")
        if re.search(r"\s{5,}\.", filename):
            out["notes"].append("Filename contains a long run of spaces before the extension, which can push the real extension out of view.")
    if ext is None:
        return out
    expected = EXTENSION_EXPECT.get(ext)
    if expected is None:
        out["notes"].append(f"Extension '.{ext}' is not in the comparison table; no mismatch check performed.")
        return out
    out["expected_types"] = sorted(expected)
    if detected_type == "ole_encrypted" and ext in ENCRYPTED_OOXML_EXTS:
        out["notes"].append("Encrypted Office files are stored in an OLE container even when the extension is OOXML; this is expected.")
        return out
    if detected_type not in expected:
        out["mismatch"] = True
    return out
