"""Evidence storage.

* Bytes are written exactly as received, under a generated name
  (``<data>/evidence/<ab>/<random>.bin``). The user-supplied filename is kept
  only as metadata and is never used to build a path.
* SHA-256 is computed on the bytes we write and re-checked on demand.
* A matching hash shows the preserved bytes have not changed since import.
  It says nothing about whether the email is authentic.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import stat
from pathlib import Path

from .config import get_settings


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _root(kind: str) -> Path:
    s = get_settings()
    return {"evidence": s.evidence_dir, "artifacts": s.artifacts_dir, "reports": s.reports_dir}[kind]


def store_bytes(data: bytes, kind: str = "evidence", suffix: str = ".bin") -> str:
    """Write bytes under a generated name. Returns the relative stored name."""
    if suffix not in {".bin", ".pdf", ".png", ".json"}:
        suffix = ".bin"
    token = secrets.token_hex(16)
    rel = f"{token[:2]}/{token}{suffix}"
    path = _root(kind) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    # O_EXCL guarantees we never overwrite existing evidence.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    try:
        os.chmod(path, stat.S_IRUSR)  # read-only after write (best effort on Windows)
    except OSError:
        pass
    return rel


def resolve(stored_name: str, kind: str = "evidence") -> Path:
    """Map a stored name back to a path, refusing anything outside the store."""
    root = _root(kind).resolve()
    path = (root / stored_name).resolve()
    if root not in path.parents:
        raise ValueError("stored name escapes evidence root")
    return path


def read_bytes(stored_name: str, kind: str = "evidence") -> bytes:
    return resolve(stored_name, kind).read_bytes()


def verify(stored_name: str, expected_sha256: str, kind: str = "evidence") -> dict:
    path = resolve(stored_name, kind)
    if not path.exists():
        return {"ok": False, "reason": "file missing from evidence store", "expected": expected_sha256, "actual": None}
    actual = sha256_file(path)
    return {
        "ok": actual == expected_sha256,
        "expected": expected_sha256,
        "actual": actual,
        "meaning": "Matching hashes show the preserved bytes are unchanged since import. "
                   "They do not show the email is authentic or unmodified before it reached you.",
    }
