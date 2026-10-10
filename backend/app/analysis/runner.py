"""Run static analysis in a separate, limited process.

Limits enforced by the parent (work on Windows, Linux and macOS):
  * wall-clock timeout
  * resident memory ceiling (polled with psutil; the child is killed if exceeded)
  * input size ceiling (checked before the child starts)
On POSIX the child additionally sets RLIMIT_AS so allocations fail early.

If the child dies or is killed, the last checkpoint it printed is kept and
marked ``partial`` (or ``failed`` if nothing useful was produced). An
incomplete run is never reported as a clean ``complete`` result.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import psutil

from ..config import get_settings

BACKEND_ROOT = Path(__file__).resolve().parents[2]


def run_static(data: bytes, filename: str | None, declared_mime: str | None) -> dict[str, Any]:
    s = get_settings()
    if len(data) > s.max_attachment_bytes:
        return {
            "status": "too_large",
            "size_bytes": len(data),
            "limitations": [f"Attachment is {len(data)} bytes, above the static analysis limit of {s.max_attachment_bytes}. Not analysed."],
            "stages_completed": [],
            "never_executed": True,
        }
    params = {
        "filename": filename, "declared_mime": declared_mime,
        "max_depth": s.archive_max_depth, "max_entries": s.archive_max_entries,
        "max_total": s.archive_max_total_bytes, "max_ratio": s.archive_max_ratio,
        "max_strings": s.max_strings, "memory_mb": s.static_memory_mb,
    }
    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "BELOW_NORMAL_PRIORITY_CLASS", 0)
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("PHB_CAPE", "AWS_", "AZURE_"))}
    proc = subprocess.Popen(
        [sys.executable, "-m", "app.analysis.static_worker", json.dumps(params)],
        cwd=str(BACKEND_ROOT), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, creationflags=creationflags,
    )
    lines: list[str] = []
    err_chunks: list[bytes] = []

    def reader() -> None:
        assert proc.stdout is not None
        for raw in proc.stdout:
            lines.append(raw.decode("utf-8", "replace"))

    def err_reader() -> None:
        assert proc.stderr is not None
        err_chunks.append(proc.stderr.read()[-4000:])

    t_out = threading.Thread(target=reader, daemon=True)
    t_err = threading.Thread(target=err_reader, daemon=True)
    t_out.start()
    t_err.start()
    try:
        assert proc.stdin is not None
        proc.stdin.write(data)
        proc.stdin.close()
    except (BrokenPipeError, OSError):
        pass

    killed_reason: str | None = None
    deadline = time.monotonic() + s.static_timeout_s
    mem_limit = s.static_memory_mb * 1024 * 1024
    try:
        ps = psutil.Process(proc.pid)
    except psutil.Error:
        ps = None
    while proc.poll() is None:
        if time.monotonic() > deadline:
            killed_reason = f"timed out after {s.static_timeout_s}s"
            break
        if ps is not None:
            try:
                if ps.memory_info().rss > mem_limit:
                    killed_reason = f"exceeded memory limit of {s.static_memory_mb} MB"
                    break
            except psutil.Error:
                pass
        time.sleep(0.05)
    if killed_reason:
        proc.kill()
    proc.wait(timeout=10)
    t_out.join(timeout=5)
    t_err.join(timeout=5)

    last: dict[str, Any] | None = None
    for ln in lines:
        try:
            last = json.loads(ln)
        except json.JSONDecodeError:
            continue

    if killed_reason or proc.returncode != 0 or last is None or last.get("status") == "running":
        reason = killed_reason or (f"analysis process exited with code {proc.returncode}" if proc.returncode else "analysis did not finish")
        stderr_tail = (err_chunks[0] if err_chunks else b"").decode("utf-8", "replace").strip().splitlines()[-1:] or []
        if last is None:
            return {"status": "failed", "limitations": [f"Static analysis failed: {reason}."] + stderr_tail,
                    "stages_completed": [], "never_executed": True}
        last.setdefault("limitations", []).insert(0, f"Static analysis stopped early ({reason}). Only stages "
                                                     f"{', '.join(last.get('stages_completed', [])) or 'none'} completed; "
                                                     "results are incomplete and must not be read as clean.")
        last["status"] = "partial"
        return last
    return last
