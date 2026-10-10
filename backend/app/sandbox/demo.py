"""DEMONSTRATION adapter — produces synthetic data, executes nothing.

Exists so the UI, job state machine and report pipeline can be shown and
tested without a sandbox host. Every observation it returns carries
``is_demo: True`` and the UI, API and PDF label it "DEMO — NOT A REAL SANDBOX
OBSERVATION". It is only active when PHB_SANDBOX_MODE=demo.

Filename triggers for demonstrating failure paths:
  * contains ``demo-fail``        -> engine reports failure
  * contains ``demo-reset-fail``  -> run finishes but reset cannot be verified
  * contains ``demo-hang``        -> never finishes (exercises the timeout)
"""
from __future__ import annotations

import hashlib
import time
from typing import Any

from .base import Artifact, Capabilities, ExternalStatus, Health, ResetCheck, empty_observations

DEMO_LABEL = "DEMO — synthetic data, not a real sandbox observation"
# 1x1 grey PNG used as a placeholder "screenshot"
_PLACEHOLDER_PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806000000"
    "1f15c4890000000d49444154789c6360606060000000050001a5f645400000000049454e44ae426082"
)


class DemoAdapter:
    name = "demo"
    is_demo = True

    def __init__(self, run_seconds: float = 4.0) -> None:
        self.run_seconds = run_seconds

    def capabilities(self) -> Capabilities:
        return Capabilities(engine="Demo (no execution)", is_demo=True, guest_platform="none",
                            supported_types={"pe", "script_text", "docm", "docx", "xlsm", "xlsx", "pdf", "zip", "html", "text", "ole", "lnk", "msi"},
                            observations=["synthetic only"], network_mode="none — nothing is executed",
                            notes=[DEMO_LABEL])

    def health(self, worker: str) -> Health:
        return Health(True, f"demo adapter ({DEMO_LABEL})", {"name": worker, "status": "poweroff", "locked": False})

    def submit(self, data: bytes, filename: str, timeout_s: int, worker: str) -> str:
        flags = ""
        low = filename.lower()
        if "demo-reset-fail" in low:
            flags = "R"
        elif "demo-fail" in low:
            flags = "F"
        elif "demo-hang" in low:
            flags = "H"
        digest = hashlib.sha256(data).hexdigest()[:12]
        return f"demo-{time.time():.0f}-{flags or 'N'}-{digest}-{worker}"

    @staticmethod
    def _parse(external_id: str) -> tuple[float, str, str, str]:
        _, ts, flags, digest, worker = external_id.split("-", 4)
        return float(ts), flags, digest, worker

    def status(self, external_id: str) -> ExternalStatus:
        ts, flags, _d, _w = self._parse(external_id)
        elapsed = time.time() - ts
        if flags == "H":
            return ExternalStatus("running", "demo: simulated hang")
        if elapsed < 1:
            return ExternalStatus("pending", "demo: queued")
        if elapsed < self.run_seconds:
            return ExternalStatus("running", "demo: running")
        if flags == "F":
            return ExternalStatus("failed", "demo: simulated engine failure")
        return ExternalStatus("finished", "demo: finished")

    def cancel(self, external_id: str) -> bool:
        return True

    def results(self, external_id: str) -> dict[str, Any]:
        _ts, _f, digest, _w = self._parse(external_id)
        obs = empty_observations("demo", True)
        obs.update({
            "demo_label": DEMO_LABEL, "duration_s": self.run_seconds, "analysis_package": "demo",
            "processes": [
                {"pid": 1000, "ppid": 500, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe", "command_line": "[DEMO]"},
                {"pid": 1100, "ppid": 1000, "name": "sample.exe", "path": "C:\\Users\\demo\\AppData\\Local\\Temp\\sample.exe", "command_line": "[DEMO] sample.exe"},
            ],
            "files": {"created": [f"C:\\Users\\demo\\AppData\\Local\\Temp\\NEMSEC_SANDBOX_DEMO_{digest}.txt"], "modified": [], "deleted": []},
            "events": [{"type": "note", "detail": DEMO_LABEL}],
        })
        return obs

    def artifacts(self, external_id: str) -> list[Artifact]:
        return [Artifact("screenshot", "DEMO placeholder (not a real screenshot)", _PLACEHOLDER_PNG, ".png")]

    def verify_reset(self, worker: str, external_id: str) -> ResetCheck:
        _ts, flags, _d, _w = self._parse(external_id)
        if flags == "R":
            return ResetCheck("failed", "demo: simulated reset failure (snapshot restore could not be confirmed)")
        return ResetCheck("verified", "demo: nothing was executed, nothing to reset")
