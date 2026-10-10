"""Sandbox adapter interface.

Any execution engine is integrated by implementing ``SandboxAdapter``. The
workbench itself never executes attachments; it hands bytes to an engine that
runs them inside a disposable VM on a separate, isolated host.

Normalised observation schema (what ``results()`` must return)::

    {
      "source": "cape" | "demo",
      "is_demo": bool,
      "duration_s": float | None, "started": str | None, "ended": str | None,
      "analysis_package": str | None,
      "processes": [{"pid", "ppid", "name", "path", "command_line"}],
      "files": {"created": [...], "modified": [...], "deleted": [...]},
      "registry": {"set": [...], "deleted": [...]},
      "persistence": [{"type", "detail"}],
      "network": {"dns": [{"query", "answers"}], "connections": [{"proto", "dst", "port"}], "http": [{"method", "url"}]},
      "events": [{"type", "detail"}],
      "engine_signatures": [{"name", "description", "severity"}],   # the engine's inferences, not observations
      "errors": [str],
    }
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class SandboxError(Exception):
    pass


@dataclass
class Health:
    ok: bool
    detail: str
    worker: dict[str, Any] | None = None


@dataclass
class ExternalStatus:
    state: str  # pending | running | finished | failed | unknown
    detail: str = ""


@dataclass
class ResetCheck:
    state: str  # verified | pending | failed
    detail: str


@dataclass
class Artifact:
    kind: str
    label: str
    data: bytes
    suffix: str = ".bin"


@dataclass
class Capabilities:
    engine: str
    is_demo: bool
    guest_platform: str
    supported_types: set[str]
    observations: list[str]
    network_mode: str
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = self.__dict__.copy()
        d["supported_types"] = sorted(self.supported_types)
        return d


class SandboxAdapter(Protocol):
    name: str
    is_demo: bool

    def capabilities(self) -> Capabilities: ...
    def health(self, worker: str) -> Health: ...
    def submit(self, data: bytes, filename: str, timeout_s: int, worker: str) -> str: ...
    def status(self, external_id: str) -> ExternalStatus: ...
    def cancel(self, external_id: str) -> bool: ...
    def results(self, external_id: str) -> dict[str, Any]: ...
    def artifacts(self, external_id: str) -> list[Artifact]: ...
    def verify_reset(self, worker: str, external_id: str) -> ResetCheck: ...


def empty_observations(source: str, is_demo: bool) -> dict[str, Any]:
    return {
        "source": source, "is_demo": is_demo, "duration_s": None, "started": None, "ended": None,
        "analysis_package": None, "processes": [], "files": {"created": [], "modified": [], "deleted": []},
        "registry": {"set": [], "deleted": []}, "persistence": [],
        "network": {"dns": [], "connections": [], "http": []}, "events": [], "engine_signatures": [], "errors": [],
    }
