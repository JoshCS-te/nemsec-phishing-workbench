"""CAPEv2 adapter (https://github.com/kevoreilly/CAPEv2).

Endpoints used (CAPE REST API v2, web/apiv2/urls.py, checked 2026-10-05):
  GET  /apiv2/cuckoo/status/                      health
  GET  /apiv2/machines/view/<name>/               guest state for reset verification
  POST /apiv2/tasks/create/file/                  submit (multipart: file, machine, timeout, enforce_timeout, options)
  GET  /apiv2/tasks/status/<id>/                  task status string
  POST /apiv2/tasks/status/<id>/  status=finish   stop a running task (needs [user_stop] enabled in api.conf)
  GET  /apiv2/tasks/delete/<id>/                  remove a pending task
  GET  /apiv2/tasks/get/report/<id>/json/         JSON report
  GET  /apiv2/tasks/get/screenshot/<id>/          screenshots (zip)
Authentication: ``Authorization: Token <token>`` when token auth is enabled.

Reset model: CAPE reverts the guest to its configured snapshot when it
*starts* each task and powers it off afterwards. ``verify_reset`` checks that
after our task the guest is powered off, unlocked, and still configured with
the expected clean snapshot. It does not independently hash the VM disk;
see docs/sandbox-deployment.md.

THIS ADAPTER HAS ONLY BEEN EXERCISED AGAINST A MOCKED HTTP TRANSPORT IN THE
DEVELOPMENT ENVIRONMENT. Verify against your own CAPE host before relying on it.
"""
from __future__ import annotations

import io
import re
import zipfile
from typing import Any

import httpx

from .base import Artifact, Capabilities, ExternalStatus, Health, ResetCheck, SandboxError, empty_observations

PENDING = {"pending", "distributed"}
RUNNING = {"running", "completed", "recovered"}   # 'completed' = analysis done, processing/reporting still running
FINISHED = {"reported"}
FAILED = {"failed_analysis", "failed_processing", "failed_reporting", "banned"}
PERSISTENCE_KEY_RE = re.compile(r"(?i)\\(Run|RunOnce|RunServices|Winlogon|Image File Execution Options|Services\\[^\\]+\\ImagePath|Explorer\\Shell Folders|Policies\\Explorer\\Run)")
STARTUP_PATH_RE = re.compile(r"(?i)\\Start Menu\\Programs\\Startup\\|\\Windows\\Tasks\\|\\System32\\Tasks\\")


class CapeAdapter:
    name = "cape"
    is_demo = False

    def __init__(self, base_url: str, token: str = "", expected_snapshot: str | None = None,
                 transport: httpx.BaseTransport | None = None, timeout: float = 30.0) -> None:
        headers = {"Authorization": f"Token {token}"} if token else {}
        self._client = httpx.Client(base_url=base_url.rstrip("/"), headers=headers, timeout=timeout, transport=transport,
                                    follow_redirects=False, trust_env=False)
        self.expected_snapshot = expected_snapshot

    # ---- helpers -------------------------------------------------------
    def _json(self, method: str, path: str, **kw: Any) -> dict[str, Any]:
        try:
            r = self._client.request(method, path, **kw)
        except httpx.HTTPError as exc:
            raise SandboxError(f"CAPE unreachable: {exc.__class__.__name__}") from exc
        if r.status_code in (401, 403):
            raise SandboxError("CAPE rejected the API token (HTTP %d)" % r.status_code)
        if r.status_code >= 400:
            raise SandboxError(f"CAPE HTTP {r.status_code} for {path}")
        try:
            body = r.json()
        except ValueError as exc:
            raise SandboxError(f"CAPE returned non-JSON for {path}") from exc
        if isinstance(body, dict) and body.get("error") is True:
            raise SandboxError(f"CAPE error: {body.get('error_value', 'unknown')}")
        return body

    # ---- interface -------------------------------------------------------
    def capabilities(self) -> Capabilities:
        return Capabilities(
            engine="CAPEv2", is_demo=False, guest_platform="windows",
            supported_types={"pe", "msi", "lnk", "script_text", "html", "docx", "docm", "xlsx", "xlsm", "pptx", "pptm",
                             "ole", "rtf", "pdf", "zip", "text"},
            observations=["processes", "process tree", "files", "registry", "persistence (derived)", "dns", "network connections",
                          "http", "screenshots", "engine signatures", "errors"],
            network_mode="Configured on the CAPE host. Recommended: host-only network routed to INetSim (simulated services), no internet.",
            notes=["Documents only run their content if the matching application (e.g. Office, a PDF reader) is installed in the guest.",
                   "Content that waits for a user click, a reboot, a date, or a live command server may show nothing.",
                   "CAPE's 'human' auxiliary module clicks some dialogs; it is not a real user."],
        )

    def health(self, worker: str) -> Health:
        try:
            self._json("GET", "/apiv2/cuckoo/status/")
            m = self._json("GET", f"/apiv2/machines/view/{worker}/").get("data") or {}
        except SandboxError as exc:
            return Health(False, str(exc))
        if not m:
            return Health(False, f"CAPE has no machine named '{worker}'")
        if self.expected_snapshot and m.get("snapshot") != self.expected_snapshot:
            return Health(False, f"Guest '{worker}' snapshot is '{m.get('snapshot')}', expected '{self.expected_snapshot}'", m)
        return Health(True, f"CAPE reachable; guest '{worker}' status={m.get('status')} locked={m.get('locked')}", m)

    def submit(self, data: bytes, filename: str, timeout_s: int, worker: str) -> str:
        files = {"file": (filename, data, "application/octet-stream")}
        form = {"machine": worker, "timeout": str(timeout_s), "enforce_timeout": "1", "priority": "1"}
        body = self._json("POST", "/apiv2/tasks/create/file/", files=files, data=form)
        ids = (body.get("data") or {}).get("task_ids") or []
        if not ids:
            raise SandboxError(f"CAPE did not return a task id: {body.get('errors') or body}")
        return str(ids[0])

    def status(self, external_id: str) -> ExternalStatus:
        body = self._json("GET", f"/apiv2/tasks/status/{int(external_id)}/")
        st = str(body.get("data") or "").lower()
        if st in PENDING:
            return ExternalStatus("pending", st)
        if st in RUNNING:
            return ExternalStatus("running", st)
        if st in FINISHED:
            return ExternalStatus("finished", st)
        if st in FAILED:
            return ExternalStatus("failed", st)
        return ExternalStatus("unknown", st or "empty status")

    def cancel(self, external_id: str) -> bool:
        st = self.status(external_id)
        try:
            if st.state == "pending":
                self._json("GET", f"/apiv2/tasks/delete/{int(external_id)}/")
                return True
            if st.state == "running":
                self._json("POST", f"/apiv2/tasks/status/{int(external_id)}/", data={"status": "finish"})
                return True
        except SandboxError:
            return False
        return False

    def results(self, external_id: str) -> dict[str, Any]:
        rep = self._json("GET", f"/apiv2/tasks/get/report/{int(external_id)}/json/")
        return normalise_cape_report(rep)

    def artifacts(self, external_id: str) -> list[Artifact]:
        out: list[Artifact] = []
        try:
            r = self._client.get(f"/apiv2/tasks/get/screenshot/{int(external_id)}/")
        except httpx.HTTPError:
            return out
        if r.status_code != 200 or not r.content.startswith(b"PK"):
            return out
        try:
            zf = zipfile.ZipFile(io.BytesIO(r.content))
        except zipfile.BadZipFile:
            return out
        for info in zf.infolist()[:30]:
            if info.is_dir() or info.file_size > 5 * 1024 * 1024:
                continue
            with zf.open(info) as fh:
                data = fh.read(5 * 1024 * 1024)
            if data.startswith(b"\xff\xd8\xff") or data.startswith(b"\x89PNG"):
                out.append(Artifact("screenshot", info.filename.rsplit("/", 1)[-1], data, ".bin"))
        return out

    def verify_reset(self, worker: str, external_id: str) -> ResetCheck:
        try:
            m = self._json("GET", f"/apiv2/machines/view/{worker}/").get("data") or {}
        except SandboxError as exc:
            return ResetCheck("pending", f"could not query guest state: {exc}")
        status = str(m.get("status") or "").lower()
        if self.expected_snapshot and m.get("snapshot") != self.expected_snapshot:
            return ResetCheck("failed", f"guest snapshot changed to '{m.get('snapshot')}' (expected '{self.expected_snapshot}')")
        if status in ("poweroff", "saved") and not m.get("locked"):
            return ResetCheck("verified", f"guest '{worker}' powered off and unlocked; CAPE restores snapshot "
                                          f"'{m.get('snapshot') or '(machinery default)'}' before the next task")
        if status in ("running", "starting", "stopping", "reverting") or m.get("locked"):
            return ResetCheck("pending", f"guest status={status or 'unknown'} locked={m.get('locked')}")
        return ResetCheck("failed", f"guest in unexpected state '{status or 'unknown'}'")


def _as_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def normalise_cape_report(rep: dict[str, Any]) -> dict[str, Any]:
    obs = empty_observations("cape", False)
    info = rep.get("info") or {}
    obs["duration_s"] = info.get("duration")
    obs["started"] = info.get("started")
    obs["ended"] = info.get("ended")
    obs["analysis_package"] = info.get("package")
    behavior = rep.get("behavior") or {}
    for p in _as_list(behavior.get("processes"))[:500]:
        env = p.get("environ") or {}
        obs["processes"].append({
            "pid": p.get("process_id"), "ppid": p.get("parent_id"), "name": p.get("process_name"),
            "path": p.get("module_path"), "command_line": env.get("CommandLine") if isinstance(env, dict) else None,
        })
    summary = behavior.get("summary") or {}
    obs["files"]["created"] = [str(x) for x in _as_list(summary.get("write_files"))[:500]]
    obs["files"]["modified"] = [str(x) for x in _as_list(summary.get("files"))[:500] if x not in summary.get("write_files", [])][:200]
    obs["files"]["deleted"] = [str(x) for x in _as_list(summary.get("delete_files"))[:500]]
    obs["registry"]["set"] = [str(x) for x in _as_list(summary.get("write_keys"))[:500]]
    obs["registry"]["deleted"] = [str(x) for x in _as_list(summary.get("delete_keys"))[:500]]
    for k in obs["registry"]["set"]:
        if PERSISTENCE_KEY_RE.search(k):
            obs["persistence"].append({"type": "registry autorun/service key written", "detail": k})
    for f in obs["files"]["created"]:
        if STARTUP_PATH_RE.search(f):
            obs["persistence"].append({"type": "file written to startup/task location", "detail": f})
    for s in _as_list(summary.get("created_services")):
        obs["persistence"].append({"type": "service created", "detail": str(s)})
    for c in _as_list(summary.get("executed_commands"))[:200]:
        obs["events"].append({"type": "command executed", "detail": str(c)})
        if re.search(r"(?i)\bschtasks\b.*\/create", str(c)):
            obs["persistence"].append({"type": "scheduled task command", "detail": str(c)})
    for mtx in _as_list(summary.get("mutexes"))[:50]:
        obs["events"].append({"type": "mutex", "detail": str(mtx)})
    net = rep.get("network") or {}
    for d in _as_list(net.get("dns"))[:300]:
        obs["network"]["dns"].append({"query": d.get("request"), "type": d.get("type"),
                                      "answers": [a.get("data") for a in _as_list(d.get("answers")) if isinstance(a, dict)]})
    for proto in ("tcp", "udp"):
        for c in _as_list(net.get(proto))[:300]:
            obs["network"]["connections"].append({"proto": proto, "dst": c.get("dst"), "port": c.get("dport")})
    for h in _as_list(net.get("http"))[:200]:
        obs["network"]["http"].append({"method": h.get("method"), "url": h.get("uri") or h.get("host")})
    for sig in _as_list(rep.get("signatures"))[:200]:
        obs["engine_signatures"].append({"name": sig.get("name"), "description": sig.get("description"), "severity": sig.get("severity")})
    debug = rep.get("debug") or {}
    obs["errors"] = [str(e)[:500] for e in _as_list(debug.get("errors"))[:50]]
    return obs
