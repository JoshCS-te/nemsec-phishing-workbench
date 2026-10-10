"""Sandbox job lifecycle.

States (sandbox_jobs.state):
    queued -> running -> completed | failed | timed_out | cancelled
    any finished state -> reset_failed   (if the guest could not be verified clean afterwards)

``completed`` means the engine finished executing and reporting. It does not
mean the attachment is safe.

A worker (guest VM) is marked ``busy`` from submission until a reset is
verified. Queued jobs wait while it is busy. If reset verification fails the
worker is ``quarantined`` and refuses all further jobs until an analyst
records that it was manually restored.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from .. import evidence
from ..config import get_settings
from ..db import new_id, record_history, transaction, utcnow
from .base import SandboxAdapter, SandboxError

log = logging.getLogger("phishbench.sandbox")
TERMINAL = {"completed", "failed", "timed_out", "cancelled", "reset_failed"}
_adapter_override: SandboxAdapter | None = None


class SubmissionRefused(Exception):
    pass


def set_adapter_for_tests(adapter: SandboxAdapter | None) -> None:
    global _adapter_override
    _adapter_override = adapter


def get_adapter() -> SandboxAdapter | None:
    if _adapter_override is not None:
        return _adapter_override
    s = get_settings()
    if s.sandbox_mode == "cape":
        from .cape import CapeAdapter

        return CapeAdapter(s.cape_url, s.cape_token, s.cape_snapshot or None)
    if s.sandbox_mode == "demo":
        from .demo import DemoAdapter

        return DemoAdapter()
    return None


def worker_name() -> str:
    s = get_settings()
    return s.cape_machine if s.sandbox_mode == "cape" else "demo-guest"


def _ensure_worker(conn: sqlite3.Connection, name: str, adapter: str) -> sqlite3.Row:
    conn.execute("INSERT OR IGNORE INTO sandbox_workers (name, adapter, status, updated_at) VALUES (?,?, 'available', ?)", (name, adapter, utcnow()))
    return conn.execute("SELECT * FROM sandbox_workers WHERE name=?", (name,)).fetchone()


def _set_worker(conn: sqlite3.Connection, name: str, status: str, reason: str | None) -> None:
    conn.execute("UPDATE sandbox_workers SET status=?, reason=?, updated_at=? WHERE name=?", (status, reason, utcnow(), name))


def status_overview(conn: sqlite3.Connection) -> dict[str, Any]:
    s = get_settings()
    adapter = get_adapter()
    out: dict[str, Any] = {"mode": s.sandbox_mode, "enabled": adapter is not None}
    if adapter is None:
        out["detail"] = "Sandbox is disabled (PHB_SANDBOX_MODE=disabled). Static analysis is still available."
        return out
    name = worker_name()
    w = _ensure_worker(conn, name, adapter.name)
    out["is_demo"] = adapter.is_demo
    out["capabilities"] = adapter.capabilities().to_dict()
    h = adapter.health(name)
    out["health"] = {"ok": h.ok, "detail": h.detail}
    out["worker"] = dict(w)
    return out


def submit(conn: sqlite3.Connection, attachment_id: str, analyst: str, confirm: bool, case_id: str | None = None,
           timeout_s: int | None = None) -> dict[str, Any]:
    if not confirm:
        raise SubmissionRefused("Execution requires explicit confirmation (confirm=true).")
    if not analyst.strip():
        raise SubmissionRefused("An analyst name is required for the audit trail.")
    adapter = get_adapter()
    if adapter is None:
        raise SubmissionRefused("Sandbox is disabled. Set PHB_SANDBOX_MODE to 'cape' (live) or 'demo' (synthetic).")
    att = conn.execute("SELECT a.*, e.sha256, e.stored_name FROM attachments a JOIN evidence e ON e.id=a.evidence_id WHERE a.evidence_id=?",
                       (attachment_id,)).fetchone()
    if not att:
        raise SubmissionRefused("Attachment not found.")
    caps = adapter.capabilities()
    if att["detected_type"] and att["detected_type"] not in caps.supported_types:
        raise SubmissionRefused(f"The {caps.engine} guest cannot meaningfully run content identified as '{att['detected_type']}'. "
                                f"Supported: {', '.join(sorted(caps.supported_types))}.")
    name = worker_name()
    w = _ensure_worker(conn, name, adapter.name)
    if w["status"] == "quarantined":
        raise SubmissionRefused(f"Sandbox worker '{name}' is quarantined: {w['reason']}. Restore and verify it, then release it.")
    s = get_settings()
    timeout_s = max(30, min(int(timeout_s or s.cape_timeout_s), 1800))
    deadline = (datetime.now(timezone.utc) + timedelta(seconds=s.cape_job_deadline_s + timeout_s)).isoformat(timespec="seconds")
    job_id = new_id("SBX")
    now = utcnow()
    with transaction(conn):
        conn.execute(
            """INSERT INTO sandbox_jobs (id, attachment_id, case_id, adapter, is_demo, worker_name, state, state_detail, timeout_s,
               submitted_by, submitted_at, deadline_at, reset_status) VALUES (?,?,?,?,?,?, 'queued', ?, ?, ?, ?, ?, NULL)""",
            (job_id, attachment_id, case_id, adapter.name, int(adapter.is_demo), name,
             "waiting for worker" if w["status"] == "busy" else "submitted by analyst", timeout_s, analyst.strip()[:100], now, deadline),
        )
        conn.execute("INSERT INTO jobs (kind, ref_id, status, run_after, created_at, updated_at) VALUES ('sandbox_poll', ?, 'queued', ?, ?, ?)",
                     (job_id, now, now, now))
        record_history(conn, "sandbox_job", job_id, "submitted",
                       {"attachment": attachment_id, "sha256": att["sha256"], "adapter": adapter.name, "demo": adapter.is_demo,
                        "analyst": analyst.strip()[:100], "timeout_s": timeout_s}, case_id)
    return {"id": job_id, "state": "queued", "is_demo": adapter.is_demo}


def request_cancel(conn: sqlite3.Connection, job_id: str) -> dict[str, Any]:
    job = conn.execute("SELECT * FROM sandbox_jobs WHERE id=?", (job_id,)).fetchone()
    if not job:
        raise SubmissionRefused("Job not found.")
    if job["state"] in TERMINAL:
        raise SubmissionRefused(f"Job already {job['state']}.")
    conn.execute("UPDATE sandbox_jobs SET cancel_requested=1 WHERE id=?", (job_id,))
    record_history(conn, "sandbox_job", job_id, "cancel_requested", {}, job["case_id"])
    return {"id": job_id, "cancel_requested": True}


def release_worker(conn: sqlite3.Connection, name: str, analyst: str, note: str) -> dict[str, Any]:
    if len(note.strip()) < 10:
        raise SubmissionRefused("Describe how the guest was restored and verified (at least 10 characters).")
    w = conn.execute("SELECT * FROM sandbox_workers WHERE name=?", (name,)).fetchone()
    if not w:
        raise SubmissionRefused("Unknown worker.")
    _set_worker(conn, name, "available", None)
    record_history(conn, "sandbox_worker", name, "released_from_quarantine", {"analyst": analyst, "note": note, "previous_reason": w["reason"]})
    return {"name": name, "status": "available"}


def _update(conn: sqlite3.Connection, job_id: str, **fields: Any) -> None:
    cols = ", ".join(f"{k}=?" for k in fields)
    conn.execute(f"UPDATE sandbox_jobs SET {cols} WHERE id=?", (*fields.values(), job_id))


def _finish_execution(conn: sqlite3.Connection, job: sqlite3.Row, outcome: str, detail: str, **extra: Any) -> None:
    _update(conn, job["id"], state=outcome, execution_outcome=outcome, state_detail=detail, finished_at=utcnow(),
            reset_status="pending", reset_wait_started_at=utcnow(), **extra)
    record_history(conn, "sandbox_job", job["id"], outcome, {"detail": detail}, job["case_id"])


def _store_results(conn: sqlite3.Connection, adapter: SandboxAdapter, job: sqlite3.Row) -> None:
    obs = adapter.results(job["external_task_id"])
    obs["is_demo"] = adapter.is_demo  # never trust the adapter payload for this flag
    _update(conn, job["id"], observations_json=json.dumps(obs, default=str))
    for art in adapter.artifacts(job["external_task_id"]):
        stored = evidence.store_bytes(art.data, kind="artifacts", suffix=art.suffix)
        conn.execute("INSERT INTO sandbox_artifacts (id, sandbox_job_id, kind, label, stored_name, sha256, size_bytes, retrieved_at) VALUES (?,?,?,?,?,?,?,?)",
                     (new_id("ART"), job["id"], art.kind, art.label[:200], stored, evidence.sha256_bytes(art.data), len(art.data), utcnow()))


def coverage_for(adapter: SandboxAdapter, detected_type: str | None, obs: dict[str, Any] | None, outcome: str) -> dict[str, Any]:
    caps = adapter.capabilities()
    notes = list(caps.notes)
    if detected_type in ("docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "ole", "rtf"):
        notes.append("Office content only runs if Office is installed and licensed in the guest, and macros may need a simulated 'Enable Content' click.")
    if detected_type == "pdf":
        notes.append("PDF behaviour depends on the reader installed in the guest.")
    if detected_type == "zip":
        notes.append("For archives the engine chooses which inner file to open; other entries may never run.")
    if detected_type in ("html", "text"):
        notes.append("Phishing pages usually need a person to type credentials; a sandbox will rarely show that.")
    empty = obs is not None and not any([obs.get("processes"), obs["files"].get("created") if obs.get("files") else None,
                                         obs.get("network", {}).get("dns"), obs.get("network", {}).get("connections")])
    if empty and outcome == "completed":
        notes.append("Little or no activity was recorded. A quiet run does not mean the file is safe: it may need interaction, "
                     "a missing application, a specific date or locale, network access, or may detect the sandbox.")
    if outcome in ("timed_out", "cancelled", "failed"):
        notes.append(f"Execution ended as '{outcome}'; any observations are incomplete.")
    return {"engine": caps.engine, "is_demo": caps.is_demo, "observed_categories": caps.observations,
            "network_mode": caps.network_mode, "limitations": notes}


def advance(conn: sqlite3.Connection, job_id: str) -> float | None:
    """Move a job forward one step. Returns seconds until the next poll, or None when fully done."""
    job = conn.execute("SELECT * FROM sandbox_jobs WHERE id=?", (job_id,)).fetchone()
    if job is None:
        return None
    adapter = get_adapter()
    if adapter is None or adapter.name != job["adapter"]:
        if job["state"] not in TERMINAL:
            _update(conn, job_id, state="failed", state_detail=f"adapter '{job['adapter']}' no longer configured", finished_at=utcnow(),
                    reset_status="not_applicable" if not job["external_task_id"] else "failed",
                    execution_outcome="failed")
            if job["external_task_id"]:
                _set_worker(conn, job["worker_name"], "quarantined", f"job {job_id} lost its adapter mid-run; guest state unknown")
        return None
    now = datetime.now(timezone.utc)

    # ---- post-execution: reset verification ---------------------------------
    if job["reset_status"] == "pending":
        check = adapter.verify_reset(job["worker_name"], job["external_task_id"] or "")
        if check.state == "verified":
            _update(conn, job_id, reset_status="verified", reset_detail=check.detail)
            _set_worker(conn, job["worker_name"], "available", None)
            record_history(conn, "sandbox_job", job_id, "reset_verified", {"detail": check.detail}, job["case_id"])
            return None
        started = datetime.fromisoformat(job["reset_wait_started_at"])
        grace = get_settings().cape_reset_grace_s
        if check.state == "failed" or (now - started).total_seconds() > grace:
            reason = check.detail if check.state == "failed" else f"reset not confirmed within {grace}s ({check.detail})"
            _update(conn, job_id, reset_status="failed", reset_detail=reason, state="reset_failed",
                    state_detail=f"execution outcome '{job['execution_outcome']}', but the guest could not be verified clean: {reason}")
            _set_worker(conn, job["worker_name"], "quarantined", f"reset failed after {job_id}: {reason}")
            record_history(conn, "sandbox_job", job_id, "reset_failed", {"detail": reason}, job["case_id"])
            log.warning("worker %s quarantined after %s", job["worker_name"], job_id)
            return None
        return 5.0

    if job["state"] in TERMINAL:
        return None

    worker = _ensure_worker(conn, job["worker_name"], adapter.name)

    # ---- cancellation before submission --------------------------------------
    if job["cancel_requested"] and not job["external_task_id"]:
        _update(conn, job_id, state="cancelled", state_detail="cancelled before execution", finished_at=utcnow(),
                reset_status="not_applicable", execution_outcome="cancelled")
        record_history(conn, "sandbox_job", job_id, "cancelled", {"before_execution": True}, job["case_id"])
        return None

    # ---- not yet handed to the engine ---------------------------------------
    if not job["external_task_id"]:
        if worker["status"] == "quarantined":
            _update(conn, job_id, state="failed", state_detail=f"worker quarantined: {worker['reason']}", finished_at=utcnow(),
                    reset_status="not_applicable", execution_outcome="failed")
            return None
        if worker["status"] == "busy":
            _update(conn, job_id, state_detail="waiting for the guest to be reset after a previous job")
            return 5.0
        if now > datetime.fromisoformat(job["deadline_at"]):
            _update(conn, job_id, state="timed_out", state_detail="never started before the deadline", finished_at=utcnow(),
                    reset_status="not_applicable", execution_outcome="timed_out")
            return None
        health = adapter.health(job["worker_name"])
        if not health.ok:
            _update(conn, job_id, state_detail=f"engine not healthy, retrying: {health.detail}")
            return 15.0
        att = conn.execute("SELECT a.filename_display, e.stored_name, e.sha256 FROM attachments a JOIN evidence e ON e.id=a.evidence_id WHERE a.evidence_id=?",
                           (job["attachment_id"],)).fetchone()
        check = evidence.verify(att["stored_name"], att["sha256"])
        if not check["ok"]:
            _update(conn, job_id, state="failed", state_detail="evidence integrity check failed; not submitted", finished_at=utcnow(),
                    reset_status="not_applicable", execution_outcome="failed")
            return None
        data = evidence.read_bytes(att["stored_name"])
        filename = att["filename_display"] or f"{att['sha256'][:16]}.bin"
        _set_worker(conn, job["worker_name"], "busy", f"running {job_id}")
        try:
            ext_id = adapter.submit(data, filename, job["timeout_s"], job["worker_name"])
        except SandboxError as exc:
            _set_worker(conn, job["worker_name"], "available", None)
            _update(conn, job_id, state="failed", state_detail=f"submission rejected: {exc}", error=str(exc)[:500], finished_at=utcnow(),
                    reset_status="not_applicable", execution_outcome="failed")
            return None
        _update(conn, job_id, external_task_id=ext_id, state_detail="handed to engine")
        record_history(conn, "sandbox_job", job_id, "handed_to_engine", {"external_id": ext_id}, job["case_id"])
        return 3.0

    # ---- handed to engine: poll ---------------------------------------------
    if job["cancel_requested"]:
        ok = adapter.cancel(job["external_task_id"])
        _finish_execution(conn, job, "cancelled", "cancelled by analyst" + ("" if ok else " (engine did not confirm the stop)"))
        return 2.0
    if now > datetime.fromisoformat(job["deadline_at"]):
        adapter.cancel(job["external_task_id"])
        _finish_execution(conn, job, "timed_out", "engine did not finish before the job deadline; stop requested")
        return 2.0
    try:
        st = adapter.status(job["external_task_id"])
    except SandboxError as exc:
        _update(conn, job_id, state_detail=f"status check failed, retrying: {exc}")
        return 10.0
    if st.state == "pending":
        _update(conn, job_id, state="queued", state_detail=f"engine: {st.detail}")
        return 3.0
    if st.state == "running":
        if job["state"] != "running":
            _update(conn, job_id, state="running", started_at=job["started_at"] or utcnow(), state_detail=f"engine: {st.detail}")
        else:
            _update(conn, job_id, state_detail=f"engine: {st.detail}")
        return 3.0
    if st.state == "failed":
        _finish_execution(conn, job, "failed", f"engine reported failure: {st.detail}")
        att = conn.execute("SELECT detected_type FROM attachments WHERE evidence_id=?", (job["attachment_id"],)).fetchone()
        _update(conn, job_id, coverage_json=json.dumps(coverage_for(adapter, att["detected_type"] if att else None, None, "failed")))
        return 2.0
    if st.state == "finished":
        try:
            _store_results(conn, adapter, job)
        except SandboxError as exc:
            _finish_execution(conn, job, "failed", f"execution finished but results could not be retrieved: {exc}", error=str(exc)[:500])
            return 2.0
        fresh = conn.execute("SELECT observations_json FROM sandbox_jobs WHERE id=?", (job_id,)).fetchone()
        obs = json.loads(fresh["observations_json"]) if fresh["observations_json"] else None
        att = conn.execute("SELECT detected_type FROM attachments WHERE evidence_id=?", (job["attachment_id"],)).fetchone()
        _finish_execution(conn, job, "completed", "execution and reporting finished (this is not a safety verdict)",
                          coverage_json=json.dumps(coverage_for(adapter, att["detected_type"] if att else None, obs, "completed")))
        return 2.0
    _update(conn, job_id, state_detail=f"engine status unknown: {st.detail}")
    return 10.0
