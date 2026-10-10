"""Background worker: processes the SQLite job queue.

Run with:  python -m app.worker
Jobs: static_analysis (attachment), sandbox_poll (sandbox job state machine).
Uploading never triggers execution; sandbox jobs only exist after an analyst
explicitly submits an attachment through the API.
"""
from __future__ import annotations

import logging
import signal
import sqlite3
import time
from datetime import datetime, timedelta, timezone

from .config import get_settings
from .db import connect, migrate, utcnow
from .logsafe import setup_logging

log = logging.getLogger("phishbench.worker")
_stop = False


def _claim(conn: sqlite3.Connection) -> sqlite3.Row | None:
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute("SELECT * FROM jobs WHERE status='queued' AND run_after <= ? ORDER BY id LIMIT 1", (utcnow(),)).fetchone()
        if row:
            conn.execute("UPDATE jobs SET status='running', attempts=attempts+1, updated_at=? WHERE id=?", (utcnow(), row["id"]))
        conn.execute("COMMIT")
        return row
    except BaseException:
        conn.execute("ROLLBACK")
        raise


def reschedule(conn: sqlite3.Connection, job_id: int, delay_s: float) -> None:
    run_after = (datetime.now(timezone.utc) + timedelta(seconds=delay_s)).isoformat(timespec="seconds")
    conn.execute("UPDATE jobs SET status='queued', run_after=?, updated_at=? WHERE id=?", (run_after, utcnow(), job_id))


def process_one(conn: sqlite3.Connection) -> bool:
    """Process a single ready job. Returns False when the queue is empty."""
    from . import services
    from .sandbox import service as sandbox_service

    job = _claim(conn)
    if job is None:
        return False
    try:
        if job["kind"] == "static_analysis":
            status = services.run_static_job(conn, job["ref_id"])
            log.info("static analysis %s -> %s", job["ref_id"], status)
            conn.execute("UPDATE jobs SET status='done', updated_at=? WHERE id=?", (utcnow(), job["id"]))
        elif job["kind"] == "sandbox_poll":
            again = sandbox_service.advance(conn, job["ref_id"])
            if again is None:
                conn.execute("UPDATE jobs SET status='done', updated_at=? WHERE id=?", (utcnow(), job["id"]))
            else:
                reschedule(conn, job["id"], again)
        else:
            raise ValueError(f"unknown job kind {job['kind']}")
    except Exception as exc:
        log.exception("job %s failed", job["id"])
        conn.execute("UPDATE jobs SET status='error', last_error=?, updated_at=? WHERE id=?", (f"{exc.__class__.__name__}: {exc}"[:500], utcnow(), job["id"]))
        if job["kind"] == "static_analysis":
            conn.execute("UPDATE attachments SET static_status='failed', static_result_json=? WHERE evidence_id=? AND static_status IN ('pending','running')",
                         ('{"status":"failed","limitations":["Worker error during analysis"],"stages_completed":[]}', job["ref_id"]))
    return True


def drain(conn: sqlite3.Connection, max_jobs: int = 1000) -> int:
    n = 0
    while n < max_jobs and process_one(conn):
        n += 1
    return n


def recover_stale(conn: sqlite3.Connection) -> None:
    """Jobs left 'running' by a crashed worker go back to the queue."""
    conn.execute("UPDATE jobs SET status='queued', updated_at=? WHERE status='running'", (utcnow(),))
    conn.execute("UPDATE attachments SET static_status='pending' WHERE static_status='running'")


def main() -> None:
    global _stop
    setup_logging()
    migrate()
    s = get_settings()
    conn = connect()
    recover_stale(conn)

    def handle(*_):
        global _stop
        _stop = True

    signal.signal(signal.SIGINT, handle)
    signal.signal(signal.SIGTERM, handle)
    log.info("worker started (sandbox mode: %s)", s.sandbox_mode)
    while not _stop:
        if not process_one(conn):
            time.sleep(s.worker_poll_s)
    conn.close()


if __name__ == "__main__":
    main()
