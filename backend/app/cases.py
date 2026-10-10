"""Investigation cases, notes, finding reviews and reference identities."""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from .db import new_id, record_history, row_to_dict, transaction, utcnow
from .services import recompute_email_findings, sync_case_findings


class NotFound(Exception):
    pass


class Invalid(Exception):
    pass


def _case(conn: sqlite3.Connection, case_id: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if not row:
        raise NotFound(f"Case {case_id} not found")
    return row


def _touch(conn: sqlite3.Connection, case_id: str) -> None:
    conn.execute("UPDATE cases SET updated_at=? WHERE id=?", (utcnow(), case_id))


def create_case(conn: sqlite3.Connection, title: str, description: str = "") -> dict[str, Any]:
    title = title.strip()
    if not title:
        raise Invalid("Title is required")
    cid = new_id("CASE")
    now = utcnow()
    with transaction(conn):
        conn.execute("INSERT INTO cases (id, title, description, status, created_at, updated_at) VALUES (?,?,?, 'open', ?, ?)",
                     (cid, title[:200], description[:5000], now, now))
        record_history(conn, "case", cid, "created", {"title": title[:200]}, cid)
    return get_case(conn, cid)


def update_case(conn: sqlite3.Connection, case_id: str, title: str | None = None, description: str | None = None,
                status: str | None = None) -> dict[str, Any]:
    row = _case(conn, case_id)
    changes: dict[str, Any] = {}
    with transaction(conn):
        if title is not None and title.strip() and title.strip() != row["title"]:
            conn.execute("UPDATE cases SET title=? WHERE id=?", (title.strip()[:200], case_id))
            changes["title"] = {"from": row["title"], "to": title.strip()[:200]}
        if description is not None and description != row["description"]:
            conn.execute("UPDATE cases SET description=? WHERE id=?", (description[:5000], case_id))
            changes["description"] = "edited"
        if status is not None and status != row["status"]:
            if status not in ("open", "closed"):
                raise Invalid("status must be open or closed")
            conn.execute("UPDATE cases SET status=?, closed_at=? WHERE id=?", (status, utcnow() if status == "closed" else None, case_id))
            changes["status"] = {"from": row["status"], "to": status}
            record_history(conn, "case", case_id, "closed" if status == "closed" else "reopened", {}, case_id)
        if changes:
            _touch(conn, case_id)
            record_history(conn, "case", case_id, "edited", changes, case_id)
    return get_case(conn, case_id)


def require_open(conn: sqlite3.Connection, case_id: str) -> None:
    if _case(conn, case_id)["status"] != "open":
        raise Invalid("Case is closed. Reopen it to make changes.")


def list_cases(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        """SELECT c.*,
             (SELECT COUNT(*) FROM case_evidence ce JOIN evidence e ON e.id=ce.evidence_id WHERE ce.case_id=c.id AND e.kind='email') AS email_count,
             (SELECT COUNT(*) FROM case_findings cf WHERE cf.case_id=c.id) AS finding_count,
             (SELECT COUNT(*) FROM case_findings cf WHERE cf.case_id=c.id AND cf.review_status='unreviewed') AS unreviewed_count,
             (SELECT MAX(status) FROM report_revisions rr JOIN reports r ON r.id=rr.report_id WHERE r.case_id=c.id
                AND rr.revision = (SELECT MAX(revision) FROM report_revisions WHERE report_id=r.id)) AS report_status
           FROM cases c ORDER BY c.status='closed', c.updated_at DESC"""
    ).fetchall()
    return [dict(r) for r in rows]


def get_case(conn: sqlite3.Connection, case_id: str) -> dict[str, Any]:
    c = dict(_case(conn, case_id))
    c["evidence"] = [dict(r) for r in conn.execute(
        """SELECT e.id, e.kind, e.sha256, e.size_bytes, e.original_filename, e.parent_id, e.imported_at, ce.include_in_report,
                  em.subject, em.from_address, em.parse_status, a.static_status, a.detected_type
           FROM case_evidence ce JOIN evidence e ON e.id=ce.evidence_id
           LEFT JOIN emails em ON em.evidence_id=e.id LEFT JOIN attachments a ON a.evidence_id=e.id
           WHERE ce.case_id=? ORDER BY e.kind DESC, e.imported_at""", (case_id,))]
    c["findings"] = case_findings(conn, case_id)
    c["notes"] = [row_to_dict(r, ("evidence_refs",)) for r in conn.execute("SELECT * FROM notes WHERE case_id=? ORDER BY created_at", (case_id,))]
    c["references"] = [dict(r) for r in conn.execute("SELECT * FROM reference_identities WHERE case_id=? OR case_id IS NULL ORDER BY display_name", (case_id,))]
    c["sandbox_jobs"] = [dict(r) for r in conn.execute(
        """SELECT id, attachment_id, case_id, adapter, is_demo, state, state_detail, reset_status, submitted_at, finished_at FROM sandbox_jobs
           WHERE case_id=? OR attachment_id IN (SELECT evidence_id FROM case_evidence WHERE case_id=?) ORDER BY submitted_at DESC""", (case_id, case_id))]
    return c


def case_findings(conn: sqlite3.Connection, case_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """SELECT f.*, cf.review_status, cf.analyst_comment, cf.include_in_report, cf.updated_at AS reviewed_at
           FROM case_findings cf JOIN findings f ON f.id=cf.finding_id WHERE cf.case_id=?
           ORDER BY CASE f.confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, f.category, f.name""",
        (case_id,),
    ).fetchall()
    return [row_to_dict(r, ("evidence_json", "benign_json")) for r in rows]


def attach_evidence(conn: sqlite3.Connection, case_id: str, evidence_id: str) -> dict[str, Any]:
    require_open(conn, case_id)
    ev = conn.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    if not ev:
        raise NotFound("Evidence not found")
    root = ev["parent_id"] or ev["id"]
    with transaction(conn):
        for eid in [root] + [r["id"] for r in conn.execute("SELECT id FROM evidence WHERE parent_id=?", (root,))]:
            conn.execute("INSERT OR IGNORE INTO case_evidence (case_id, evidence_id, added_at) VALUES (?,?,?)", (case_id, eid, utcnow()))
        sync_case_findings(conn, case_id)
        _touch(conn, case_id)
        record_history(conn, "case", case_id, "evidence_attached", {"evidence": root}, case_id)
    recompute_email_findings(conn, root)
    return get_case(conn, case_id)


def set_evidence_selection(conn: sqlite3.Connection, case_id: str, evidence_id: str, include: bool) -> None:
    require_open(conn, case_id)
    cur = conn.execute("UPDATE case_evidence SET include_in_report=? WHERE case_id=? AND evidence_id=?", (int(include), case_id, evidence_id))
    if cur.rowcount == 0:
        raise NotFound("Evidence is not part of this case")
    record_history(conn, "case", case_id, "evidence_selection", {"evidence": evidence_id, "include": include}, case_id)


def review_finding(conn: sqlite3.Connection, case_id: str, finding_id: str, status: str | None, comment: str | None,
                   include: bool | None) -> dict[str, Any]:
    require_open(conn, case_id)
    row = conn.execute("SELECT * FROM case_findings WHERE case_id=? AND finding_id=?", (case_id, finding_id)).fetchone()
    if not row:
        raise NotFound("Finding is not part of this case")
    if status is not None and status not in ("unreviewed", "relevant", "benign", "unresolved"):
        raise Invalid("Invalid review status")
    new = {
        "review_status": status if status is not None else row["review_status"],
        "analyst_comment": (comment if comment is not None else row["analyst_comment"])[:4000],
        "include_in_report": int(include) if include is not None else row["include_in_report"],
    }
    with transaction(conn):
        conn.execute("UPDATE case_findings SET review_status=?, analyst_comment=?, include_in_report=?, updated_at=? WHERE case_id=? AND finding_id=?",
                     (new["review_status"], new["analyst_comment"], new["include_in_report"], utcnow(), case_id, finding_id))
        _touch(conn, case_id)
        record_history(conn, "finding", finding_id, "reviewed",
                       {"from": row["review_status"], "to": new["review_status"], "include": bool(new["include_in_report"])}, case_id)
    return new


NOTE_KINDS = ("fact", "interpretation", "question", "note")


def add_note(conn: sqlite3.Connection, case_id: str, kind: str, body: str, refs: list[str]) -> dict[str, Any]:
    require_open(conn, case_id)
    if kind not in NOTE_KINDS:
        raise Invalid(f"kind must be one of {NOTE_KINDS}")
    if not body.strip():
        raise Invalid("Note body is required")
    _validate_refs(conn, case_id, refs)
    nid = new_id("N")
    now = utcnow()
    with transaction(conn):
        conn.execute("INSERT INTO notes (id, case_id, kind, body, evidence_refs, created_at, updated_at) VALUES (?,?,?,?,?,?,?)",
                     (nid, case_id, kind, body.strip()[:10000], json.dumps(refs), now, now))
        _touch(conn, case_id)
        record_history(conn, "note", nid, "created", {"kind": kind}, case_id)
    return row_to_dict(conn.execute("SELECT * FROM notes WHERE id=?", (nid,)).fetchone(), ("evidence_refs",))  # type: ignore[return-value]


def update_note(conn: sqlite3.Connection, case_id: str, note_id: str, body: str | None, kind: str | None,
                resolved: bool | None, refs: list[str] | None) -> dict[str, Any]:
    require_open(conn, case_id)
    row = conn.execute("SELECT * FROM notes WHERE id=? AND case_id=?", (note_id, case_id)).fetchone()
    if not row:
        raise NotFound("Note not found")
    if kind is not None and kind not in NOTE_KINDS:
        raise Invalid("Invalid kind")
    if refs is not None:
        _validate_refs(conn, case_id, refs)
    with transaction(conn):
        conn.execute("UPDATE notes SET body=?, kind=?, resolved=?, evidence_refs=?, updated_at=? WHERE id=?",
                     ((body.strip()[:10000] if body is not None else row["body"]), kind or row["kind"],
                      int(resolved) if resolved is not None else row["resolved"],
                      json.dumps(refs) if refs is not None else row["evidence_refs"], utcnow(), note_id))
        _touch(conn, case_id)
        record_history(conn, "note", note_id, "edited", {"kind": kind or row["kind"]}, case_id)
    return row_to_dict(conn.execute("SELECT * FROM notes WHERE id=?", (note_id,)).fetchone(), ("evidence_refs",))  # type: ignore[return-value]


def delete_note(conn: sqlite3.Connection, case_id: str, note_id: str) -> None:
    require_open(conn, case_id)
    with transaction(conn):
        cur = conn.execute("DELETE FROM notes WHERE id=? AND case_id=?", (note_id, case_id))
        if cur.rowcount == 0:
            raise NotFound("Note not found")
        record_history(conn, "note", note_id, "deleted", {}, case_id)


def _validate_refs(conn: sqlite3.Connection, case_id: str, refs: list[str]) -> None:
    for r in refs:
        ok = conn.execute("SELECT 1 FROM case_evidence WHERE case_id=? AND evidence_id=?", (case_id, r)).fetchone() or \
             conn.execute("SELECT 1 FROM case_findings WHERE case_id=? AND finding_id=?", (case_id, r)).fetchone() or \
             conn.execute("SELECT 1 FROM sandbox_jobs WHERE case_id=? AND id=?", (case_id, r)).fetchone()
        if not ok:
            raise Invalid(f"Reference {r} is not evidence, a finding or a sandbox job in this case")


def add_reference(conn: sqlite3.Connection, case_id: str | None, display_name: str, email: str | None) -> dict[str, Any]:
    if not display_name.strip():
        raise Invalid("Display name required")
    rid = new_id("REF")
    conn.execute("INSERT INTO reference_identities (id, case_id, display_name, email, created_at) VALUES (?,?,?,?,?)",
                 (rid, case_id, display_name.strip()[:200], (email or "").strip()[:320] or None, utcnow()))
    record_history(conn, "reference_identity", rid, "created", {"display_name": display_name}, case_id)
    _rerun_for_case(conn, case_id)
    return dict(conn.execute("SELECT * FROM reference_identities WHERE id=?", (rid,)).fetchone())


def delete_reference(conn: sqlite3.Connection, ref_id: str) -> None:
    row = conn.execute("SELECT * FROM reference_identities WHERE id=?", (ref_id,)).fetchone()
    if not row:
        raise NotFound("Reference not found")
    conn.execute("DELETE FROM reference_identities WHERE id=?", (ref_id,))
    record_history(conn, "reference_identity", ref_id, "deleted", {}, row["case_id"])
    _rerun_for_case(conn, row["case_id"])


def _rerun_for_case(conn: sqlite3.Connection, case_id: str | None) -> None:
    if case_id:
        ids = [r["evidence_id"] for r in conn.execute(
            "SELECT ce.evidence_id FROM case_evidence ce JOIN evidence e ON e.id=ce.evidence_id WHERE ce.case_id=? AND e.kind='email'", (case_id,))]
    else:
        ids = [r["evidence_id"] for r in conn.execute("SELECT evidence_id FROM emails")]
    for eid in ids:
        recompute_email_findings(conn, eid)


def history(conn: sqlite3.Connection, case_id: str) -> list[dict[str, Any]]:
    return [row_to_dict(r, ("detail_json",)) for r in conn.execute("SELECT * FROM history WHERE case_id=? ORDER BY id DESC LIMIT 500", (case_id,))]  # type: ignore[misc]
