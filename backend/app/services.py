"""Evidence import and analysis orchestration."""
from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any

from . import evidence
from .analysis import findings as rules
from .analysis.runner import run_static
from .analysis.urls import extract_urls
from .config import get_settings
from .db import new_id, record_history, row_to_dict, transaction, utcnow
from .parsing.email_parser import parse_email

log = logging.getLogger("phishbench.import")


class ImportRejected(Exception):
    pass


def import_email(conn: sqlite3.Connection, data: bytes, original_filename: str | None, case_id: str | None = None) -> dict[str, Any]:
    s = get_settings()
    if len(data) == 0:
        raise ImportRejected("The uploaded file is empty.")
    if len(data) > s.max_upload_bytes:
        raise ImportRejected(f"File is {len(data)} bytes; the upload limit is {s.max_upload_bytes} bytes (PHB_MAX_UPLOAD_BYTES).")
    if original_filename and not original_filename.lower().endswith(".eml"):
        raise ImportRejected("Only .eml files are supported in this version.")

    if case_id and not conn.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
        raise ImportRejected(f"Case {case_id} does not exist.")

    sha = evidence.sha256_bytes(data)
    now = utcnow()
    existing = conn.execute("SELECT id FROM evidence WHERE kind='email' AND sha256=?", (sha,)).fetchone()
    if existing:
        ev_id = existing["id"]
        with transaction(conn):
            conn.execute("INSERT INTO evidence_imports (evidence_id, original_filename, size_bytes, imported_at, duplicate, case_id) VALUES (?,?,?,?,1,?)",
                         (ev_id, original_filename, len(data), now, case_id))
            if case_id:
                _link_case(conn, case_id, ev_id)
            record_history(conn, "evidence", ev_id, "duplicate_import", {"filename": original_filename}, case_id)
        log.info("duplicate import of %s", ev_id)
        return {"evidence_id": ev_id, "duplicate": True, "sha256": sha,
                "message": "These exact bytes were already imported. No second copy was stored; this upload was "
                           "recorded as an additional import event of the existing evidence."}

    ev_id = new_id("EV")
    stored = evidence.store_bytes(data)
    parsed = parse_email(data)

    with transaction(conn):
        conn.execute("INSERT INTO evidence (id, kind, sha256, size_bytes, original_filename, stored_name, imported_at) VALUES (?,?,?,?,?,?,?)",
                     (ev_id, "email", sha, len(data), original_filename, stored, now))
        conn.execute("INSERT INTO evidence_imports (evidence_id, original_filename, size_bytes, imported_at, duplicate, case_id) VALUES (?,?,?,?,0,?)",
                     (ev_id, original_filename, len(data), now, case_id))
        d = parsed.data
        frm = (d.get("from", {}).get("addresses") or [{}])[0] if d.get("from") else {}
        conn.execute(
            "INSERT INTO emails (evidence_id, parse_status, subject, from_address, from_display, date_utc, message_id, parsed_json, warnings_json, errors_json, parsed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (ev_id, parsed.status, (d.get("subject") or {}).get("decoded"), frm.get("address"), frm.get("display_name"),
             (d.get("date") or {}).get("utc"), (d.get("message_id") or {}).get("decoded"), json.dumps(d), json.dumps(parsed.warnings),
             json.dumps(parsed.errors), now),
        )
        for att in parsed.attachments:
            at_id = new_id("AT")
            at_stored = evidence.store_bytes(att.payload)
            conn.execute("INSERT INTO evidence (id, kind, sha256, size_bytes, original_filename, stored_name, parent_id, mime_part_ref, imported_at) VALUES (?,?,?,?,?,?,?,?,?)",
                         (at_id, "attachment", evidence.sha256_bytes(att.payload), len(att.payload), att.filename_display, at_stored, ev_id, att.part_ref, now))
            conn.execute("INSERT INTO attachments (evidence_id, email_evidence_id, filename_raw, filename_display, declared_mime, disposition, static_status) VALUES (?,?,?,?,?,?, 'pending')",
                         (at_id, ev_id, att.filename_raw, att.filename_display, att.declared_mime, att.disposition))
            conn.execute("INSERT INTO jobs (kind, ref_id, status, run_after, created_at, updated_at) VALUES ('static_analysis', ?, 'queued', ?, ?, ?)",
                         (at_id, now, now, now))
        if parsed.status != "failed":
            urls = extract_urls([b["content"] for b in d.get("text_bodies", [])], [b["content"] for b in d.get("html_bodies", [])])
            for u in urls:
                uid = new_id("URL")
                conn.execute("INSERT INTO urls (id, email_evidence_id, source, original, visible_text, scheme, hostname, normalized_host, parse_ok, warnings_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
                             (uid, ev_id, u.source, u.original, u.visible_text, u.scheme, u.hostname, u.normalized_host, int(u.parse_ok), json.dumps(u.warnings)))
        if case_id:
            _link_case(conn, case_id, ev_id)
        record_history(conn, "evidence", ev_id, "imported", {"filename": original_filename, "sha256": sha,
                                                              "parse_status": parsed.status, "attachments": len(parsed.attachments)}, case_id)
    recompute_email_findings(conn, ev_id)
    return {"evidence_id": ev_id, "duplicate": False, "sha256": sha, "parse_status": parsed.status,
            "warnings": parsed.warnings, "errors": parsed.errors, "attachments": len(parsed.attachments)}


def _link_case(conn: sqlite3.Connection, case_id: str, ev_id: str) -> None:
    if not conn.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
        raise ImportRejected(f"Case {case_id} does not exist.")
    conn.execute("INSERT OR IGNORE INTO case_evidence (case_id, evidence_id, added_at) VALUES (?,?,?)", (case_id, ev_id, utcnow()))
    for row in conn.execute("SELECT id FROM evidence WHERE parent_id=?", (ev_id,)).fetchall():
        conn.execute("INSERT OR IGNORE INTO case_evidence (case_id, evidence_id, added_at) VALUES (?,?,?)", (case_id, row["id"], utcnow()))
    conn.execute("UPDATE cases SET updated_at=? WHERE id=?", (utcnow(), case_id))
    sync_case_findings(conn, case_id)


def sync_case_findings(conn: sqlite3.Connection, case_id: str) -> None:
    conn.execute(
        """INSERT OR IGNORE INTO case_findings (case_id, finding_id, updated_at)
           SELECT ?, f.id, ? FROM findings f JOIN case_evidence ce ON ce.evidence_id = f.email_evidence_id AND ce.case_id = ?""",
        (case_id, utcnow(), case_id),
    )


def references_for_email(conn: sqlite3.Connection, ev_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        """SELECT DISTINCT r.* FROM reference_identities r
           WHERE r.case_id IS NULL OR r.case_id IN (SELECT case_id FROM case_evidence WHERE evidence_id = ?)""",
        (ev_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def recompute_email_findings(conn: sqlite3.Connection, ev_id: str) -> int:
    """(Re)generate rule findings for one email. Analyst review state is kept for findings whose rule+subject+evidence is unchanged."""
    em = conn.execute("SELECT * FROM emails WHERE evidence_id=?", (ev_id,)).fetchone()
    if not em:
        return 0
    parsed = json.loads(em["parsed_json"])
    url_rows = [row_to_dict(r, ("warnings_json",)) for r in conn.execute("SELECT * FROM urls WHERE email_evidence_id=?", (ev_id,))]
    for u in url_rows:
        u["warnings"] = u.pop("warnings_json")
        u["parse_ok"] = bool(u["parse_ok"])
    out = rules.header_findings(parsed, references_for_email(conn, ev_id)) + rules.url_findings(url_rows) + rules.language_findings(parsed)
    for att in conn.execute("SELECT a.*, e.original_filename FROM attachments a JOIN evidence e ON e.id=a.evidence_id WHERE a.email_evidence_id=?", (ev_id,)):
        static = json.loads(att["static_result_json"]) if att["static_result_json"] else None
        out += rules.attachment_findings(att["evidence_id"], att["filename_display"], static)

    with transaction(conn):
        existing = {(r["rule_id"], r["subject_evidence_id"] or "", r["evidence_json"]): r["id"]
                    for r in conn.execute("SELECT id, rule_id, subject_evidence_id, evidence_json FROM findings WHERE email_evidence_id=?", (ev_id,))}
        keep: set[str] = set()
        for f in out:
            key = (f["rule_id"], f["subject_evidence_id"] or "", json.dumps(f["evidence"]))
            if key in existing:
                keep.add(existing[key])
                continue
            fid = new_id("F")
            keep.add(fid)
            conn.execute("INSERT INTO findings (id, email_evidence_id, subject_evidence_id, rule_id, name, category, explanation, evidence_json, confidence, uncertainty, benign_json, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                         (fid, ev_id, f["subject_evidence_id"], f["rule_id"], f["name"], f["category"], f["explanation"],
                          json.dumps(f["evidence"]), f["confidence"], f["uncertainty"], json.dumps(f["benign"]), utcnow()))
        stale = [fid for fid in existing.values() if fid not in keep]
        for fid in stale:
            conn.execute("DELETE FROM case_findings WHERE finding_id=?", (fid,))
            conn.execute("DELETE FROM findings WHERE id=?", (fid,))
        for row in conn.execute("SELECT case_id FROM case_evidence WHERE evidence_id=?", (ev_id,)).fetchall():
            sync_case_findings(conn, row["case_id"])
    return len(out)


def run_static_job(conn: sqlite3.Connection, attachment_id: str) -> str:
    row = conn.execute("SELECT a.*, e.stored_name, e.sha256 FROM attachments a JOIN evidence e ON e.id=a.evidence_id WHERE a.evidence_id=?",
                       (attachment_id,)).fetchone()
    if not row:
        return "missing"
    conn.execute("UPDATE attachments SET static_status='running', static_updated_at=? WHERE evidence_id=?", (utcnow(), attachment_id))
    check = evidence.verify(row["stored_name"], row["sha256"])
    if not check["ok"]:
        result = {"status": "failed", "limitations": [f"Evidence integrity check failed before analysis: {check}"], "stages_completed": []}
    else:
        data = evidence.read_bytes(row["stored_name"])
        try:
            result = run_static(data, row["filename_display"], row["declared_mime"])
        except Exception as exc:  # the runner itself failed
            result = {"status": "failed", "limitations": [f"Analysis runner error: {exc.__class__.__name__}"], "stages_completed": []}
    detected = (result.get("detected") or {}).get("type")
    conn.execute("UPDATE attachments SET static_status=?, static_result_json=?, detected_type=?, static_updated_at=? WHERE evidence_id=?",
                 (result["status"], json.dumps(result, default=str), detected, utcnow(), attachment_id))
    recompute_email_findings(conn, row["email_evidence_id"])
    return result["status"]
