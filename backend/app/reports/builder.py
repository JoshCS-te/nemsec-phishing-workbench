"""Report revisions.

A report revision has two clearly separated halves:

* ``generated`` — a snapshot of what the tool observed and what its rules
  inferred, taken from the database at a point in time. Analysts cannot edit
  it (they change the underlying review state and refresh instead).
* ``analyst`` — text written by the analyst: summary, assessment, actions,
  limitations, plus the case notes classified as facts / interpretations /
  questions.

Drafts can be edited and refreshed. Marking a revision ``reviewed`` freezes it;
any later edit creates a new draft revision. Every revision is kept.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from .. import evidence
from ..cases import NotFound, Invalid, case_findings
from ..db import new_id, record_history, transaction, utcnow

ASSESSMENTS = ("undetermined", "likely_benign", "suspicious", "likely_malicious", "confirmed_malicious")
ANALYST_FIELDS = ("summary", "assessment", "assessment_rationale", "actions", "recommendations", "limitations")


def _summ_addr(block: dict[str, Any] | None) -> str | None:
    return (block or {}).get("raw")


def build_generated(conn: sqlite3.Connection, case_id: str) -> dict[str, Any]:
    case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if not case:
        raise NotFound("Case not found")
    included = conn.execute(
        """SELECT e.* FROM case_evidence ce JOIN evidence e ON e.id=ce.evidence_id
           WHERE ce.case_id=? AND ce.include_in_report=1 ORDER BY e.kind DESC, e.imported_at""", (case_id,)).fetchall()
    inc_ids = {r["id"] for r in included}
    scope = []
    for e in included:
        integrity = evidence.verify(e["stored_name"], e["sha256"])
        scope.append({"id": e["id"], "kind": e["kind"], "filename": e["original_filename"], "sha256": e["sha256"],
                      "size_bytes": e["size_bytes"], "imported_at": e["imported_at"], "parent_id": e["parent_id"],
                      "mime_part_ref": e["mime_part_ref"], "integrity_ok_at_snapshot": integrity["ok"]})

    emails = []
    for e in included:
        if e["kind"] != "email":
            continue
        em = conn.execute("SELECT * FROM emails WHERE evidence_id=?", (e["id"],)).fetchone()
        p = json.loads(em["parsed_json"])
        emails.append({
            "id": e["id"], "parse_status": em["parse_status"],
            "subject": (p.get("subject") or {}).get("decoded"), "from": _summ_addr(p.get("from")),
            "reply_to": _summ_addr(p.get("reply_to")), "return_path": _summ_addr(p.get("return_path")),
            "to": _summ_addr(p.get("to")), "cc": _summ_addr(p.get("cc")),
            "message_id": (p.get("message_id") or {}).get("raw"),
            "date_raw": (p.get("date") or {}).get("raw"), "date_utc": (p.get("date") or {}).get("utc"),
            "received_hops": len(p.get("received") or []),
            "auth_claims": [{"authserv_id": a["authserv_id"], "methods": [f"{m['method']}={m['result']}" for m in a["methods"]]}
                            for a in p.get("authentication_results", [])],
            "warnings": json.loads(em["warnings_json"]), "errors": json.loads(em["errors_json"]),
        })

    findings = []
    for f in case_findings(conn, case_id):
        if not f["include_in_report"] or f["email_evidence_id"] not in inc_ids:
            continue
        if f["subject_evidence_id"] and f["subject_evidence_id"] not in inc_ids:
            continue
        refs = [f["email_evidence_id"]] + ([f["subject_evidence_id"]] if f["subject_evidence_id"] else [])
        findings.append({
            "id": f["id"], "rule_id": f["rule_id"], "name": f["name"], "category": f["category"], "confidence": f["confidence"],
            "explanation": f["explanation"], "evidence": f["evidence_json"], "uncertainty": f["uncertainty"],
            "benign": f["benign_json"], "review_status": f["review_status"], "analyst_comment": f["analyst_comment"],
            "evidence_refs": refs,
        })

    attachments = []
    for e in included:
        if e["kind"] != "attachment":
            continue
        a = conn.execute("SELECT * FROM attachments WHERE evidence_id=?", (e["id"],)).fetchone()
        st = json.loads(a["static_result_json"]) if a["static_result_json"] else {}
        attachments.append({
            "id": e["id"], "email_id": e["parent_id"], "filename": a["filename_display"], "filename_raw": a["filename_raw"],
            "declared_mime": a["declared_mime"], "sha256": e["sha256"], "size_bytes": e["size_bytes"], "mime_part_ref": e["mime_part_ref"],
            "detected": (st.get("detected") or {}).get("label"), "static_status": a["static_status"],
            "limitations": st.get("limitations", []),
        })

    sandbox = []
    # Runs are about the attachment, so any run of an in-scope attachment is included, whichever case submitted it.
    for j in conn.execute(
            "SELECT * FROM sandbox_jobs WHERE attachment_id IN (SELECT evidence_id FROM case_evidence WHERE case_id=? AND include_in_report=1) "
            "ORDER BY submitted_at", (case_id,)).fetchall():
        obs = json.loads(j["observations_json"]) if j["observations_json"] else None
        cov = json.loads(j["coverage_json"]) if j["coverage_json"] else None
        summary = None
        if obs:
            summary = {
                "processes": [f"{p.get('name')} (pid {p.get('pid')}, parent {p.get('ppid')})" for p in obs.get("processes", [])[:30]],
                "files_created": obs.get("files", {}).get("created", [])[:30],
                "files_deleted": obs.get("files", {}).get("deleted", [])[:30],
                "registry_set": obs.get("registry", {}).get("set", [])[:30],
                "persistence": [f"{p['type']}: {p['detail']}" for p in obs.get("persistence", [])[:20]],
                "dns": [d.get("query") for d in obs.get("network", {}).get("dns", [])[:30]],
                "connections": [f"{c.get('proto')} {c.get('dst')}:{c.get('port')}" for c in obs.get("network", {}).get("connections", [])[:30]],
                "engine_signatures": [f"{s.get('name')}: {s.get('description')}" for s in obs.get("engine_signatures", [])[:20]],
                "errors": obs.get("errors", [])[:10],
                "duration_s": obs.get("duration_s"),
            }
        shots = conn.execute("SELECT id, label FROM sandbox_artifacts WHERE sandbox_job_id=? AND kind='screenshot'", (j["id"],)).fetchall()
        sandbox.append({
            "id": j["id"], "attachment_id": j["attachment_id"], "engine": j["adapter"], "is_demo": bool(j["is_demo"]),
            "state": j["state"], "state_detail": j["state_detail"], "execution_outcome": j["execution_outcome"],
            "reset_status": j["reset_status"], "submitted_by": j["submitted_by"], "submitted_at": j["submitted_at"],
            "finished_at": j["finished_at"], "observations": summary, "coverage": cov,
            "screenshots": [dict(s) for s in shots],
        })

    could_not = [
        "Whether the email is authentic. Header contents, including Received and Authentication-Results, are as written "
        "in the file and were not verified against a trusted receiving server. SPF/DKIM/DMARC were not re-evaluated.",
        "What any linked website contains or does. Links were analysed as text only and were not visited.",
    ]
    attachments_sandboxed = {s["attachment_id"] for s in sandbox if not s["is_demo"] and s["execution_outcome"] == "completed"}
    for a in attachments:
        if a["static_status"] in ("partial", "unsupported", "encrypted", "failed", "too_large", "pending", "running"):
            could_not.append(f"Full static content of attachment {a['id']} ({a['filename']}): analysis status '{a['static_status']}'.")
        if a["id"] not in attachments_sandboxed:
            could_not.append(f"Runtime behaviour of attachment {a['id']} ({a['filename']}): no completed live sandbox run.")
    if any(s["is_demo"] for s in sandbox):
        could_not.append("Sandbox entries marked DEMO contain synthetic data and are not observations of the attachment.")
    for s in sandbox:
        if s["reset_status"] == "failed":
            could_not.append(f"Sandbox job {s['id']}: the guest could not be verified clean afterwards; treat later runs on that worker with caution.")

    return {"case": {"id": case["id"], "title": case["title"], "description": case["description"], "status": case["status"]},
            "snapshot_at": utcnow(), "scope": scope, "emails": emails, "findings": findings, "attachments": attachments,
            "sandbox": sandbox, "could_not_establish": could_not}


def _notes_snapshot(conn: sqlite3.Connection, case_id: str) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {"facts": [], "interpretations": [], "questions": []}
    key = {"fact": "facts", "interpretation": "interpretations", "question": "questions"}
    for n in conn.execute("SELECT * FROM notes WHERE case_id=? AND kind IN ('fact','interpretation','question') ORDER BY created_at", (case_id,)):
        out[key[n["kind"]]].append({"id": n["id"], "body": n["body"], "refs": json.loads(n["evidence_refs"]), "resolved": bool(n["resolved"])})
    return out


def _report(conn: sqlite3.Connection, case_id: str) -> sqlite3.Row:
    r = conn.execute("SELECT * FROM reports WHERE case_id=?", (case_id,)).fetchone()
    if r:
        return r
    rid = new_id("RPT")
    conn.execute("INSERT INTO reports (id, case_id, created_at) VALUES (?,?,?)", (rid, case_id, utcnow()))
    return conn.execute("SELECT * FROM reports WHERE id=?", (rid,)).fetchone()


def latest(conn: sqlite3.Connection, case_id: str) -> dict[str, Any] | None:
    r = conn.execute("SELECT * FROM reports WHERE case_id=?", (case_id,)).fetchone()
    if not r:
        return None
    rev = conn.execute("SELECT * FROM report_revisions WHERE report_id=? ORDER BY revision DESC LIMIT 1", (r["id"],)).fetchone()
    return _rev_dict(rev) if rev else None


def list_revisions(conn: sqlite3.Connection, case_id: str) -> list[dict[str, Any]]:
    return [dict(r) for r in conn.execute(
        """SELECT rr.id, rr.revision, rr.status, rr.created_at, rr.reviewed_at, rr.reviewer, rr.pdf_sha256
           FROM report_revisions rr JOIN reports r ON r.id=rr.report_id WHERE r.case_id=? ORDER BY rr.revision DESC""", (case_id,))]


def get_revision(conn: sqlite3.Connection, revision_id: str) -> dict[str, Any]:
    rev = conn.execute("SELECT * FROM report_revisions WHERE id=?", (revision_id,)).fetchone()
    if not rev:
        raise NotFound("Revision not found")
    return _rev_dict(rev)


def _rev_dict(rev: sqlite3.Row) -> dict[str, Any]:
    d = dict(rev)
    d["content"] = json.loads(d.pop("content_json"))
    return d


def _blank_analyst() -> dict[str, Any]:
    return {"summary": "", "assessment": "undetermined", "assessment_rationale": "", "actions": "", "recommendations": "",
            "limitations": "", "author": ""}


def new_draft(conn: sqlite3.Connection, case_id: str) -> dict[str, Any]:
    """Create a draft. If the latest revision is already a draft, refresh its generated snapshot instead."""
    with transaction(conn):
        rpt = _report(conn, case_id)
        prev = conn.execute("SELECT * FROM report_revisions WHERE report_id=? ORDER BY revision DESC LIMIT 1", (rpt["id"],)).fetchone()
        generated = build_generated(conn, case_id)
        notes = _notes_snapshot(conn, case_id)
        if prev and prev["status"] == "draft":
            content = json.loads(prev["content_json"])
            content["generated"] = generated
            content["analyst"]["notes"] = notes
            conn.execute("UPDATE report_revisions SET content_json=?, pdf_stored_name=NULL, pdf_sha256=NULL WHERE id=?",
                         (json.dumps(content), prev["id"]))
            record_history(conn, "report", prev["id"], "draft_refreshed", {"revision": prev["revision"]}, case_id)
            rev_id = prev["id"]
        else:
            analyst = json.loads(prev["content_json"])["analyst"] if prev else _blank_analyst()
            analyst["notes"] = notes
            number = (prev["revision"] + 1) if prev else 1
            rev_id = new_id("REV")
            conn.execute("INSERT INTO report_revisions (id, report_id, revision, status, content_json, created_at) VALUES (?,?,?, 'draft', ?, ?)",
                         (rev_id, rpt["id"], number, json.dumps({"generated": generated, "analyst": analyst}), utcnow()))
            record_history(conn, "report", rev_id, "draft_created", {"revision": number, "based_on": prev["revision"] if prev else None}, case_id)
    return get_revision(conn, rev_id)


def update_draft(conn: sqlite3.Connection, revision_id: str, analyst: dict[str, Any]) -> dict[str, Any]:
    rev = conn.execute("SELECT rr.*, r.case_id FROM report_revisions rr JOIN reports r ON r.id=rr.report_id WHERE rr.id=?", (revision_id,)).fetchone()
    if not rev:
        raise NotFound("Revision not found")
    if rev["status"] != "draft":
        raise Invalid("Reviewed revisions are frozen. Create a new draft to make changes.")
    content = json.loads(rev["content_json"])
    for k in ANALYST_FIELDS + ("author",):
        if k in analyst and analyst[k] is not None:
            v = str(analyst[k])[:20000]
            if k == "assessment" and v not in ASSESSMENTS:
                raise Invalid(f"assessment must be one of {ASSESSMENTS}")
            content["analyst"][k] = v
    with transaction(conn):
        conn.execute("UPDATE report_revisions SET content_json=?, pdf_stored_name=NULL, pdf_sha256=NULL WHERE id=?", (json.dumps(content), revision_id))
        record_history(conn, "report", revision_id, "draft_edited", {"fields": sorted(k for k in analyst if k in ANALYST_FIELDS)}, rev["case_id"])
    return get_revision(conn, revision_id)


def mark_reviewed(conn: sqlite3.Connection, revision_id: str, reviewer: str) -> dict[str, Any]:
    rev = conn.execute("SELECT rr.*, r.case_id FROM report_revisions rr JOIN reports r ON r.id=rr.report_id WHERE rr.id=?", (revision_id,)).fetchone()
    if not rev:
        raise NotFound("Revision not found")
    if rev["status"] != "draft":
        raise Invalid("Already reviewed")
    if not reviewer.strip():
        raise Invalid("Reviewer name is required")
    content = json.loads(rev["content_json"])
    a = content["analyst"]
    missing = [k for k in ("summary", "assessment_rationale") if not a.get(k, "").strip()]
    if missing:
        raise Invalid(f"Fill in {', '.join(missing)} before marking the report reviewed.")
    with transaction(conn):
        conn.execute("UPDATE report_revisions SET status='reviewed', reviewed_at=?, reviewer=?, pdf_stored_name=NULL, pdf_sha256=NULL WHERE id=?",
                     (utcnow(), reviewer.strip()[:100], revision_id))
        record_history(conn, "report", revision_id, "reviewed", {"revision": rev["revision"], "reviewer": reviewer.strip()[:100]}, rev["case_id"])
    return get_revision(conn, revision_id)
