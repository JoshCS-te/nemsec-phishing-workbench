"""FastAPI application — NEMSEC Phishing Investigation Workbench API."""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterator

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from . import cases as case_svc
from . import evidence, services
from .config import get_settings
from .db import connect, migrate, row_to_dict, utcnow
from .logsafe import setup_logging
from .parsing.sanitize import PREVIEW_CSP, preview_document, sanitize_html, text_preview_document
from .reports import builder as report_svc
from .reports.pdf import render_pdf
from .sandbox import service as sandbox_svc

log = logging.getLogger("phishbench.api")
REPO_ROOT = Path(__file__).resolve().parents[2]


def create_app() -> FastAPI:
    setup_logging()
    migrate()
    s = get_settings()
    app = FastAPI(title="NEMSEC Phishing Investigation Workbench", version="1.0.0",
                  description="Local evidence-handling API. Bind to localhost only.")
    # DNS-rebinding protection: only accept requests addressed to local names.
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]", "testserver"])
    app.add_middleware(CORSMiddleware, allow_origins=[s.frontend_origin, "http://127.0.0.1:3000"], allow_methods=["*"],
                       allow_headers=["*"], allow_credentials=False)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    _register_routes(app)
    if __import__("os").environ.get("PHB_INLINE_WORKER") == "1":
        threading.Thread(target=_inline_worker, daemon=True, name="inline-worker").start()
    return app


def _inline_worker() -> None:
    import time

    from .worker import process_one, recover_stale

    conn = connect()
    recover_stale(conn)
    while True:
        try:
            if not process_one(conn):
                time.sleep(get_settings().worker_poll_s)
        except Exception:
            log.exception("inline worker error")
            time.sleep(2)


def get_db() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


def _err(exc: Exception) -> HTTPException:
    if isinstance(exc, case_svc.NotFound):
        return HTTPException(404, str(exc))
    return HTTPException(400, str(exc))


# ---------------------------------------------------------------- models
class CaseIn(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = ""


class CasePatch(BaseModel):
    title: str | None = None
    description: str | None = None
    status: str | None = None


class EvidenceLink(BaseModel):
    evidence_id: str


class Selection(BaseModel):
    include: bool


class FindingReview(BaseModel):
    review_status: str | None = None
    analyst_comment: str | None = None
    include_in_report: bool | None = None


class NoteIn(BaseModel):
    kind: str
    body: str
    evidence_refs: list[str] = []


class NotePatch(BaseModel):
    kind: str | None = None
    body: str | None = None
    resolved: bool | None = None
    evidence_refs: list[str] | None = None


class ReferenceIn(BaseModel):
    case_id: str | None = None
    display_name: str
    email: str | None = None


class SandboxSubmit(BaseModel):
    analyst: str
    confirm: bool = False
    case_id: str | None = None
    timeout_s: int | None = None


class WorkerRelease(BaseModel):
    analyst: str
    note: str


class AnalystFields(BaseModel):
    summary: str | None = None
    assessment: str | None = None
    assessment_rationale: str | None = None
    actions: str | None = None
    recommendations: str | None = None
    limitations: str | None = None
    author: str | None = None


class ReviewIn(BaseModel):
    reviewer: str


def _email_detail(conn: sqlite3.Connection, ev_id: str) -> dict[str, Any]:
    ev = conn.execute("SELECT * FROM evidence WHERE id=? AND kind='email'", (ev_id,)).fetchone()
    if not ev:
        raise HTTPException(404, "Email evidence not found")
    em = conn.execute("SELECT * FROM emails WHERE evidence_id=?", (ev_id,)).fetchone()
    parsed = json.loads(em["parsed_json"])
    html_bodies = parsed.get("html_bodies", [])
    preview_info = sanitize_html(html_bodies[0]["content"])["removed"] if html_bodies else None
    for b in parsed.get("html_bodies", []):
        b["content_length"] = len(b["content"])
    atts = [row_to_dict(r) for r in conn.execute(
        """SELECT a.evidence_id AS id, a.filename_display, a.filename_raw, a.declared_mime, a.disposition, a.detected_type,
                  a.static_status, e.sha256, e.size_bytes, e.mime_part_ref FROM attachments a JOIN evidence e ON e.id=a.evidence_id
           WHERE a.email_evidence_id=? ORDER BY e.mime_part_ref""", (ev_id,))]
    urls = [row_to_dict(r, ("warnings_json",)) for r in conn.execute("SELECT * FROM urls WHERE email_evidence_id=?", (ev_id,))]
    findings = [row_to_dict(r, ("evidence_json", "benign_json")) for r in conn.execute(
        """SELECT * FROM findings WHERE email_evidence_id=?
           ORDER BY CASE confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, category""", (ev_id,))]
    imports = [dict(r) for r in conn.execute("SELECT * FROM evidence_imports WHERE evidence_id=? ORDER BY id", (ev_id,))]
    case_ids = [r["case_id"] for r in conn.execute("SELECT case_id FROM case_evidence WHERE evidence_id=?", (ev_id,))]
    return {
        "evidence": dict(ev), "imports": imports, "cases": case_ids, "parse_status": em["parse_status"],
        "warnings": json.loads(em["warnings_json"]), "errors": json.loads(em["errors_json"]),
        "parsed": parsed, "attachments": atts, "urls": urls, "findings": findings, "preview_removed": preview_info,
    }


def _register_routes(app: FastAPI) -> None:
    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"ok": True, "time": utcnow()}

    @app.get("/api/settings")
    def settings_view() -> dict[str, Any]:
        s = get_settings()
        return {"max_upload_bytes": s.max_upload_bytes, "max_attachment_bytes": s.max_attachment_bytes,
                "static_timeout_s": s.static_timeout_s, "static_memory_mb": s.static_memory_mb, "sandbox_mode": s.sandbox_mode,
                "archive_limits": {"depth": s.archive_max_depth, "entries": s.archive_max_entries,
                                   "total_bytes": s.archive_max_total_bytes, "ratio": s.archive_max_ratio}}

    # ---------------- evidence / emails
    @app.post("/api/emails/import")
    async def import_email(file: UploadFile = File(...), case_id: str | None = Form(None), conn=Depends(get_db)) -> dict[str, Any]:
        s = get_settings()
        chunks, total = [], 0
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > s.max_upload_bytes:
                raise HTTPException(413, f"File exceeds the upload limit of {s.max_upload_bytes} bytes.")
            chunks.append(chunk)
        try:
            return services.import_email(conn, b"".join(chunks), file.filename, case_id or None)
        except services.ImportRejected as exc:
            raise HTTPException(400, str(exc))

    @app.get("/api/emails")
    def list_emails(conn=Depends(get_db)) -> list[dict[str, Any]]:
        return [dict(r) for r in conn.execute(
            """SELECT e.id, e.original_filename, e.sha256, e.size_bytes, e.imported_at, em.subject, em.from_address, em.parse_status,
                      (SELECT COUNT(*) FROM attachments a WHERE a.email_evidence_id=e.id) AS attachment_count,
                      (SELECT COUNT(*) FROM findings f WHERE f.email_evidence_id=e.id) AS finding_count
               FROM evidence e JOIN emails em ON em.evidence_id=e.id ORDER BY e.imported_at DESC""")]

    @app.get("/api/emails/{ev_id}")
    def email_detail(ev_id: str, conn=Depends(get_db)) -> dict[str, Any]:
        return _email_detail(conn, ev_id)

    @app.get("/api/emails/{ev_id}/preview", response_class=HTMLResponse)
    def email_preview(ev_id: str, mode: str = "html", conn=Depends(get_db)) -> HTMLResponse:
        em = conn.execute("SELECT parsed_json FROM emails WHERE evidence_id=?", (ev_id,)).fetchone()
        if not em:
            raise HTTPException(404, "Not found")
        parsed = json.loads(em["parsed_json"])
        if mode == "html" and parsed.get("html_bodies"):
            doc = preview_document(sanitize_html(parsed["html_bodies"][0]["content"])["html"])
        else:
            text = parsed["text_bodies"][0]["content"] if parsed.get("text_bodies") else "(no plain-text body in this message)"
            doc = text_preview_document(text)
        s = get_settings()
        csp = PREVIEW_CSP.format(ancestors=f"'self' {s.frontend_origin} http://127.0.0.1:3000")
        return HTMLResponse(doc, headers={"Content-Security-Policy": csp, "X-Content-Type-Options": "nosniff",
                                          "Referrer-Policy": "no-referrer", "Cross-Origin-Resource-Policy": "same-site"})

    @app.get("/api/emails/{ev_id}/raw")
    def email_raw(ev_id: str, conn=Depends(get_db)) -> Response:
        ev = conn.execute("SELECT * FROM evidence WHERE id=? AND kind='email'", (ev_id,)).fetchone()
        if not ev:
            raise HTTPException(404, "Not found")
        # Served as text so a browser never renders it as HTML.
        return Response(evidence.read_bytes(ev["stored_name"]), media_type="text/plain; charset=us-ascii",
                        headers={"Content-Disposition": f'attachment; filename="{ev_id}.eml"', "X-Evidence-SHA256": ev["sha256"]})

    @app.post("/api/emails/{ev_id}/reanalyze")
    def reanalyze(ev_id: str, conn=Depends(get_db)) -> dict[str, Any]:
        n = services.recompute_email_findings(conn, ev_id)
        return {"findings": n}

    @app.get("/api/evidence/{ev_id}/verify")
    def verify(ev_id: str, conn=Depends(get_db)) -> dict[str, Any]:
        ev = conn.execute("SELECT * FROM evidence WHERE id=?", (ev_id,)).fetchone()
        if not ev:
            raise HTTPException(404, "Not found")
        return {"evidence_id": ev_id, **evidence.verify(ev["stored_name"], ev["sha256"])}

    # ---------------- attachments
    @app.get("/api/attachments/{at_id}")
    def attachment_detail(at_id: str, conn=Depends(get_db)) -> dict[str, Any]:
        row = conn.execute(
            """SELECT a.*, e.sha256, e.size_bytes, e.mime_part_ref, e.imported_at FROM attachments a JOIN evidence e ON e.id=a.evidence_id
               WHERE a.evidence_id=?""", (at_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Attachment not found")
        d = row_to_dict(row, ("static_result_json",))
        d["static_result"] = d.pop("static_result_json")
        d["findings"] = [row_to_dict(r, ("evidence_json", "benign_json")) for r in conn.execute(
            "SELECT * FROM findings WHERE subject_evidence_id=?", (at_id,))]
        d["sandbox_jobs"] = [_job_dict(conn, r["id"], brief=True) for r in conn.execute(
            "SELECT id FROM sandbox_jobs WHERE attachment_id=? ORDER BY submitted_at DESC", (at_id,))]
        return d

    @app.post("/api/attachments/{at_id}/reanalyze")
    def reanalyze_attachment(at_id: str, conn=Depends(get_db)) -> dict[str, Any]:
        if not conn.execute("SELECT 1 FROM attachments WHERE evidence_id=?", (at_id,)).fetchone():
            raise HTTPException(404, "Attachment not found")
        now = utcnow()
        conn.execute("UPDATE attachments SET static_status='pending' WHERE evidence_id=?", (at_id,))
        conn.execute("INSERT INTO jobs (kind, ref_id, status, run_after, created_at, updated_at) VALUES ('static_analysis', ?, 'queued', ?, ?, ?)",
                     (at_id, now, now, now))
        return {"queued": True}

    # ---------------- sandbox
    @app.get("/api/sandbox/status")
    def sandbox_status(conn=Depends(get_db)) -> dict[str, Any]:
        return sandbox_svc.status_overview(conn)

    @app.post("/api/attachments/{at_id}/sandbox")
    def sandbox_submit(at_id: str, body: SandboxSubmit, conn=Depends(get_db)) -> dict[str, Any]:
        try:
            return sandbox_svc.submit(conn, at_id, body.analyst, body.confirm, body.case_id, body.timeout_s)
        except sandbox_svc.SubmissionRefused as exc:
            raise HTTPException(409, str(exc))

    def _job_dict(conn: sqlite3.Connection, job_id: str, brief: bool = False) -> dict[str, Any]:
        r = conn.execute("SELECT * FROM sandbox_jobs WHERE id=?", (job_id,)).fetchone()
        if not r:
            raise HTTPException(404, "Job not found")
        d = row_to_dict(r, ("observations_json", "coverage_json"))
        d["observations"] = d.pop("observations_json")
        d["coverage"] = d.pop("coverage_json")
        d["is_demo"] = bool(d["is_demo"])
        if brief:
            d.pop("observations", None)
        d["artifacts"] = [dict(a) for a in conn.execute("SELECT id, kind, label, sha256, size_bytes FROM sandbox_artifacts WHERE sandbox_job_id=?", (job_id,))]
        return d

    @app.get("/api/sandbox/jobs")
    def sandbox_jobs(conn=Depends(get_db)) -> list[dict[str, Any]]:
        return [_job_dict(conn, r["id"], brief=True) for r in conn.execute("SELECT id FROM sandbox_jobs ORDER BY submitted_at DESC LIMIT 200")]

    @app.get("/api/sandbox/jobs/{job_id}")
    def sandbox_job(job_id: str, conn=Depends(get_db)) -> dict[str, Any]:
        return _job_dict(conn, job_id)

    @app.post("/api/sandbox/jobs/{job_id}/cancel")
    def sandbox_cancel(job_id: str, conn=Depends(get_db)) -> dict[str, Any]:
        try:
            return sandbox_svc.request_cancel(conn, job_id)
        except sandbox_svc.SubmissionRefused as exc:
            raise HTTPException(409, str(exc))

    @app.post("/api/sandbox/workers/{name}/release")
    def sandbox_release(name: str, body: WorkerRelease, conn=Depends(get_db)) -> dict[str, Any]:
        try:
            return sandbox_svc.release_worker(conn, name, body.analyst, body.note)
        except sandbox_svc.SubmissionRefused as exc:
            raise HTTPException(400, str(exc))

    @app.get("/api/sandbox/artifacts/{art_id}")
    def sandbox_artifact(art_id: str, conn=Depends(get_db)) -> Response:
        a = conn.execute("SELECT * FROM sandbox_artifacts WHERE id=?", (art_id,)).fetchone()
        if not a or a["kind"] != "screenshot":
            raise HTTPException(404, "Not found")
        data = evidence.read_bytes(a["stored_name"], kind="artifacts")
        if data.startswith(b"\x89PNG"):
            mt = "image/png"
        elif data.startswith(b"\xff\xd8\xff"):
            mt = "image/jpeg"
        else:
            raise HTTPException(415, "Artifact is not a recognised image")
        return Response(data, media_type=mt, headers={"Content-Security-Policy": "default-src 'none'; sandbox"})

    # ---------------- cases
    @app.get("/api/cases")
    def list_cases(conn=Depends(get_db)) -> list[dict[str, Any]]:
        return case_svc.list_cases(conn)

    @app.post("/api/cases")
    def create_case(body: CaseIn, conn=Depends(get_db)) -> dict[str, Any]:
        try:
            return case_svc.create_case(conn, body.title, body.description)
        except Exception as exc:
            raise _err(exc)

    @app.get("/api/cases/{case_id}")
    def get_case(case_id: str, conn=Depends(get_db)) -> dict[str, Any]:
        try:
            return case_svc.get_case(conn, case_id)
        except Exception as exc:
            raise _err(exc)

    @app.patch("/api/cases/{case_id}")
    def patch_case(case_id: str, body: CasePatch, conn=Depends(get_db)) -> dict[str, Any]:
        try:
            return case_svc.update_case(conn, case_id, body.title, body.description, body.status)
        except Exception as exc:
            raise _err(exc)

    @app.get("/api/cases/{case_id}/history")
    def case_history(case_id: str, conn=Depends(get_db)) -> list[dict[str, Any]]:
        return case_svc.history(conn, case_id)

    @app.post("/api/cases/{case_id}/evidence")
    def case_attach(case_id: str, body: EvidenceLink, conn=Depends(get_db)) -> dict[str, Any]:
        try:
            return case_svc.attach_evidence(conn, case_id, body.evidence_id)
        except Exception as exc:
            raise _err(exc)

    @app.patch("/api/cases/{case_id}/evidence/{ev_id}")
    def case_select(case_id: str, ev_id: str, body: Selection, conn=Depends(get_db)) -> dict[str, Any]:
        try:
            case_svc.set_evidence_selection(conn, case_id, ev_id, body.include)
            return {"ok": True}
        except Exception as exc:
            raise _err(exc)

    @app.patch("/api/cases/{case_id}/findings/{finding_id}")
    def case_review(case_id: str, finding_id: str, body: FindingReview, conn=Depends(get_db)) -> dict[str, Any]:
        try:
            return case_svc.review_finding(conn, case_id, finding_id, body.review_status, body.analyst_comment, body.include_in_report)
        except Exception as exc:
            raise _err(exc)

    @app.post("/api/cases/{case_id}/notes")
    def note_add(case_id: str, body: NoteIn, conn=Depends(get_db)) -> dict[str, Any]:
        try:
            return case_svc.add_note(conn, case_id, body.kind, body.body, body.evidence_refs)
        except Exception as exc:
            raise _err(exc)

    @app.patch("/api/cases/{case_id}/notes/{note_id}")
    def note_patch(case_id: str, note_id: str, body: NotePatch, conn=Depends(get_db)) -> dict[str, Any]:
        try:
            return case_svc.update_note(conn, case_id, note_id, body.body, body.kind, body.resolved, body.evidence_refs)
        except Exception as exc:
            raise _err(exc)

    @app.delete("/api/cases/{case_id}/notes/{note_id}")
    def note_delete(case_id: str, note_id: str, conn=Depends(get_db)) -> dict[str, Any]:
        try:
            case_svc.delete_note(conn, case_id, note_id)
            return {"ok": True}
        except Exception as exc:
            raise _err(exc)

    @app.get("/api/references")
    def refs(case_id: str | None = None, conn=Depends(get_db)) -> list[dict[str, Any]]:
        q = "SELECT * FROM reference_identities WHERE case_id IS NULL" + (" OR case_id=?" if case_id else "")
        return [dict(r) for r in conn.execute(q, (case_id,) if case_id else ())]

    @app.post("/api/references")
    def ref_add(body: ReferenceIn, conn=Depends(get_db)) -> dict[str, Any]:
        try:
            return case_svc.add_reference(conn, body.case_id, body.display_name, body.email)
        except Exception as exc:
            raise _err(exc)

    @app.delete("/api/references/{ref_id}")
    def ref_delete(ref_id: str, conn=Depends(get_db)) -> dict[str, Any]:
        try:
            case_svc.delete_reference(conn, ref_id)
            return {"ok": True}
        except Exception as exc:
            raise _err(exc)

    # ---------------- reports
    @app.get("/api/cases/{case_id}/report")
    def report_view(case_id: str, conn=Depends(get_db)) -> dict[str, Any]:
        return {"latest": report_svc.latest(conn, case_id), "revisions": report_svc.list_revisions(conn, case_id)}

    @app.post("/api/cases/{case_id}/report/drafts")
    def report_draft(case_id: str, conn=Depends(get_db)) -> dict[str, Any]:
        try:
            return report_svc.new_draft(conn, case_id)
        except Exception as exc:
            raise _err(exc)

    @app.get("/api/reports/revisions/{rev_id}")
    def report_rev(rev_id: str, conn=Depends(get_db)) -> dict[str, Any]:
        try:
            return report_svc.get_revision(conn, rev_id)
        except Exception as exc:
            raise _err(exc)

    @app.patch("/api/reports/revisions/{rev_id}")
    def report_edit(rev_id: str, body: AnalystFields, conn=Depends(get_db)) -> dict[str, Any]:
        try:
            return report_svc.update_draft(conn, rev_id, body.model_dump(exclude_none=True))
        except Exception as exc:
            raise _err(exc)

    @app.post("/api/reports/revisions/{rev_id}/review")
    def report_review(rev_id: str, body: ReviewIn, conn=Depends(get_db)) -> dict[str, Any]:
        try:
            return report_svc.mark_reviewed(conn, rev_id, body.reviewer)
        except Exception as exc:
            raise _err(exc)

    @app.get("/api/reports/revisions/{rev_id}/pdf")
    def report_pdf(rev_id: str, conn=Depends(get_db)) -> Response:
        try:
            rev = report_svc.get_revision(conn, rev_id)
        except Exception as exc:
            raise _err(exc)

        def loader(art_id: str) -> bytes | None:
            a = conn.execute("SELECT stored_name FROM sandbox_artifacts WHERE id=?", (art_id,)).fetchone()
            return evidence.read_bytes(a["stored_name"], kind="artifacts") if a else None

        if rev.get("pdf_stored_name"):
            pdf = evidence.read_bytes(rev["pdf_stored_name"], kind="reports")
        else:
            pdf = render_pdf(rev, loader)
            stored = evidence.store_bytes(pdf, kind="reports", suffix=".pdf")
            conn.execute("UPDATE report_revisions SET pdf_stored_name=?, pdf_sha256=? WHERE id=?", (stored, evidence.sha256_bytes(pdf), rev_id))
        case_id = rev["content"]["generated"]["case"]["id"]
        tag = "reviewed" if rev["status"] == "reviewed" else "DRAFT"
        return Response(pdf, media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="NEMSEC_{case_id}_rev{rev["revision"]}_{tag}.pdf"'})

    # ---------------- demo dataset loader
    @app.post("/api/demo/load-samples")
    def load_samples(conn=Depends(get_db)) -> dict[str, Any]:
        sample_dir = REPO_ROOT / "samples" / "emails"
        files = sorted(sample_dir.glob("*.eml"))
        if not files:
            raise HTTPException(404, "No sample emails found. Run: python samples/build_samples.py")
        case = case_svc.create_case(conn, "Demo: synthetic phishing dataset",
                                    "Synthetic samples bundled with the workbench. No real credentials, destinations or payloads.")
        case_svc.add_reference(conn, case["id"], "Adaeze Okafor (CFO)", "adaeze.okafor@contoso-demo.example")
        results = [services.import_email(conn, f.read_bytes(), f.name, case["id"]) for f in files]
        return {"case_id": case["id"], "imported": results}

    @app.exception_handler(sqlite3.Error)
    async def db_error(_request: Request, exc: sqlite3.Error) -> JSONResponse:
        log.error("database error: %s", exc.__class__.__name__)
        return JSONResponse({"detail": "Database error"}, status_code=500)


app = create_app()


if __name__ == "__main__":
    import uvicorn

    s = get_settings()
    if s.host not in ("127.0.0.1", "localhost", "::1"):
        log.warning("Binding to %s exposes evidence to the network. This is not recommended.", s.host)
    uvicorn.run("app.main:app", host=s.host, port=s.port, reload=False)
