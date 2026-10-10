"""End-to-end through the HTTP API: upload -> analysis -> case -> review -> sandbox (demo) -> reviewed PDF."""
import io
import time

from pypdf import PdfReader

from app.db import connect
from app.worker import drain

from .conftest import sample


def test_upload_to_reviewed_pdf(client, monkeypatch):
    monkeypatch.setenv("PHB_SANDBOX_MODE", "demo")
    from app.config import reset_settings

    reset_settings()
    case = client.post("/api/cases", json={"title": "E2E: courier lure", "description": "Reported via phish button"}).json()
    up = client.post("/api/emails/import", data={"case_id": case["id"]},
                     files={"file": ("07.eml", sample("07_archive_with_script.eml"), "message/rfc822")}).json()
    ev = up["evidence_id"]
    assert up["parse_status"] == "parsed"
    up2 = client.post("/api/emails/import", data={"case_id": case["id"]},
                      files={"file": ("08.eml", sample("08_sandbox_verification.eml"), "message/rfc822")}).json()

    conn = connect()
    drain(conn)

    detail = client.get(f"/api/emails/{ev}").json()
    assert detail["attachments"][0]["static_status"] == "complete"
    assert {f["rule_id"] for f in detail["findings"]} >= {"archive_executable", "archive_unsafe_paths"}
    assert client.get(f"/api/evidence/{ev}/verify").json()["ok"] is True

    c = client.get(f"/api/cases/{case['id']}").json()
    fid = next(f["id"] for f in c["findings"] if f["rule_id"] == "archive_executable")
    assert client.patch(f"/api/cases/{case['id']}/findings/{fid}", json={"review_status": "relevant", "analyst_comment": "batch file in zip"}).status_code == 200
    client.post(f"/api/cases/{case['id']}/notes", json={"kind": "fact", "body": "Recipient reported before opening.", "evidence_refs": [ev]})
    client.post(f"/api/cases/{case['id']}/notes", json={"kind": "question", "body": "Were other mailboxes targeted?"})

    exe = next(a for a in client.get(f"/api/emails/{up2['evidence_id']}").json()["attachments"] if a["detected_type"] == "pe")
    refused = client.post(f"/api/attachments/{exe['id']}/sandbox", json={"analyst": "J", "confirm": False})
    assert refused.status_code == 409
    job = client.post(f"/api/attachments/{exe['id']}/sandbox", json={"analyst": "J. Analyst", "confirm": True, "case_id": case["id"]}).json()
    for _ in range(30):
        drain(conn)
        j = client.get(f"/api/sandbox/jobs/{job['id']}").json()
        if j["state"] == "completed" and j["reset_status"] == "verified":
            break
        conn.execute("UPDATE jobs SET run_after='2000-01-01T00:00:00+00:00' WHERE status='queued'")
        time.sleep(0.5)
    assert j["is_demo"] is True and j["observations"]["is_demo"] is True

    draft = client.post(f"/api/cases/{case['id']}/report/drafts").json()
    assert draft["status"] == "draft"
    assert client.post(f"/api/reports/revisions/{draft['id']}/review", json={"reviewer": "Lead"}).status_code == 400
    client.patch(f"/api/reports/revisions/{draft['id']}", json={
        "summary": "Courier-themed lure delivering a batch script inside a ZIP.", "assessment": "likely_malicious",
        "assessment_rationale": "Script disguised as PDF inside archive; unsafe path entry.", "actions": "Blocked sender domain.",
        "recommendations": "Search mail logs for same subject.", "author": "J. Analyst"})
    reviewed = client.post(f"/api/reports/revisions/{draft['id']}/review", json={"reviewer": "Lead Reviewer"}).json()
    assert reviewed["status"] == "reviewed"

    pdf = client.get(f"/api/reports/revisions/{draft['id']}/pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    assert "reviewed" in pdf.headers["content-disposition"]
    text = "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf.content)).pages)
    for needle in ("Courier-themed lure", "Likely malicious", "Reviewed by Lead Reviewer", ev, fid, "DEMO", "Were other mailboxes targeted?"):
        assert needle in text, needle
    # the stored PDF is hashed and re-served identically
    again = client.get(f"/api/reports/revisions/{draft['id']}/pdf")
    assert again.content == pdf.content
    hist = client.get(f"/api/cases/{case['id']}/history").json()
    assert {"reviewed", "submitted", "imported"} <= {h["action"] for h in hist}
    conn.close()
