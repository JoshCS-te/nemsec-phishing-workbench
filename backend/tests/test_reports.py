import io

import pytest
from pypdf import PdfReader

from app import cases, services
from app.reports import builder
from app.reports.pdf import render_pdf
from app.worker import drain

from .conftest import sample


def pdf_text(data: bytes) -> str:
    return "\n".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(data)).pages)


@pytest.fixture()
def case_with_email(conn):
    case = cases.create_case(conn, "Invoice with fake PDF", "Reported by accounts team")
    ev = services.import_email(conn, sample("04_misleading_extension.eml"), "04.eml", case["id"])["evidence_id"]
    drain(conn)
    return case["id"], ev


def test_case_lifecycle_and_history(conn, case_with_email):
    cid, _ = case_with_email
    cases.update_case(conn, cid, status="closed")
    with pytest.raises(cases.Invalid):
        cases.add_note(conn, cid, "fact", "x", [])
    cases.update_case(conn, cid, status="open")
    actions = [h["action"] for h in cases.history(conn, cid)]
    assert {"created", "imported", "closed", "reopened"} <= set(actions)


def test_notes_validate_evidence_references(conn, case_with_email):
    cid, ev = case_with_email
    n = cases.add_note(conn, cid, "fact", "User did not open the attachment.", [ev])
    assert n["evidence_refs"] == [ev]
    with pytest.raises(cases.Invalid):
        cases.add_note(conn, cid, "fact", "bad ref", ["EV-NOTREAL"])


def test_report_separates_generated_and_analyst_content(conn, case_with_email):
    cid, ev = case_with_email
    fid = conn.execute("SELECT id FROM findings WHERE rule_id='extension_mismatch'").fetchone()[0]
    cases.review_finding(conn, cid, fid, "relevant", "Confirmed: PE disguised as PDF", None)
    cases.add_note(conn, cid, "question", "Did anyone else receive this?", [])
    draft = builder.new_draft(conn, cid)
    gen, an = draft["content"]["generated"], draft["content"]["analyst"]
    f = next(x for x in gen["findings"] if x["id"] == fid)
    assert f["review_status"] == "relevant" and ev in f["evidence_refs"]
    att = gen["attachments"][0]
    assert att["sha256"] and att["static_status"] == "complete"
    assert any("not verified" in c for c in gen["could_not_establish"])
    assert any("no completed live sandbox run" in c for c in gen["could_not_establish"])
    assert an["notes"]["questions"][0]["body"].startswith("Did anyone")
    assert draft["status"] == "draft"
    # Analyst cannot write into the generated half through the edit API.
    updated = builder.update_draft(conn, draft["id"], {"summary": "Fake invoice.", "generated": "tamper"})
    assert updated["content"]["generated"]["findings"] == gen["findings"]


def test_excluded_findings_and_evidence_leave_the_report(conn, case_with_email):
    cid, ev = case_with_email
    fid = conn.execute("SELECT id FROM findings WHERE rule_id='urgent_sensitive_request'").fetchone()[0]
    cases.review_finding(conn, cid, fid, "benign", "normal invoice wording", False)
    att = conn.execute("SELECT id FROM evidence WHERE parent_id=?", (ev,)).fetchone()[0]
    cases.set_evidence_selection(conn, cid, att, False)
    gen = builder.new_draft(conn, cid)["content"]["generated"]
    assert fid not in {f["id"] for f in gen["findings"]}
    assert not gen["attachments"]
    assert not any(f["subject_evidence_id"] if "subject_evidence_id" in f else False for f in gen["findings"])


def test_review_freezes_and_new_edit_creates_revision(conn, case_with_email):
    cid, _ = case_with_email
    d1 = builder.new_draft(conn, cid)
    with pytest.raises(cases.Invalid):
        builder.mark_reviewed(conn, d1["id"], "Analyst")  # summary/rationale missing
    builder.update_draft(conn, d1["id"], {"summary": "Disguised executable.", "assessment": "likely_malicious",
                                          "assessment_rationale": "PE content behind a .pdf name.", "author": "J. Analyst"})
    r1 = builder.mark_reviewed(conn, d1["id"], "Lead Reviewer")
    assert r1["status"] == "reviewed"
    with pytest.raises(cases.Invalid):
        builder.update_draft(conn, d1["id"], {"summary": "changed"})
    d2 = builder.new_draft(conn, cid)
    assert d2["revision"] == 2 and d2["status"] == "draft"
    assert d2["content"]["analyst"]["summary"] == "Disguised executable."  # carried forward
    revs = builder.list_revisions(conn, cid)
    assert [(r["revision"], r["status"]) for r in revs] == [(2, "draft"), (1, "reviewed")]


def test_pdf_marks_drafts_and_contains_evidence(conn, case_with_email):
    cid, ev = case_with_email
    d = builder.new_draft(conn, cid)
    builder.update_draft(conn, d["id"], {"summary": "Summary <b>with markup</b> & ampersand", "assessment_rationale": "R"})
    draft_pdf = render_pdf(builder.get_revision(conn, d["id"]))
    assert draft_pdf.startswith(b"%PDF")
    t = pdf_text(draft_pdf)
    assert "DRAFT" in t and ev in t and "NEMSEC" in t and "nemsec.com.ng" in t
    assert "<b>with markup</b>" in t  # escaped, shown literally rather than interpreted
    sha = conn.execute("SELECT sha256 FROM evidence WHERE parent_id=?", (ev,)).fetchone()[0]
    assert sha[:20] in t.replace("\n", "")
    reviewed = builder.mark_reviewed(conn, d["id"], "Lead Reviewer")
    t2 = pdf_text(render_pdf(reviewed))
    assert "Reviewed by Lead Reviewer" in t2 and "DRAFT — this revision" not in t2


def test_sandbox_run_from_another_case_appears_in_report(conn, case_with_email, monkeypatch):
    from app.config import reset_settings
    from app.sandbox import service as sb
    from app.sandbox.demo import DemoAdapter

    cid, ev = case_with_email
    other = cases.create_case(conn, "other")
    cases.attach_evidence(conn, other["id"], ev)
    monkeypatch.setenv("PHB_SANDBOX_MODE", "demo")
    reset_settings()
    sb.set_adapter_for_tests(DemoAdapter(run_seconds=0))
    att = conn.execute("SELECT id FROM evidence WHERE parent_id=?", (ev,)).fetchone()[0]
    job = sb.submit(conn, att, "a", confirm=True, case_id=other["id"])
    gen = builder.new_draft(conn, cid)["content"]["generated"]
    assert [s["id"] for s in gen["sandbox"]] == [job["id"]]
    assert job["id"] in {j["id"] for j in cases.get_case(conn, cid)["sandbox_jobs"]}
