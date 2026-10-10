"""PDF export (ReportLab). NEMSEC branded.

Every piece of text from evidence is XML-escaped before it reaches ReportLab's
mini-markup, so email content cannot inject markup into the report.
"""
from __future__ import annotations

import io
import os
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (Image, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

REPO_ROOT = Path(__file__).resolve().parents[3]
BRAND = "NEMSEC"
BRAND_URL = "nemsec.com.ng"
INK = colors.HexColor("#111418")
MUTED = colors.HexColor("#5b6470")
ACCENT = colors.HexColor("#0f6e5a")
WARN = colors.HexColor("#9a3412")
RULE = colors.HexColor("#d6dbe1")
ASSESSMENT_LABELS = {
    "undetermined": "Undetermined", "likely_benign": "Likely benign", "suspicious": "Suspicious",
    "likely_malicious": "Likely malicious", "confirmed_malicious": "Confirmed malicious",
}

_FONT = "Helvetica"
_FONT_BOLD = "Helvetica-Bold"
_MONO = "Courier"


def _register_fonts() -> None:
    """Prefer a Unicode TTF so non-Latin text (e.g. look-alike domains) renders instead of boxes."""
    global _FONT, _FONT_BOLD
    candidates = [
        ("C:/Windows/Fonts/segoeui.ttf", "C:/Windows/Fonts/segoeuib.ttf"),
        ("C:/Windows/Fonts/arial.ttf", "C:/Windows/Fonts/arialbd.ttf"),
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
        ("/Library/Fonts/Arial Unicode.ttf", "/Library/Fonts/Arial Unicode.ttf"),
    ]
    for reg, bold in candidates:
        if os.path.exists(reg) and os.path.exists(bold):
            try:
                pdfmetrics.registerFont(TTFont("PBSans", reg))
                pdfmetrics.registerFont(TTFont("PBSans-Bold", bold))
                _FONT, _FONT_BOLD = "PBSans", "PBSans-Bold"
                return
            except Exception:
                continue


_register_fonts()


def logo_path() -> Path | None:
    p = Path(os.environ.get("PHB_LOGO_PATH", str(REPO_ROOT / "branding" / "nemsec-logo.png")))
    return p if p.exists() else None


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    s = {
        "title": ParagraphStyle("t", parent=base["Title"], fontName=_FONT_BOLD, fontSize=20, leading=24, textColor=INK, alignment=TA_LEFT, spaceAfter=4),
        "h1": ParagraphStyle("h1", parent=base["Heading1"], fontName=_FONT_BOLD, fontSize=13.5, leading=17, textColor=INK, spaceBefore=12, spaceAfter=6),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontName=_FONT_BOLD, fontSize=11, leading=14, textColor=INK, spaceBefore=8, spaceAfter=3),
        "body": ParagraphStyle("b", parent=base["BodyText"], fontName=_FONT, fontSize=9.2, leading=12.6, textColor=INK),
        "small": ParagraphStyle("s", parent=base["BodyText"], fontName=_FONT, fontSize=8, leading=10.4, textColor=MUTED),
        "mono": ParagraphStyle("m", parent=base["BodyText"], fontName=_MONO, fontSize=7.6, leading=9.6, textColor=INK, wordWrap="CJK"),
        "label": ParagraphStyle("l", parent=base["BodyText"], fontName=_FONT_BOLD, fontSize=8, leading=10.4, textColor=MUTED),
        "banner": ParagraphStyle("bn", parent=base["BodyText"], fontName=_FONT_BOLD, fontSize=9, leading=12, textColor=WARN),
    }
    return s


def _p(text: Any, style: ParagraphStyle) -> Paragraph:
    t = "" if text is None else str(text)
    return Paragraph(escape(t).replace("\n", "<br/>"), style)


def _kv_table(rows: list[tuple[str, Any]], st: dict[str, ParagraphStyle], mono_keys: set[str] = frozenset()) -> Table:
    data = [[_p(k, st["label"]), _p(v if v not in (None, "") else "— not present —", st["mono"] if k in mono_keys else st["body"])] for k, v in rows]
    t = Table(data, colWidths=[38 * mm, None])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.3, RULE),
                           ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    return t


def _grid(header: list[str], rows: list[list[Any]], st: dict[str, ParagraphStyle], widths: list[float | None], mono_cols: set[int] = frozenset()) -> Table:
    data = [[_p(h, st["label"]) for h in header]]
    for r in rows:
        data.append([_p(c, st["mono"] if i in mono_cols else st["body"]) for i, c in enumerate(r)])
    t = Table(data, colWidths=widths, repeatRows=1)
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, 0), 0.8, INK),
                           ("LINEBELOW", (0, 1), (-1, -1), 0.3, RULE), ("TOPPADDING", (0, 0), (-1, -1), 3),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    return t


def render_pdf(revision: dict[str, Any], artifact_loader=None) -> bytes:
    content = revision["content"]
    gen, an = content["generated"], content["analyst"]
    is_draft = revision["status"] != "reviewed"
    st = _styles()
    buf = io.BytesIO()
    case = gen["case"]
    footer_left = f"{BRAND} · {BRAND_URL}"
    footer_mid = f"{case['id']} · Revision {revision['revision']} · {'DRAFT — NOT REVIEWED' if is_draft else 'Reviewed by ' + (revision.get('reviewer') or '')}"
    logo = logo_path()

    def on_page(canvas, doc) -> None:
        canvas.saveState()
        w, h = A4
        canvas.setFillColor(INK)
        canvas.rect(0, h - 14 * mm, w, 14 * mm, stroke=0, fill=1)
        x = 15 * mm
        if logo:
            try:
                # White tile behind the black mark so it reads on the dark header band (same as the UI rail).
                canvas.setFillColor(colors.white)
                canvas.roundRect(x, h - 12 * mm, 10 * mm, 10 * mm, 1.2 * mm, stroke=0, fill=1)
                canvas.drawImage(str(logo), x + 0.8 * mm, h - 11.2 * mm, width=8.4 * mm, height=8.4 * mm, mask="auto",
                                 preserveAspectRatio=True)
                x += 13 * mm
            except Exception:
                pass
        canvas.setFillColor(colors.white)
        canvas.setFont(_FONT_BOLD, 11)
        canvas.drawString(x, h - 8.6 * mm, BRAND)
        canvas.setFont(_FONT, 8.5)
        canvas.drawString(x + canvas.stringWidth(BRAND, _FONT_BOLD, 11) + 4 * mm, h - 8.6 * mm, "Phishing Investigation Report")
        canvas.drawRightString(w - 15 * mm, h - 8.6 * mm, "CONFIDENTIAL")
        canvas.setFillColor(MUTED)
        canvas.setFont(_FONT, 7.5)
        canvas.drawString(15 * mm, 9 * mm, footer_left)
        canvas.drawCentredString(w / 2, 9 * mm, footer_mid)
        canvas.drawRightString(w - 15 * mm, 9 * mm, f"Page {doc.page}")
        if is_draft:
            canvas.setFillColor(colors.Color(0.6, 0.2, 0.05, alpha=0.08))
            canvas.setFont(_FONT_BOLD, 64)
            canvas.translate(w / 2, h / 2)
            canvas.rotate(35)
            canvas.drawCentredString(0, 0, "DRAFT")
        canvas.restoreState()

    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=22 * mm, bottomMargin=16 * mm,
                            title=f"{case['title']} — {case['id']}", author=an.get("author") or BRAND, subject="Phishing investigation report",
                            creator=f"{BRAND} Phishing Investigation Workbench")
    flow: list[Any] = []
    flow.append(_p(case["title"], st["title"]))
    flow.append(_p(f"Case {case['id']} · Report revision {revision['revision']} · Evidence snapshot {gen['snapshot_at']}", st["small"]))
    if is_draft:
        flow.append(Spacer(1, 4))
        flow.append(_p("DRAFT — this revision has not been reviewed. Do not rely on it as a final assessment.", st["banner"]))
    else:
        flow.append(_p(f"Reviewed by {revision.get('reviewer')} at {revision.get('reviewed_at')}", st["small"]))
    flow.append(Spacer(1, 6))
    flow.append(_p("How to read this report: sections marked GENERATED are observations recorded by the tool and inferences made "
                   "by its rules. Sections marked ANALYST are written by the investigator. Rule findings are indicators, not "
                   "verdicts; no automatic score is used.", st["small"]))

    # 1. Summary (analyst)
    flow.append(_p("1. Case summary  [ANALYST]", st["h1"]))
    flow.append(_p(an.get("summary") or "— not written —", st["body"]))
    if case.get("description"):
        flow.append(Spacer(1, 4))
        flow.append(_p("Case description: " + case["description"], st["small"]))

    flow.append(_p("2. Analyst assessment  [ANALYST]", st["h1"]))
    flow.append(_kv_table([("Assessment", ASSESSMENT_LABELS.get(an.get("assessment"), an.get("assessment"))),
                           ("Rationale", an.get("assessment_rationale")), ("Author", an.get("author"))], st))
    notes = an.get("notes") or {}
    for key, title in (("facts", "Confirmed facts"), ("interpretations", "Interpretations"), ("questions", "Unanswered questions")):
        items = notes.get(key) or []
        if items:
            flow.append(_p(title, st["h2"]))
            for n in items:
                refs = f"  [refs: {', '.join(n['refs'])}]" if n.get("refs") else ""
                resolved = "  (resolved)" if n.get("resolved") and key == "questions" else ""
                flow.append(_p(f"• {n['body']}{refs}{resolved}", st["body"]))

    # 3. Scope
    flow.append(_p("3. Scope and evidence  [GENERATED]", st["h1"]))
    flow.append(_p("SHA-256 values confirm the preserved bytes are unchanged since import; they do not prove authenticity.", st["small"]))
    flow.append(_grid(["Evidence ID", "Kind / source", "Filename", "SHA-256", "Bytes", "Imported (UTC)", "Integrity"],
                      [[e["id"], e["kind"] + (f"\n{e['parent_id']} part {e['mime_part_ref']}" if e.get("parent_id") else ""),
                        e["filename"], e["sha256"], e["size_bytes"], (e["imported_at"] or "")[:16].replace("T", " "),
                        "OK" if e["integrity_ok_at_snapshot"] else "MISMATCH"]
                       for e in gen["scope"]], st, [24 * mm, 26 * mm, 32 * mm, 44 * mm, 14 * mm, 22 * mm, 18 * mm], {0, 3}))

    # 4. Email metadata
    flow.append(_p("4. Email metadata  [GENERATED — header values as written in the file]", st["h1"]))
    for em in gen["emails"]:
        flow.append(_p(f"{em['id']} — parse status: {em['parse_status']}", st["h2"]))
        flow.append(_kv_table([("Subject", em["subject"]), ("From", em["from"]), ("Reply-To", em["reply_to"]),
                               ("Return-Path", em["return_path"]), ("To", em["to"]), ("Cc", em["cc"]), ("Message-ID", em["message_id"]),
                               ("Date (raw)", em["date_raw"]), ("Date (UTC)", em["date_utc"]), ("Received hops", em["received_hops"]),
                               ("Auth. claims", "; ".join(f"{a['authserv_id']}: {', '.join(a['methods'])}" for a in em["auth_claims"]) or None)],
                              st, {"Message-ID", "From", "Reply-To", "Return-Path"}))
        if em["auth_claims"]:
            flow.append(_p("Authentication-Results are reported claims by the named server and were not verified by this tool.", st["small"]))
        if em["warnings"] or em["errors"]:
            flow.append(_p("Parser warnings/errors: " + " | ".join(em["errors"] + em["warnings"])[:3000], st["small"]))

    # 5/6. Findings
    email_f = [f for f in gen["findings"] if f["category"] not in ("attachments",)]
    att_f = [f for f in gen["findings"] if f["category"] == "attachments"]

    def finding_block(f: dict[str, Any]) -> KeepTogether:
        parts = [
            _p(f"{f['name']}  ·  {f['category']}  ·  indicator weight: {f['confidence'].upper()}  ·  analyst review: {f['review_status'].upper()}", st["h2"]),
            _p(f"Finding {f['id']} · rule {f['rule_id']} · evidence refs: {', '.join(f['evidence_refs'])}", st["small"]),
            _p(f["explanation"], st["body"]),
        ]
        if f["evidence"]:
            parts.append(_kv_table([(e.get("label", ""), e.get("value")) for e in f["evidence"]], st, {e.get("label", "") for e in f["evidence"]}))
        if f.get("uncertainty"):
            parts.append(_p("Uncertainty: " + f["uncertainty"], st["small"]))
        if f.get("benign"):
            parts.append(_p("Possible benign explanations: " + " / ".join(f["benign"]), st["small"]))
        if f.get("analyst_comment"):
            parts.append(_p("Analyst comment: " + f["analyst_comment"], st["body"]))
        parts.append(Spacer(1, 4))
        return KeepTogether(parts)

    flow.append(_p("5. Email findings  [GENERATED rule inferences + ANALYST review status]", st["h1"]))
    if not email_f:
        flow.append(_p("No email-level rule findings were selected for this report. Absence of findings is not evidence of safety.", st["body"]))
    for f in email_f:
        flow.append(finding_block(f))

    flow.append(_p("6. Attachment inventory  [GENERATED]", st["h1"]))
    if not gen["attachments"]:
        flow.append(_p("No attachments in scope.", st["body"]))
    else:
        flow.append(_grid(["ID", "Filename", "Identified as", "SHA-256", "Bytes", "Static analysis"],
                          [[a["id"], a["filename"], a["detected"], a["sha256"], a["size_bytes"], a["static_status"]] for a in gen["attachments"]],
                          st, [22 * mm, 32 * mm, 32 * mm, 48 * mm, 14 * mm, 24 * mm], {0, 3}))
        for a in gen["attachments"]:
            if a["limitations"]:
                flow.append(_p(f"{a['id']} limitations: " + " | ".join(a["limitations"]), st["small"]))

    flow.append(_p("7. Static analysis findings  [GENERATED]", st["h1"]))
    if not att_f:
        flow.append(_p("No attachment findings selected. Where analysis was partial, unsupported or encrypted, see section 10.", st["body"]))
    for f in att_f:
        flow.append(finding_block(f))

    flow.append(_p("8. Sandbox observations  [GENERATED]", st["h1"]))
    if not gen["sandbox"]:
        flow.append(_p("No attachment in scope was submitted to a sandbox.", st["body"]))
    for j in gen["sandbox"]:
        title = f"{j['id']} — {j['attachment_id']} — {j['engine']} — state: {j['state']}"
        flow.append(_p(title, st["h2"]))
        if j["is_demo"]:
            flow.append(_p("DEMO — SYNTHETIC DATA. These are not observations of the attachment. Nothing was executed.", st["banner"]))
        flow.append(_kv_table([("Submitted", f"{j['submitted_at']} by {j['submitted_by']}"), ("Finished", j["finished_at"]),
                               ("Execution outcome", j["execution_outcome"]), ("Post-run reset", j["reset_status"]),
                               ("Detail", j["state_detail"])], st))
        flow.append(_p("A completed run means execution finished. It does not mean the file is safe.", st["small"]))
        o = j.get("observations")
        if o:
            rows = [("Duration (s)", o.get("duration_s")), ("Processes", "\n".join(o["processes"]) or "none recorded"),
                    ("Files created", "\n".join(o["files_created"]) or "none recorded"),
                    ("Files deleted", "\n".join(o["files_deleted"]) or "none recorded"),
                    ("Registry written", "\n".join(o["registry_set"]) or "none recorded"),
                    ("Persistence-related", "\n".join(o["persistence"]) or "none recorded"),
                    ("DNS queries", "\n".join(str(d) for d in o["dns"]) or "none recorded"),
                    ("Connections", "\n".join(o["connections"]) or "none recorded"),
                    ("Engine signatures (engine inferences)", "\n".join(o["engine_signatures"]) or "none"),
                    ("Engine errors", "\n".join(o["errors"]) or "none")]
            flow.append(_kv_table(rows, st, {"Processes", "Files created", "Files deleted", "Registry written", "DNS queries", "Connections"}))
        cov = j.get("coverage")
        if cov:
            flow.append(_p("Coverage limits: " + " | ".join(cov.get("limitations", [])), st["small"]))
        if artifact_loader:
            for shot in j.get("screenshots", [])[:2]:
                data = artifact_loader(shot["id"])
                if data:
                    try:
                        img = Image(io.BytesIO(data))
                        if img.imageWidth < 64 or img.imageHeight < 64:
                            flow.append(_p(f"Screenshot {shot['id']} is a placeholder too small to display.", st["small"]))
                            continue
                        ratio = img.imageHeight / float(img.imageWidth or 1)
                        img.drawWidth = min(120 * mm, 100 * mm / ratio)
                        img.drawHeight = img.drawWidth * ratio
                        flow.append(img)
                        flow.append(_p(("DEMO placeholder — " if j["is_demo"] else "") + f"Screenshot {shot['id']}: {shot['label']}", st["small"]))
                    except Exception:
                        flow.append(_p(f"Screenshot {shot['id']} could not be rendered.", st["small"]))

    flow.append(_p("9. Actions and recommendations  [ANALYST]", st["h1"]))
    flow.append(_kv_table([("Actions taken", an.get("actions")), ("Recommendations", an.get("recommendations"))], st))

    flow.append(_p("10. Limitations and what could not be established", st["h1"]))
    flow.append(_p("Generated:", st["label"]))
    for item in gen["could_not_establish"]:
        flow.append(_p("• " + item, st["body"]))
    flow.append(Spacer(1, 4))
    flow.append(_p("Analyst:", st["label"]))
    flow.append(_p(an.get("limitations") or "— none added —", st["body"]))
    open_q = [q for q in (notes.get("questions") or []) if not q.get("resolved")]
    if open_q:
        flow.append(_p("Open questions:", st["label"]))
        for q in open_q:
            flow.append(_p("• " + q["body"], st["body"]))

    doc.build(flow, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()
