"""Explainable rule-based findings.

A finding is an *inference by a rule* from observed values. Each one carries
the exact values it was based on, how much weight it deserves on its own,
what is uncertain about it, and ordinary reasons it might be benign.

There is deliberately no overall score: indicators are weighed by the analyst.
``confidence`` describes how strongly the indicator, taken alone, is associated
with malicious mail — never a verdict on the message.
"""
from __future__ import annotations

import difflib
import re
import unicodedata
from typing import Any

from .filetype import EXECUTABLE_EXTENSIONS, SCRIPT_EXTENSIONS
from .urls import registrable_domain

URGENCY_TERMS = [
    "urgent", "urgently", "immediately", "immediate action", "within 24 hours", "within 48 hours", "today only",
    "act now", "final notice", "final warning", "last chance", "account will be suspended", "suspended",
    "will be closed", "deactivated", "expire", "expires today", "as soon as possible", "asap", "time-sensitive",
    "right away", "before end of day",
]
SENSITIVE_TERMS = {
    "credentials": ["password", "passcode", "verify your account", "confirm your account", "login", "log in", "sign in",
                    "username", "credentials", "one-time code", "otp", "pin", "security code", "mfa code", "2fa"],
    "payment": ["wire transfer", "bank transfer", "bank details", "account number", "routing number", "iban", "swift",
                "payment", "pay the invoice", "outstanding invoice", "gift card", "itunes card", "crypto", "bitcoin",
                "change of bank", "new bank account"],
    "sensitive_information": ["social security", "ssn", "bvn", "nin", "date of birth", "passport", "tax id",
                              "w-2", "payroll", "credit card", "card number", "cvv"],
}


def _f(rule_id: str, name: str, category: str, explanation: str, evidence: list[dict[str, Any]], confidence: str,
       uncertainty: str, benign: list[str], subject: str | None = None) -> dict[str, Any]:
    return {
        "rule_id": rule_id, "name": name, "category": category, "explanation": explanation, "evidence": evidence,
        "confidence": confidence, "uncertainty": uncertainty, "benign": benign, "subject_evidence_id": subject,
    }


def _norm_name(s: str | None) -> str:
    if not s:
        return ""
    s = unicodedata.normalize("NFKC", s).casefold()
    s = re.sub(r"[\"'`.,()\[\]<>]", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def _first_addr(block: dict[str, Any]) -> dict[str, Any] | None:
    addrs = block.get("addresses") or []
    return addrs[0] if addrs and addrs[0].get("address") else None


def header_findings(parsed: dict[str, Any], references: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    frm = _first_addr(parsed.get("from", {}))
    rto = _first_addr(parsed.get("reply_to", {}))
    rpath = _first_addr(parsed.get("return_path", {}))

    if frm and rto and rto["address"].lower() != frm["address"].lower():
        same_org = registrable_domain(rto["domain"]) == registrable_domain(frm["domain"])
        out.append(_f(
            "reply_to_differs", "Reply-To differs from From", "sender",
            "Replies will go to a different address than the one shown as the sender."
            + ("" if same_org else " The Reply-To is on a different domain, so a reply would leave the sender's organisation."),
            [{"label": "From (raw header)", "value": parsed["from"]["raw"]},
             {"label": "Reply-To (raw header)", "value": parsed["reply_to"]["raw"]}],
            "low" if same_org else "medium",
            "Header values are as written in the file. The rule cannot tell whether the sender intended this.",
            ["Mailing lists, newsletters and ticketing systems often set Reply-To to a shared inbox.",
             "Assistants or shared mailboxes may send on behalf of someone else.",
             "Marketing platforms send From the brand and route replies to a vendor domain."],
        ))
    if frm and rpath and rpath["domain"] and frm["domain"] and registrable_domain(rpath["domain"]) != registrable_domain(frm["domain"]):
        out.append(_f(
            "return_path_differs", "Return-Path domain differs from From domain", "sender",
            "The envelope sender (where bounces go, and what SPF checks) is on a different domain from the visible From address.",
            [{"label": "From (raw header)", "value": parsed["from"]["raw"]},
             {"label": "Return-Path (raw header)", "value": parsed["return_path"]["raw"]}],
            "low",
            "Return-Path is normally written by the final receiving server, but in an uploaded file it may have been edited.",
            ["Very common for legitimate bulk mail sent through email service providers (bounce domains).",
             "Forwarding services and mailing lists rewrite the envelope sender."],
        ))
    # Display name contains a different email address
    if frm and frm.get("display_name"):
        embedded = re.findall(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+", frm["display_name"])
        others = [e for e in embedded if e.lower() != frm["address"].lower()]
        if others:
            out.append(_f(
                "display_name_has_other_address", "Display name contains a different email address", "impersonation",
                "The sender's display name contains an email address that is not the real sending address. Many mail "
                "clients show only the display name, so recipients may see the embedded address instead.",
                [{"label": "Display name", "value": frm["display_name"]}, {"label": "Actual address", "value": frm["address"]}],
                "medium",
                "Some legitimate systems include an original sender's address in the display name when relaying.",
                ["Relaying or 'on behalf of' systems sometimes format names this way."],
            ))
    # Impersonation vs analyst-provided reference identities
    if frm:
        shown = _norm_name(frm.get("display_name"))
        for ref in references:
            ref_name = _norm_name(ref.get("display_name"))
            if not ref_name or not shown:
                continue
            ratio = difflib.SequenceMatcher(None, shown, ref_name).ratio()
            contains = ref_name in shown or shown in ref_name
            if ratio < 0.85 and not contains:
                continue
            ref_email = (ref.get("email") or "").lower().strip()
            ref_domain = ref_email.rsplit("@", 1)[1] if "@" in ref_email else None
            addr = frm["address"].lower()
            if ref_email and addr == ref_email:
                continue
            same_domain = ref_domain and registrable_domain(frm["domain"]) == registrable_domain(ref_domain)
            out.append(_f(
                "display_name_impersonation", "Display name resembles a reference identity", "impersonation",
                f"The sender's display name {'matches' if ratio > 0.97 or shown == ref_name else 'closely resembles'} "
                f"the reference identity '{ref['display_name']}', but the sending address "
                f"{'is a different mailbox on the same domain' if same_domain else 'is not that identity’s known address'}.",
                [{"label": "From display name", "value": frm.get("display_name")},
                 {"label": "From address", "value": frm["address"]},
                 {"label": "Reference identity", "value": f"{ref['display_name']} <{ref.get('email') or 'no address recorded'}>"},
                 {"label": "Name similarity", "value": f"{ratio:.2f}"}],
                "medium" if same_domain else "high",
                "Similarity is text-based. Two real people can share a name; the reference list may be incomplete.",
                ["The person may be writing from a personal or new address.",
                 "A different person with the same or similar name.",
                 "The reference identity's address list may be out of date."],
            ))
    # Duplicate identity headers
    for key, label in (("from", "From"), ("subject", "Subject"), ("date", "Date")):
        all_raw = parsed.get(key, {}).get("all_raw") or []
        if len(all_raw) > 1:
            out.append(_f(
                f"duplicate_{key}", f"Multiple {label} headers", "structure",
                f"The message has {len(all_raw)} {label} headers. Different mail clients may display different ones, "
                "which can be used to show one value to filters and another to people.",
                [{"label": f"{label} #{i + 1}", "value": v} for i, v in enumerate(all_raw)],
                "medium" if key == "from" else "low",
                "Duplicate headers are also produced by buggy software.",
                ["Poorly written mailers and some forwarding tools duplicate headers."],
            ))
    # Authentication-Results claims
    for ar in parsed.get("authentication_results", []):
        fails = [m for m in ar["methods"] if m["method"] in ("spf", "dkim", "dmarc") and m["result"] in ("fail", "softfail", "permerror", "none")]
        if fails:
            out.append(_f(
                "auth_results_claim_fail", "Authentication-Results header reports a failure", "header_claims",
                "A header in the file states that one or more authentication checks did not pass. This is a reported "
                "claim by the server named in the header, not a check made by this tool.",
                [{"label": "Authentication-Results (raw)", "value": ar["raw"]}] +
                [{"label": f"{m['method'].upper()} reported", "value": m["result"]} for m in fails],
                "low",
                "Anyone handling the file could add or edit this header. Only a header added by a receiving server "
                "you trust is meaningful. Results reflect DNS at delivery time and cannot be re-checked now.",
                ["Forwarding and mailing lists commonly break SPF and sometimes DKIM.",
                 "Domains without published SPF/DMARC produce 'none'.",
                 "Misconfigured but legitimate senders fail authentication regularly."],
            ))
    return out


def url_findings(urls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for u in urls:
        codes = {w["code"]: w for w in u.get("warnings", [])}
        ev = [{"label": "Original URL (as extracted)", "value": u["original"], "ref": u.get("id")},
              {"label": "Source", "value": u["source"]}]
        if u.get("visible_text"):
            ev.append({"label": "Visible link text", "value": u["visible_text"]})
        if u.get("normalized_host"):
            ev.append({"label": "Destination host", "value": u["normalized_host"]})
        if "text_destination_mismatch" in codes:
            out.append(_f("link_text_mismatch", "Link text shows a different destination", "links",
                          codes["text_destination_mismatch"]["message"], ev, "medium",
                          "Domain comparison uses a built-in suffix list, not the full Public Suffix List.",
                          ["Click-tracking and link-protection services (e.g. marketing platforms, Safe Links) rewrite destinations.",
                           "Companies use separate domains for marketing or redirects."]))
        if "ip_host" in codes:
            out.append(_f("ip_destination", "Link points to an IP address", "links", codes["ip_host"]["message"], ev, "medium",
                          "Not visited; the IP's owner was not looked up.",
                          ["Internal tools, routers, printers and dev servers are often reached by IP."]))
        if "idn" in codes and codes["idn"]["weight"] == "notable":
            out.append(_f("idn_confusable", "Look-alike characters in link domain", "links", codes["idn"]["message"], ev, "medium",
                          "Script mixing is a strong signal for look-alike domains, but many legitimate non-English domains use non-Latin scripts.",
                          ["Legitimate internationalised domains for non-English organisations."]))
        if "dangerous_scheme" in codes:
            out.append(_f("dangerous_scheme", "Link uses a scheme that can run or open content", "links", codes["dangerous_scheme"]["message"], ev, "medium",
                          "The link was not followed; what it would do depends on the mail client.",
                          ["Some HTML emails use javascript:void(0) placeholders produced by editors."]))
        if "embedded_credentials" in codes:
            out.append(_f("url_userinfo", "Link has text before '@' in the host part", "links", codes["embedded_credentials"]["message"], ev, "medium",
                          "Valid URL syntax; rarely used legitimately in email links.",
                          ["FTP or internal links occasionally carry usernames."]))
        if not u.get("parse_ok", True):
            out.append(_f("malformed_url", "Malformed link", "links",
                          "; ".join(w["message"] for w in u["warnings"] if w["code"].startswith("malformed")) or "URL could not be parsed.",
                          ev, "low", "Malformed links can be deliberate (to evade filters) or simple mistakes.",
                          ["Typos, broken templates or encoding problems."]))
        if u["source"] == "html_form_action":
            out.append(_f("html_form", "Email body contains a form that submits data", "links",
                          "The HTML contains a form whose data would be sent to the address shown. Forms in email are a "
                          "common way to collect credentials without a separate web page.",
                          ev, "high", "The form was neutralised in preview and never submitted.",
                          ["Rare in legitimate mail; some surveys embed forms."]))
        if u["source"] == "html_meta_refresh":
            out.append(_f("meta_refresh", "HTML attempts automatic redirect", "links",
                          "The HTML contains a meta-refresh instruction that would navigate automatically if rendered in a browser.",
                          ev, "medium", "Blocked in preview.", ["Uncommon in legitimate email."]))
    return out


def attachment_findings(att_id: str, filename: str | None, static: dict[str, Any] | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if not static:
        return out
    det = static.get("detected") or {}
    ext_info = static.get("extension") or {}
    ev_base = [{"label": "Attachment", "value": f"{filename or '(no filename)'} [{att_id}]", "ref": att_id},
               {"label": "SHA-256", "value": static.get("sha256")}]
    if det:
        ev_base.append({"label": "Identified content", "value": f"{det.get('label')} ({det.get('type')})"})

    if ext_info.get("mismatch"):
        out.append(_f("extension_mismatch", "File extension does not match content", "attachments",
                      f"The name ends in '.{ext_info['extension']}' (expected {', '.join(ext_info['expected_types'])}), "
                      f"but the content was identified as {det.get('label')}.",
                      ev_base, "high" if det.get("family") in ("executable", "script") else "medium",
                      "Identification is by magic bytes and simple content checks; rare formats may be misidentified.",
                      ["Files renamed by users or systems (e.g. '.dat' exports).",
                       "Some tools save with a generic extension."], att_id))
    for note in ext_info.get("notes", []):
        if "Double extension" in note or "bidirectional" in note or "spaces" in note:
            out.append(_f("filename_deception", "Filename may hide its real type", "attachments", note,
                          ev_base + [{"label": "Raw filename", "value": filename}], "high",
                          "The filename is attacker-controlled text; the content identification is more reliable.",
                          ["Rarely benign; occasionally caused by systems appending extensions."], att_id))
    ext = (ext_info.get("extension") or "").lower()
    if det.get("family") in ("executable",) or ext in EXECUTABLE_EXTENSIONS:
        out.append(_f("executable_attachment", "Executable attachment", "attachments",
                      "The attachment is (or is named as) a program that runs when opened.",
                      ev_base, "high", "Being executable says nothing about what it does.",
                      ["Software vendors and IT staff sometimes send installers, though most organisations block this."], att_id))
    elif det.get("family") == "script" or ext in SCRIPT_EXTENSIONS or det.get("type") == "script_text":
        out.append(_f("script_attachment", "Script or shortcut attachment", "attachments",
                      "The attachment is a script or shortcut type that Windows can run directly when opened.",
                      ev_base, "high", "Content was read as text only, never run.",
                      ["Developers and administrators exchange scripts, usually not by email to non-technical staff."], att_id))
    if det.get("type") in ("html", "svg") and ext in ("html", "htm", "svg", "shtml"):
        out.append(_f("html_attachment", "HTML/SVG attachment", "attachments",
                      "HTML and SVG attachments open in a browser and can show a convincing local login page or run script.",
                      ev_base, "medium", "Content not rendered.",
                      ["Receipts, statements and exported reports are sometimes sent as HTML."], att_id))

    office = static.get("office") or {}
    macros = office.get("macros") or {}
    if macros.get("present"):
        auto = [k for k in macros.get("keywords", []) if k["type"] in ("AutoExec", "Suspicious")]
        out.append(_f("office_macros", "Document contains macros", "attachments",
                      "The document contains VBA macro code." + (f" {len(auto)} auto-run or suspicious keywords were found by static scan." if auto else ""),
                      ev_base + [{"label": "Macro modules", "value": ", ".join(m["name"] for m in macros.get("modules", [])) or "(names unavailable)"}]
                      + [{"label": f"{k['type']} keyword", "value": f"{k['keyword']} — {k['description']}"} for k in auto[:15]],
                      "high" if auto else "medium",
                      "Static keyword matching only; macros were not run. Obfuscated code can hide behaviour from this scan.",
                      ["Finance and operations teams use legitimate macro-enabled spreadsheets.",
                       "Older templates often contain harmless macros."], att_id))
    if office.get("external_relationships"):
        out.append(_f("office_external_reference", "Document references external content", "attachments",
                      "The document points to content outside the file, which Office may fetch when it opens (for example a remote template).",
                      ev_base + [{"label": f"External {r.get('type')}", "value": r.get("target")} for r in office["external_relationships"][:10]],
                      "medium", "Targets were not contacted.",
                      ["Hyperlinks and linked images in legitimate documents are also external relationships."], att_id))
    if office.get("embedded_objects"):
        out.append(_f("office_embedded_objects", "Document contains embedded objects", "attachments",
                      "The document embeds other files or OLE objects, which may themselves be executable.",
                      ev_base + [{"label": "Embedded", "value": ", ".join(office["embedded_objects"][:10])}], "low",
                      "Embedded objects were listed, not extracted.",
                      ["Charts, spreadsheets and images are commonly embedded."], att_id))
    pdf = static.get("pdf") or {}
    kc = pdf.get("keyword_counts") or {}
    active = {k: v for k, v in kc.items() if v and k in ("/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile", "/RichMedia", "/SubmitForm")}
    if active:
        out.append(_f("pdf_active_content", "PDF contains active-content keywords", "attachments",
                      "The PDF contains keywords for actions, scripts or embedded files.",
                      ev_base + [{"label": k, "value": str(v)} for k, v in active.items()],
                      "medium" if any(k in active for k in ("/Launch", "/JavaScript", "/JS", "/EmbeddedFile")) else "low",
                      "Keyword presence is not proof the feature does anything harmful.",
                      ["Forms and interactive PDFs legitimately use JavaScript and OpenAction."], att_id))
    archive = static.get("archive") or {}

    def walk_archive(a: dict[str, Any], prefix: str = "") -> list[dict[str, Any]]:
        rows = []
        for e in a.get("entries", []):
            rows.append((prefix + e["name"], e))
        for n in a.get("nested", []):
            rows += walk_archive(n["result"], prefix + n["name"] + " ➜ ")
        return rows

    rows = walk_archive(archive) if archive.get("entries") else []
    risky = [(n, e) for n, e in rows if (e.get("detected") or {}).get("family") in ("executable", "script")
             or (n.rsplit(".", 1)[-1].lower() in (SCRIPT_EXTENSIONS | EXECUTABLE_EXTENSIONS))]
    if risky:
        out.append(_f("archive_executable", "Archive contains executable or script files", "attachments",
                      "Files inside the archive are programs or scripts. Archives are often used to get these past attachment filters.",
                      ev_base + [{"label": "Entry", "value": n} for n, _ in risky[:15]], "high",
                      "Entries were identified, not run.",
                      ["Software distributions are zipped legitimately."], att_id))
    unsafe = [(n, e) for n, e in rows if e.get("path_issue") or e.get("symlink")]
    if unsafe:
        out.append(_f("archive_unsafe_paths", "Archive entries with unsafe paths", "attachments",
                      "Some entry names would write outside the extraction folder or are symbolic links. Nothing was extracted to disk.",
                      ev_base + [{"label": "Entry", "value": f"{n} ({e.get('path_issue') or 'symlink'})"} for n, e in unsafe[:15]], "medium",
                      "Some archivers produce these by accident.", ["Badly built archives."], att_id))
    if static.get("status") in ("encrypted",) or archive.get("encrypted_entries"):
        out.append(_f("encrypted_content", "Encrypted attachment content could not be inspected", "coverage",
                      "Encryption prevents static inspection. Password-protected attachments are also a known way to get files past mail filters.",
                      ev_base, "medium",
                      "Nothing about the encrypted content is known.",
                      ["Confidential documents are legitimately sent password-protected."], att_id))
    return out


def language_findings(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    subject = parsed.get("subject", {}).get("decoded") or ""
    bodies = [b["content"] for b in parsed.get("text_bodies", [])]
    if not bodies:
        bodies = [re.sub(r"<[^>]+>", " ", b["content"]) for b in parsed.get("html_bodies", [])]
    text = subject + "\n" + "\n".join(bodies)
    low = text.lower()

    def hits(terms: list[str]) -> list[str]:
        found = []
        for t in terms:
            for m in re.finditer(r"(?<![a-z])" + re.escape(t) + r"(?![a-z])", low):
                start, end = max(0, m.start() - 50), min(len(text), m.end() + 50)
                found.append(re.sub(r"\s+", " ", text[start:end]).strip())
                break
        return found

    urgency = hits(URGENCY_TERMS)
    sensitive: dict[str, list[str]] = {k: hits(v) for k, v in SENSITIVE_TERMS.items()}
    sensitive = {k: v for k, v in sensitive.items() if v}
    if not urgency or not sensitive:
        return []
    ev = [{"label": "Urgency phrase", "value": f"…{s}…"} for s in urgency[:4]]
    for k, v in sensitive.items():
        ev += [{"label": f"Request involving {k.replace('_', ' ')}", "value": f"…{s}…"} for s in v[:3]]
    return [_f("urgent_sensitive_request", "Urgent request involving " + ", ".join(k.replace("_", " ") for k in sensitive),
               "content",
               "The message combines time pressure with a request about credentials, payment or personal data. "
               "Pressure plus a sensitive request is a common social-engineering pattern.",
               ev, "medium",
               "Keyword matching in English only; it does not understand context, negation or quoted text.",
               ["Genuine security notices, invoices and payroll reminders use the same language.",
                "Quoted text from an earlier legitimate message."])]
