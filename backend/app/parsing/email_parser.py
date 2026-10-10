"""Parse an RFC 5322 / MIME message into a structured, explainable record.

Design rules
------------
* Raw header values are always kept next to decoded/normalised values.
* Missing information stays missing (``None``); nothing is guessed.
* Every recoverable problem becomes a warning, every unrecoverable one an error.
* Attachments are returned as bytes for preservation only. Nothing here
  executes, renders or interprets attachment content.
"""
from __future__ import annotations

import email
import re
from dataclasses import dataclass, field
from datetime import timezone
from email import policy
from email.header import decode_header, make_header
from email.message import Message
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any

SINGLE_VALUE_HEADERS = ["From", "Sender", "Reply-To", "Return-Path", "To", "Cc", "Subject", "Date", "Message-ID"]
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
BIDI_CHARS = re.compile("[‪-‮⁦-⁩‎‏]")
TRUST_NOTE = (
    "Received and Authentication-Results headers are text inside the uploaded file. Anyone who "
    "crafted or relayed the message could have added or altered them. Only headers added by a "
    "receiving server you trust (and that strips inbound copies of its own headers) can be relied "
    "on. Without that context these are reported claims, not verified results. This tool does not "
    "re-check SPF, DKIM or DMARC, because DNS records and keys may have changed since delivery."
)


@dataclass
class ParsedAttachment:
    part_ref: str
    filename_raw: str | None
    filename_display: str | None
    declared_mime: str
    disposition: str | None
    content_id: str | None
    payload: bytes
    decode_warnings: list[str] = field(default_factory=list)


@dataclass
class ParseResult:
    status: str  # parsed | partial | failed
    data: dict[str, Any]
    attachments: list[ParsedAttachment]
    warnings: list[str]
    errors: list[str]


def decode_header_value(raw: str | None, warnings: list[str], label: str) -> str | None:
    if raw is None:
        return None
    raw_str = str(raw)
    try:
        decoded = str(make_header(decode_header(raw_str)))
    except Exception as exc:  # unknown charset, bad base64 etc.
        warnings.append(f"{label}: could not decode encoded-word ({exc.__class__.__name__}); raw value shown")
        decoded = raw_str
    # Unfold continuation lines
    decoded = re.sub(r"\r?\n[ \t]+", " ", decoded)
    return decoded


def display_safe(text: str | None) -> str | None:
    """Strip control and bidi-override characters for display (raw value is kept separately)."""
    if text is None:
        return None
    return BIDI_CHARS.sub("", CONTROL_CHARS.sub("", text))


def _parse_addresses(decoded: str | None) -> list[dict[str, Any]]:
    if not decoded:
        return []
    out = []
    for name, addr in getaddresses([decoded]):
        addr = addr.strip()
        valid = bool(re.fullmatch(r"[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+", addr))
        domain = addr.rsplit("@", 1)[1].lower() if "@" in addr else None
        out.append({"display_name": name or None, "address": addr or None, "domain": domain, "syntax_valid": valid})
    return out


def _parse_date(raw: str | None, warnings: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {"raw": raw, "utc": None, "offset": None, "timezone_known": None}
    if raw is None:
        return result
    try:
        dt = parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError):
        dt = None
    if dt is None:
        warnings.append(f"Date header could not be parsed: {raw!r}. The raw value is kept; no date was assumed.")
        return result
    if dt.tzinfo is None:
        # RFC 5322 '-0000' => time is UTC but local zone is unknown
        result["timezone_known"] = False
        dt = dt.replace(tzinfo=timezone.utc)
        warnings.append("Date header has offset -0000 (no local timezone information).")
    else:
        result["timezone_known"] = True
    off = dt.utcoffset()
    if off is not None:
        total = int(off.total_seconds() // 60)
        sign = "+" if total >= 0 else "-"
        result["offset"] = f"{sign}{abs(total) // 60:02d}{abs(total) % 60:02d}"
    result["utc"] = dt.astimezone(timezone.utc).isoformat()
    result["local"] = dt.isoformat()
    return result




def _parse_received(values: list[str], warnings: list[str]) -> list[dict[str, Any]]:
    hops = []
    for idx, raw in enumerate(values):
        unfolded = re.sub(r"\s+", " ", raw).strip()
        hop: dict[str, Any] = {"index": idx, "raw": raw, "from": None, "by": None, "with": None, "date_raw": None, "date_utc": None}
        clauses, _, date_part = unfolded.rpartition(";")
        if not clauses:
            clauses, date_part = unfolded, ""
        for key in ("from", "by", "with"):
            m = re.search(rf"(?:^|\s){key}\s+(.+?)(?=\s+(?:from|by|via|with|id|for)\s|$)", clauses, re.I)
            if m:
                hop[key] = m.group(1).strip()
        if date_part.strip():
            hop["date_raw"] = date_part.strip()
            tmp: list[str] = []
            hop["date_utc"] = _parse_date(hop["date_raw"], tmp)["utc"]
        ip = re.findall(r"\[(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})\]", unfolded)
        hop["bracketed_ips"] = ip
        hops.append(hop)
    # Received headers are prepended; index 0 is the most recent hop (closest to the recipient).
    return hops


AUTH_METHOD_RE = re.compile(r"\b(spf|dkim|dmarc|arc|bimi|iprev|auth)\s*=\s*([a-z]+)", re.I)


def _parse_auth_results(values: list[str]) -> list[dict[str, Any]]:
    out = []
    for raw in values:
        unfolded = re.sub(r"\s+", " ", raw).strip()
        authserv = unfolded.split(";", 1)[0].strip() if ";" in unfolded else None
        methods = []
        for clause in unfolded.split(";")[1:] if ";" in unfolded else [unfolded]:
            m = AUTH_METHOD_RE.search(clause)
            if m:
                props = dict(re.findall(r"\b((?:smtp|header|policy|body)\.[a-z-]+)=([^\s;]+)", clause, re.I))
                methods.append({"method": m.group(1).lower(), "result": m.group(2).lower(), "properties": props, "clause": clause.strip()})
        out.append({
            "raw": raw,
            "authserv_id": authserv,
            "methods": methods,
            "status": "reported_claim",
        })
    return out


def _decode_text_part(part: Message, warnings: list[str], ref: str) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        payload = b""
    charset = part.get_content_charset() or "us-ascii"
    try:
        return payload.decode(charset)
    except (LookupError, UnicodeDecodeError) as exc:
        warnings.append(f"Part {ref}: body declared charset {charset!r} but could not be decoded cleanly "
                        f"({exc.__class__.__name__}); undecodable bytes shown as �.")
        try:
            return payload.decode(charset, errors="replace")
        except LookupError:
            return payload.decode("utf-8", errors="replace")


def _is_attachment(part: Message) -> bool:
    if part.is_multipart():
        return False
    disp = (part.get("Content-Disposition") or "").split(";", 1)[0].strip().lower()
    ctype = part.get_content_type()
    if disp == "attachment":
        return True
    if part.get_filename() or part.get_param("name"):
        return True
    if ctype in ("text/plain", "text/html"):
        return False
    return True  # any other leaf (images, application/*, message/*) is preserved as an attachment


def parse_email(data: bytes) -> ParseResult:
    warnings: list[str] = []
    errors: list[str] = []
    attachments: list[ParsedAttachment] = []

    try:
        msg = email.message_from_bytes(data, policy=policy.compat32)
    except Exception as exc:  # extremely rare with compat32, but never crash an import
        errors.append(f"MIME parser failed: {exc.__class__.__name__}: {exc}")
        return ParseResult("failed", {"trust_note": TRUST_NOTE}, [], warnings, errors)

    for d in msg.defects:
        warnings.append(f"Top-level MIME defect: {d.__class__.__name__}")

    # --- headers -------------------------------------------------------
    all_headers = []
    for name, value in msg.items():
        all_headers.append({
            "name": name,
            "raw": str(value),
            "decoded": decode_header_value(value, warnings, name),
        })

    def values(name: str) -> list[str]:
        return [str(v) for v in (msg.get_all(name) or [])]

    for h in SINGLE_VALUE_HEADERS:
        vs = values(h)
        if len(vs) > 1:
            warnings.append(f"Duplicate {h} header ({len(vs)} occurrences). Mail clients disagree on which one "
                            f"they show; all values are kept and the first is used in summaries.")

    def first(name: str) -> dict[str, Any]:
        vs = values(name)
        raw = vs[0] if vs else None
        return {"raw": raw, "decoded": decode_header_value(raw, warnings, name), "all_raw": vs}

    subject = first("Subject")
    from_h = first("From")
    reply_to = first("Reply-To")
    return_path = first("Return-Path")
    sender_h = first("Sender")
    to_h = first("To")
    cc_h = first("Cc")
    msgid = first("Message-ID")
    date_h = first("Date")

    from_addrs = _parse_addresses(from_h["decoded"])
    if from_h["raw"] is None:
        warnings.append("No From header present.")
    elif not from_addrs or not from_addrs[0]["address"]:
        warnings.append("From header present but no address could be parsed from it.")
    elif len(from_addrs) > 1:
        warnings.append(f"From header lists {len(from_addrs)} addresses.")

    if msgid["raw"] is None:
        warnings.append("No Message-ID header present.")
    if subject["raw"] is None:
        warnings.append("No Subject header present.")

    date = _parse_date(date_h["raw"], warnings)
    if date_h["raw"] is None:
        warnings.append("No Date header present.")

    received = _parse_received(values("Received"), warnings)
    auth_results = _parse_auth_results(values("Authentication-Results"))
    arc_auth = _parse_auth_results(values("ARC-Authentication-Results"))
    received_spf = values("Received-SPF")
    dkim_sigs = []
    for raw in values("DKIM-Signature"):
        flat = re.sub(r"\s+", "", raw)
        tags = dict(re.findall(r"(?:^|;)([a-z]+)=([^;]*)", flat))
        dkim_sigs.append({"raw": raw, "d": tags.get("d"), "s": tags.get("s"), "signature_verified": False})

    # --- MIME tree -------------------------------------------------------
    text_bodies: list[dict[str, Any]] = []
    html_bodies: list[dict[str, Any]] = []

    def walk(part: Message, ref: str, depth: int) -> dict[str, Any]:
        node: dict[str, Any] = {
            "part_ref": ref,
            "content_type": part.get_content_type(),
            "declared_content_type": part.get("Content-Type"),
            "charset": part.get_content_charset(),
            "transfer_encoding": part.get("Content-Transfer-Encoding"),
            "disposition": part.get("Content-Disposition"),
            "filename": None,
            "size_bytes": None,
            "defects": [d.__class__.__name__ for d in part.defects],
            "children": [],
            "role": None,
        }
        for d in part.defects:
            warnings.append(f"Part {ref or 'root'}: MIME defect {d.__class__.__name__}")
        if depth > 30:
            warnings.append(f"Part {ref}: MIME nesting deeper than 30 levels; stopped descending.")
            return node
        if part.get_content_type() == "message/rfc822" and depth > 0:
            # An attached/forwarded email is preserved whole as its own piece of evidence.
            inner = part.get_payload()
            if isinstance(inner, list) and inner:
                body = inner[0].as_bytes()
            else:
                body = part.get_payload(decode=True) or b""
            node["role"] = "attachment"
            node["size_bytes"] = len(body)
            fn_raw = part.get_filename() or "embedded-message.eml"
            attachments.append(ParsedAttachment(ref or "1", part.get_filename(), display_safe(decode_header_value(fn_raw, warnings, "filename")),
                                                "message/rfc822", node["disposition"], part.get("Content-ID"), body))
            node["filename"] = fn_raw
            return node

        if part.is_multipart():
            payload = part.get_payload()
            if isinstance(payload, list):
                for i, child in enumerate(payload, start=1):
                    node["children"].append(walk(child, f"{ref}.{i}" if ref else str(i), depth + 1))
            node["role"] = "container"
            return node

        if _is_attachment(part):
            dec_warn: list[str] = []
            raw_payload = part.get_payload()
            payload = part.get_payload(decode=True)
            if payload is None:
                payload = raw_payload.encode("latin-1", "replace") if isinstance(raw_payload, str) else b""
                dec_warn.append("Payload could not be transfer-decoded; raw encoded text preserved instead.")
            cte = (part.get("Content-Transfer-Encoding") or "").strip().lower()
            if cte == "base64" and isinstance(raw_payload, str):
                stripped = re.sub(r"\s+", "", raw_payload)
                if len(stripped) % 4 != 0:
                    dec_warn.append("Base64 payload length is not a multiple of 4; the decoded bytes may be truncated or padded.")
            fn_raw = part.get_filename()
            if fn_raw is None:
                name_param = part.get_param("name")
                fn_raw = email.utils.collapse_rfc2231_value(name_param) if name_param else None
            fn_decoded = decode_header_value(fn_raw, warnings, f"Part {ref} filename") if fn_raw else None
            disp = (part.get("Content-Disposition") or "").split(";", 1)[0].strip().lower() or None
            att = ParsedAttachment(ref or "1", fn_raw, display_safe(fn_decoded), part.get_content_type(), disp,
                                   part.get("Content-ID"), payload, dec_warn)
            attachments.append(att)
            for w in dec_warn:
                warnings.append(f"Part {ref}: {w}")
            node["role"] = "attachment"
            node["filename"] = fn_decoded
            node["size_bytes"] = len(payload)
            return node

        text = _decode_text_part(part, warnings, ref or "1")
        body = {"part_ref": ref or "1", "charset": part.get_content_charset(), "content": text}
        if part.get_content_type() == "text/html":
            html_bodies.append(body)
            node["role"] = "html_body"
        else:
            text_bodies.append(body)
            node["role"] = "text_body"
        node["size_bytes"] = len(text.encode("utf-8"))
        return node

    try:
        mime_tree = walk(msg, "", 0)
    except Exception as exc:
        errors.append(f"MIME walk failed part-way: {exc.__class__.__name__}: {exc}")
        mime_tree = {"part_ref": "", "content_type": msg.get_content_type(), "children": [], "role": "unknown"}

    looks_like_email = any(values(h) for h in ("From", "Date", "Subject", "Received", "Message-ID"))
    if not looks_like_email:
        warnings.append("No standard email headers (From/Date/Subject/Received/Message-ID) were found. "
                        "This file may not be an email or may be badly malformed.")

    data_out = {
        "subject": subject,
        "from": {**from_h, "addresses": from_addrs},
        "sender": {**sender_h, "addresses": _parse_addresses(sender_h["decoded"])},
        "reply_to": {**reply_to, "addresses": _parse_addresses(reply_to["decoded"])},
        "return_path": {**return_path, "addresses": _parse_addresses(return_path["decoded"])},
        "to": {**to_h, "addresses": _parse_addresses(to_h["decoded"])},
        "cc": {**cc_h, "addresses": _parse_addresses(cc_h["decoded"])},
        "message_id": msgid,
        "date": {**date, "all_raw": date_h["all_raw"]},
        "received": received,
        "authentication_results": auth_results,
        "arc_authentication_results": arc_auth,
        "received_spf": received_spf,
        "dkim_signatures": dkim_sigs,
        "headers": all_headers,
        "text_bodies": text_bodies,
        "html_bodies": html_bodies,
        "mime_tree": mime_tree,
        "trust_note": TRUST_NOTE,
    }

    if errors:
        status = "partial"
    elif not looks_like_email or any(w.startswith("Top-level MIME defect") for w in warnings):
        status = "partial"
    else:
        status = "parsed"
    return ParseResult(status, data_out, attachments, list(dict.fromkeys(warnings)), errors)
