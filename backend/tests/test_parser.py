from app.parsing.email_parser import parse_email

from .conftest import make_email, sample


def test_encoded_headers_and_rfc2231_filename():
    raw = (
        b"From: =?UTF-8?Q?Ad=C3=A1ez=C3=A9_Okafor?= <a@x.example>\r\n"
        b"Subject: =?UTF-8?B?VVJHRU5UOiB2ZW5kb3IgcGF5bWVudCB0b2RheQ==?=\r\n"
        b"Date: Mon, 05 Oct 2026 09:02:44 +0100\r\nMessage-ID: <1@x>\r\nMIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n'
        b"--b\r\nContent-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.txt\r\n\r\nabc\r\n--b--\r\n"
    )
    r = parse_email(raw)
    assert r.status == "parsed"
    assert r.data["subject"]["decoded"] == "URGENT: vendor payment today"
    assert r.data["subject"]["raw"].startswith("=?UTF-8?B?")  # raw kept alongside decoded
    assert r.data["from"]["addresses"][0]["display_name"] == "Adáezé Okafor"
    assert r.attachments[0].filename_display == "résumé.txt"
    assert r.attachments[0].payload == b"abc"


def test_missing_fields_are_not_invented():
    r = parse_email(make_email("To: someone@x.example"))
    assert r.data["from"]["raw"] is None and r.data["from"]["addresses"] == []
    assert r.data["date"]["utc"] is None
    assert r.data["message_id"]["raw"] is None
    assert any("No From header" in w for w in r.warnings)
    assert any("No Date header" in w for w in r.warnings)


def test_duplicate_headers_and_malformed_date():
    r = parse_email(sample("05_malformed.eml"))
    assert r.status in ("parsed", "partial")
    assert len(r.data["from"]["all_raw"]) == 2
    assert any("Duplicate From" in w for w in r.warnings)
    assert r.data["date"]["raw"].startswith("Funday")
    assert r.data["date"]["utc"] is None
    assert any("Date header could not be parsed" in w for w in r.warnings)
    assert any("charset" in w for w in r.warnings)  # unknown charset body
    assert any("Base64" in w for w in r.warnings)


def test_garbage_input_does_not_crash():
    r = parse_email(b"\x00\x01\x02 not an email at all \xff\xfe")
    assert r.status in ("partial", "failed")
    assert any("No standard email headers" in w for w in r.warnings) or r.errors


def test_multipart_structure_and_bodies():
    r = parse_email(sample("01_legitimate.eml"))
    tree = r.data["mime_tree"]
    assert tree["content_type"] == "multipart/alternative"
    assert [c["role"] for c in tree["children"]] == ["text_body", "html_body"]
    assert r.data["text_bodies"] and r.data["html_bodies"]


def test_authentication_results_are_claims_not_verification():
    r = parse_email(sample("01_legitimate.eml"))
    ar = r.data["authentication_results"][0]
    assert ar["status"] == "reported_claim"
    assert {m["method"]: m["result"] for m in ar["methods"]} == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}
    assert "not verified" in r.data["trust_note"] or "reported claims" in r.data["trust_note"]
    assert all(sig["signature_verified"] is False for sig in r.data["dkim_signatures"])


def test_forged_auth_header_stays_a_claim():
    """An attacker can write 'dmarc=pass' into their own message. It must never become a verified result."""
    raw = make_email("""Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=bank.example; dkim=pass; dmarc=pass
From: Bank <security@bank.example>
To: v@x.example
Subject: hi
Date: Mon, 05 Oct 2026 09:02:44 +0100
Message-ID: <f@x>""")
    r = parse_email(raw)
    ar = r.data["authentication_results"][0]
    assert ar["status"] == "reported_claim"
    assert "verified" not in ar


def test_received_hops_order_and_parse():
    r = parse_email(sample("02_reply_to_mismatch.eml"))
    hop = r.data["received"][0]
    assert hop["index"] == 0 and "mail.sender-demo.example" in hop["from"]
    assert hop["bracketed_ips"] == ["192.0.2.10"]


def test_bidi_override_removed_from_display_but_kept_raw():
    rlo = "‮"
    raw = (
        "From: a@x.example\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n"
        "Content-Type: text/plain\r\n\r\nx\r\n--b\r\nContent-Type: application/octet-stream\r\n"
        "Content-Disposition: attachment; filename*=UTF-8''invoice%E2%80%AEfdp.exe\r\n\r\nMZ\r\n--b--\r\n"
    ).encode("utf-8")
    r = parse_email(raw)
    att = r.attachments[0]
    assert rlo in att.filename_raw
    assert rlo not in att.filename_display
