import json

from app import cases, services
from app.analysis import findings as rules
from app.parsing.email_parser import parse_email
from app.worker import drain

from .conftest import make_email, sample

# Expected rule ids per sample (documented in samples/EXPECTED_FINDINGS.md). Must be present; extra findings fail too,
# so the documentation stays accurate.
EXPECTED = {
    "01_legitimate.eml": set(),
    "02_reply_to_mismatch.eml": {"reply_to_differs", "return_path_differs", "auth_results_claim_fail", "urgent_sensitive_request",
                                 "display_name_impersonation"},
    "03_misleading_link.eml": {"link_text_mismatch", "ip_destination", "idn_confusable", "url_userinfo", "html_form",
                               "meta_refresh", "dangerous_scheme", "urgent_sensitive_request"},
    "04_misleading_extension.eml": {"extension_mismatch", "executable_attachment", "urgent_sensitive_request"},
    "05_malformed.eml": {"duplicate_from"},
    "06_encrypted_unsupported.eml": {"encrypted_content"},
    "07_archive_with_script.eml": {"archive_executable", "archive_unsafe_paths"},
    "08_sandbox_verification.eml": {"executable_attachment", "script_attachment"},
    "09_demo_failure_paths.eml": {"script_attachment"},
}


def test_every_sample_produces_exactly_the_documented_findings(conn):
    case = cases.create_case(conn, "samples")
    cases.add_reference(conn, case["id"], "Adaeze Okafor (CFO)", "adaeze.okafor@contoso-demo.example")
    ids = {}
    for name in EXPECTED:
        ids[name] = services.import_email(conn, sample(name), name, case["id"])["evidence_id"]
    drain(conn)
    for name, expected in EXPECTED.items():
        got = {r[0] for r in conn.execute("SELECT rule_id FROM findings WHERE email_evidence_id=?", (ids[name],))}
        assert got == expected, (name, got ^ expected)


def test_every_finding_is_explainable():
    parsed = parse_email(sample("02_reply_to_mismatch.eml")).data
    out = rules.header_findings(parsed, [{"display_name": "Adaeze Okafor (CFO)", "email": "adaeze.okafor@contoso-demo.example"}])
    assert out
    for f in out:
        assert f["name"] and f["category"] and f["explanation"]
        assert f["evidence"] and all("value" in e for e in f["evidence"])
        assert f["confidence"] in ("low", "medium", "high")
        assert f["uncertainty"]
        assert f["benign"], f["rule_id"]  # benign explanations are always offered for these rules


def test_impersonation_needs_reference_and_ignores_real_address():
    parsed = parse_email(make_email('From: "Adaeze Okafor" <adaeze.okafor@contoso-demo.example>\nSubject: x')).data
    ref = [{"display_name": "Adaeze Okafor", "email": "adaeze.okafor@contoso-demo.example"}]
    assert not [f for f in rules.header_findings(parsed, ref) if f["rule_id"] == "display_name_impersonation"]
    assert not [f for f in rules.header_findings(parsed, []) if f["rule_id"] == "display_name_impersonation"]
    spoof = parse_email(make_email('From: "Adaeze  Okafor" <ceo.office@freemail-demo.example>\nSubject: x')).data
    hit = [f for f in rules.header_findings(spoof, ref) if f["rule_id"] == "display_name_impersonation"]
    assert hit and hit[0]["confidence"] == "high"


def test_same_org_reply_to_is_low_weight():
    p = parse_email(make_email("From: a@x.example\nReply-To: helpdesk@x.example\nSubject: s")).data
    f = [f for f in rules.header_findings(p, []) if f["rule_id"] == "reply_to_differs"][0]
    assert f["confidence"] == "low"


def test_no_aggregate_score_exists(conn):
    r = services.import_email(conn, sample("03_misleading_link.eml"), "03.eml")
    cols = {c[1] for c in conn.execute("PRAGMA table_info(emails)")} | {c[1] for c in conn.execute("PRAGMA table_info(findings)")}
    assert not any("score" in c or "verdict" in c for c in cols)
    assert r["evidence_id"]


def test_review_state_survives_recompute(conn):
    case = cases.create_case(conn, "c")
    ev = services.import_email(conn, sample("02_reply_to_mismatch.eml"), "02.eml", case["id"])["evidence_id"]
    fid = conn.execute("SELECT id FROM findings WHERE rule_id='reply_to_differs' AND email_evidence_id=?", (ev,)).fetchone()[0]
    cases.review_finding(conn, case["id"], fid, "benign", "vendor uses a shared payments desk", None)
    services.recompute_email_findings(conn, ev)
    row = conn.execute("SELECT review_status, analyst_comment FROM case_findings WHERE finding_id=?", (fid,)).fetchone()
    assert tuple(row) == ("benign", "vendor uses a shared payments desk")


def test_urgent_request_needs_both_pressure_and_sensitive_ask():
    calm = parse_email(make_email("From: a@x.example\nSubject: password policy", "Reminder: our password policy changed last month.")).data
    assert rules.language_findings(calm) == []
    pushy = parse_email(make_email("From: a@x.example\nSubject: URGENT", "Verify your account password immediately.")).data
    f = rules.language_findings(pushy)[0]
    assert f["rule_id"] == "urgent_sensitive_request" and "English only" in f["uncertainty"]
    assert json.dumps(f["evidence"])
