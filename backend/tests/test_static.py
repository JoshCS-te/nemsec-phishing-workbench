import io
import os
import zipfile

from app.analysis import filetype
from app.analysis.runner import run_static
from app.analysis.static import Limits, analyse

from .conftest import REPO

EXE = (REPO / "samples" / "harmless" / "nemsec_sandbox_demo.exe").read_bytes()


def zbytes(entries: dict[str, bytes], compression=zipfile.ZIP_DEFLATED) -> bytes:
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", compression) as z:
        for n, d in entries.items():
            z.writestr(n, d)
    return b.getvalue()


def test_extension_mismatch_and_double_extension():
    det = filetype.detect(EXE, "Invoice.pdf")
    assert det["type"] == "pe"
    assess = filetype.extension_assessment("Invoice.pdf", det["type"])
    assert assess["mismatch"] and assess["expected_types"] == ["pdf"]
    dbl = filetype.extension_assessment("Invoice.pdf.exe", "pe")
    assert not dbl["mismatch"] and any("Double extension" in n for n in dbl["notes"])


def test_traversal_and_symlink_entries_flagged_and_nothing_written(tmp_path):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("../../evil.txt", "x")
        z.writestr("C:/Windows/evil.txt", "x")
        info = zipfile.ZipInfo("link")
        info.external_attr = (0o120777 << 16)
        z.writestr(info, "/etc/passwd")
    before = set(os.listdir(tmp_path))
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        r = analyse(b.getvalue(), "a.zip", None, Limits())
    finally:
        os.chdir(cwd)
    assert set(os.listdir(tmp_path)) == before  # nothing extracted to disk
    issues = {e["name"]: (e["path_issue"], e["symlink"]) for e in r["archive"]["entries"]}
    assert issues["../../evil.txt"][0].startswith("parent-directory")
    assert issues["C:/Windows/evil.txt"][0] == "drive-letter path"
    assert issues["link"][1] is True
    assert r["archive"]["unsafe_entries"] == 3


def test_compression_ratio_bomb_not_expanded():
    data = zbytes({"zeros.bin": b"\0" * 5_000_000})
    r = analyse(data, "bomb.zip", None, Limits(max_ratio=100))
    e = r["archive"]["entries"][0]
    assert e["status"] == "skipped_ratio"
    assert r["status"] == "partial"  # incomplete must not look clean


def test_entry_count_total_size_and_depth_limits():
    many = zbytes({f"f{i}.txt": b"x" for i in range(20)})
    r = analyse(many, "m.zip", None, Limits(max_entries=5))
    assert len(r["archive"]["entries"]) == 5 and r["status"] == "partial"

    big = zbytes({"a.txt": os.urandom(4000), "b.txt": os.urandom(4000)})
    r = analyse(big, "b.zip", None, Limits(max_total=5000, max_ratio=1000))
    assert any(e["status"] == "skipped_budget" for e in r["archive"]["entries"])

    nested = zbytes({"z.txt": b"deep"})
    for _ in range(4):
        nested = zbytes({"inner.zip": nested}, zipfile.ZIP_STORED)
    r = analyse(nested, "n.zip", None, Limits(max_depth=2))
    assert r["status"] == "partial" and any("beyond depth" in l for l in r["limitations"])


def test_encrypted_and_unsupported_marked():
    from build_samples import encrypted_zip

    r = analyse(encrypted_zip({"x.docm": b"secret"}, b"pw"), "s.zip", None, Limits())
    assert r["status"] == "encrypted"
    r7 = analyse(b"7z\xbc\xaf\x27\x1c" + b"\0" * 40, "a.7z", None, Limits())
    assert r7["status"] == "unsupported"
    ole_enc = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 100 + "EncryptedPackage".encode("utf-16-le")
    r_ole = analyse(ole_enc, "secret.docx", None, Limits())
    assert r_ole["status"] == "encrypted" and not r_ole["extension"]["mismatch"]


def test_pe_and_pdf_static_details():
    r = analyse(EXE, "x.exe", None, Limits())
    assert r["status"] == "complete" and r["pe"]["machine"] == "0x8664"
    assert any(i["dll"].lower() == "kernel32.dll" for i in r["pe"]["imports"])
    pdf = b"%PDF-1.7\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >>\n2 0 obj << /S /JavaScript /JS (app.alert(1)) >>\n" \
          b"3 0 obj << /URI (http://pdf-link.invalid/x) >>\n%%EOF"
    p = analyse(pdf, "d.pdf", None, Limits())["pdf"]
    assert p["keyword_counts"]["/OpenAction"] == 1 and p["keyword_counts"]["/JavaScript"] == 1
    assert p["uris"] == ["http://pdf-link.invalid/x"]


def test_scripts_identified_by_content_not_executed():
    bat = (REPO / "samples" / "harmless" / "nemsec_sandbox_demo.bat").read_bytes()
    r = analyse(bat, "label.txt", None, Limits())
    assert r["detected"]["type"] == "script_text" and r["never_executed"] is True
    assert "text_excerpt" in r


def test_ooxml_external_template_detected():
    rels = b'<?xml version="1.0"?><Relationships><Relationship Id="rId1" Type="http://x/attachedTemplate" ' \
           b'Target="http://template.invalid/t.dotm" TargetMode="External"/></Relationships>'
    docx = zbytes({"[Content_Types].xml": b"<Types/>", "word/document.xml": b"<w/>", "word/_rels/settings.xml.rels": rels})
    r = analyse(docx, "cv.docx", None, Limits())
    assert r["detected"]["type"] == "docx"
    assert r["office"]["external_relationships"][0]["target"] == "http://template.invalid/t.dotm"


def test_runner_timeout_keeps_partial_result(data_dir, monkeypatch):
    from app.config import reset_settings

    monkeypatch.setenv("PHB_STATIC_TIMEOUT_S", "2")
    monkeypatch.setenv("PHB_STATIC_TEST_DELAY_S", "10")
    reset_settings()
    r = run_static(EXE, "x.exe", None)
    assert r["status"] == "partial"
    assert "identify" in r["stages_completed"] and "format" not in r["stages_completed"]
    assert "stopped early" in r["limitations"][0]


def test_runner_size_limit(data_dir, monkeypatch):
    from app.config import reset_settings

    monkeypatch.setenv("PHB_MAX_ATTACHMENT_BYTES", "10")
    reset_settings()
    assert run_static(b"x" * 11, "a.txt", None)["status"] == "too_large"


def test_runner_full_run(data_dir):
    r = run_static(EXE, "x.exe", None)
    assert r["status"] == "complete" and r["detected"]["type"] == "pe"
