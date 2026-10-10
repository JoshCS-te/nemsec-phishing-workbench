import hashlib
import os

import pytest

from app import evidence, services

from .conftest import make_email, sample


def test_hash_and_byte_preservation(conn):
    data = sample("04_misleading_extension.eml")
    r = services.import_email(conn, data, "04.eml")
    ev = conn.execute("SELECT * FROM evidence WHERE id=?", (r["evidence_id"],)).fetchone()
    assert ev["sha256"] == hashlib.sha256(data).hexdigest()
    assert evidence.read_bytes(ev["stored_name"]) == data
    assert evidence.verify(ev["stored_name"], ev["sha256"])["ok"]
    att = conn.execute("SELECT * FROM evidence WHERE parent_id=?", (r["evidence_id"],)).fetchone()
    exe = (evidence.resolve(att["stored_name"])).read_bytes()
    assert exe.startswith(b"MZ") and att["sha256"] == hashlib.sha256(exe).hexdigest()
    assert att["mime_part_ref"] == "2"


def test_stored_names_are_generated_not_user_paths(conn, data_dir):
    r = services.import_email(conn, make_email("From: a@x.example\nSubject: t"), "../../../../etc/evil.eml")
    ev = conn.execute("SELECT * FROM evidence WHERE id=?", (r["evidence_id"],)).fetchone()
    assert "evil" not in ev["stored_name"] and ".." not in ev["stored_name"]
    assert ev["original_filename"] == "../../../../etc/evil.eml"  # kept only as metadata
    assert evidence.resolve(ev["stored_name"]).is_relative_to(data_dir / "evidence")
    with pytest.raises(ValueError):
        evidence.resolve("../../outside.bin")


def test_duplicate_import_is_recorded_not_restored(conn):
    data = sample("01_legitimate.eml")
    first = services.import_email(conn, data, "a.eml")
    second = services.import_email(conn, data, "renamed.eml")
    assert second["duplicate"] and second["evidence_id"] == first["evidence_id"]
    assert conn.execute("SELECT COUNT(*) FROM evidence WHERE kind='email'").fetchone()[0] == 1
    imports = conn.execute("SELECT original_filename, duplicate FROM evidence_imports ORDER BY id").fetchall()
    assert [tuple(r) for r in imports] == [("a.eml", 0), ("renamed.eml", 1)]


def test_tampering_is_detected(conn):
    r = services.import_email(conn, sample("01_legitimate.eml"), "a.eml")
    ev = conn.execute("SELECT * FROM evidence WHERE id=?", (r["evidence_id"],)).fetchone()
    path = evidence.resolve(ev["stored_name"])
    os.chmod(path, 0o600)
    path.write_bytes(path.read_bytes() + b"x")
    v = evidence.verify(ev["stored_name"], ev["sha256"])
    assert not v["ok"] and "authentic" in v["meaning"]


def test_upload_limits_and_type(conn, monkeypatch):
    from app.config import reset_settings

    monkeypatch.setenv("PHB_MAX_UPLOAD_BYTES", "100")
    reset_settings()
    with pytest.raises(services.ImportRejected):
        services.import_email(conn, b"x" * 101, "big.eml")
    with pytest.raises(services.ImportRejected):
        services.import_email(conn, b"", "empty.eml")
    with pytest.raises(services.ImportRejected):
        services.import_email(conn, b"From: a@b", "thing.exe")


def test_api_upload_limit(client, monkeypatch):
    from app.config import reset_settings

    monkeypatch.setenv("PHB_MAX_UPLOAD_BYTES", "50")
    reset_settings()
    r = client.post("/api/emails/import", files={"file": ("x.eml", b"A" * 51, "message/rfc822")})
    assert r.status_code == 413


def test_upload_never_executes_or_runs_sandbox(conn, monkeypatch):
    """Importing creates static jobs only; no sandbox job may exist without explicit submission."""
    monkeypatch.setenv("PHB_SANDBOX_MODE", "demo")
    from app.config import reset_settings

    reset_settings()
    services.import_email(conn, sample("08_sandbox_verification.eml"), "08.eml")
    kinds = {r[0] for r in conn.execute("SELECT kind FROM jobs")}
    assert kinds == {"static_analysis"}
    assert conn.execute("SELECT COUNT(*) FROM sandbox_jobs").fetchone()[0] == 0
