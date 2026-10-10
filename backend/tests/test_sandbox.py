"""Sandbox lifecycle tests.

CAPE tests use httpx.MockTransport — they verify our request/response handling
against the documented CAPE API, NOT a live CAPE installation.
"""
import io
import json
import time
import zipfile

import httpx
import pytest

from app import services
from app.sandbox import service as sb
from app.sandbox.cape import CapeAdapter
from app.sandbox.demo import DemoAdapter
from app.worker import drain

from .conftest import sample


def run_until_done(conn, job_id, max_steps=60):
    for _ in range(max_steps):
        nxt = sb.advance(conn, job_id)
        if nxt is None:
            break
    return dict(conn.execute("SELECT * FROM sandbox_jobs WHERE id=?", (job_id,)).fetchone())


@pytest.fixture()
def exe_attachment(conn):
    ev = services.import_email(conn, sample("08_sandbox_verification.eml"), "08.eml")["evidence_id"]
    drain(conn)
    return conn.execute("SELECT evidence_id FROM attachments WHERE email_evidence_id=? AND detected_type='pe'", (ev,)).fetchone()[0]


class FakeCape:
    """Stateful fake of the CAPE REST API endpoints the adapter uses."""

    def __init__(self, statuses=("pending", "running", "completed", "reported"), machine_after=("poweroff", False), fail_submit=False):
        self.statuses = list(statuses)
        self.machine_after = machine_after
        self.fail_submit = fail_submit
        self.calls = []
        self.finished = False
        self.auth_headers = set()

    def __call__(self, req: httpx.Request) -> httpx.Response:
        p = req.url.path
        self.calls.append((req.method, p))
        self.auth_headers.add(req.headers.get("authorization"))
        if p == "/apiv2/cuckoo/status/":
            return httpx.Response(200, json={"error": False, "data": {"tasks": {}}})
        if p.startswith("/apiv2/machines/view/"):
            status, locked = ("running", True) if not self.finished else self.machine_after
            return httpx.Response(200, json={"error": [], "data": {"name": "win10", "status": status, "locked": locked, "snapshot": "clean"}})
        if p == "/apiv2/tasks/create/file/":
            if self.fail_submit:
                return httpx.Response(200, json={"error": True, "error_value": "machine not available"})
            assert b'name="machine"' in req.content and b"win10" in req.content
            return httpx.Response(200, json={"error": False, "data": {"task_ids": [42], "message": "ok"}})
        if p == "/apiv2/tasks/status/42/":
            if req.method == "POST":
                self.finished = True
                return httpx.Response(200, json={"error": False, "data": "ok"})
            st = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
            if st in ("reported", "failed_analysis"):
                self.finished = True
            return httpx.Response(200, json={"error": False, "data": st})
        if p == "/apiv2/tasks/get/report/42/json/":
            return httpx.Response(200, json={
                "info": {"duration": 61, "started": "2026-10-05 10:00:00", "ended": "2026-10-05 10:01:01", "package": "exe"},
                "behavior": {"processes": [{"process_id": 3000, "parent_id": 1200, "process_name": "nemsec_sandbox_demo.exe",
                                            "module_path": "C:\\Users\\u\\AppData\\Local\\Temp\\nemsec_sandbox_demo.exe",
                                            "environ": {"CommandLine": "nemsec_sandbox_demo.exe"}}],
                             "summary": {"write_files": ["C:\\Users\\u\\AppData\\Local\\Temp\\NEMSEC_SANDBOX_DEMO_3000.txt"],
                                         "files": [], "delete_files": [], "write_keys": [], "delete_keys": [], "executed_commands": []}},
                "network": {"dns": [], "tcp": [], "udp": [], "http": []},
                "signatures": [], "debug": {"errors": []}})
        if p == "/apiv2/tasks/get/screenshot/42/":
            b = io.BytesIO()
            with zipfile.ZipFile(b, "w") as z:
                z.writestr("shots/0001.jpg", b"\xff\xd8\xff\xe0fakejpeg")
                z.writestr("shots/evil.html", b"<script>")
            return httpx.Response(200, content=b.getvalue())
        if p == "/apiv2/tasks/delete/42/":
            return httpx.Response(200, json={"error": False})
        return httpx.Response(404, json={"error": True, "error_value": "not found"})


def use_cape(monkeypatch, fake: FakeCape, snapshot="clean"):
    monkeypatch.setenv("PHB_SANDBOX_MODE", "cape")
    monkeypatch.setenv("PHB_CAPE_MACHINE", "win10")
    from app.config import reset_settings

    reset_settings()
    sb.set_adapter_for_tests(CapeAdapter("http://cape.test", "secret-token", snapshot, transport=httpx.MockTransport(fake)))


def test_submission_requires_explicit_confirmation(conn, exe_attachment, monkeypatch):
    use_cape(monkeypatch, FakeCape())
    with pytest.raises(sb.SubmissionRefused):
        sb.submit(conn, exe_attachment, "analyst", confirm=False)
    with pytest.raises(sb.SubmissionRefused):
        sb.submit(conn, exe_attachment, "  ", confirm=True)


def test_disabled_mode_refuses(conn, exe_attachment):
    with pytest.raises(sb.SubmissionRefused, match="disabled"):
        sb.submit(conn, exe_attachment, "a", confirm=True)


def test_cape_happy_path_live_results_and_reset(conn, exe_attachment, monkeypatch):
    fake = FakeCape()
    use_cape(monkeypatch, fake)
    job = sb.submit(conn, exe_attachment, "J. Analyst", confirm=True)
    assert job["is_demo"] is False
    j = run_until_done(conn, job["id"])
    assert j["state"] == "completed" and j["reset_status"] == "verified" and j["external_task_id"] == "42"
    obs = json.loads(j["observations_json"])
    assert obs["is_demo"] is False and obs["source"] == "cape"
    assert obs["files"]["created"][0].endswith("NEMSEC_SANDBOX_DEMO_3000.txt")
    assert obs["processes"][0]["ppid"] == 1200
    cov = json.loads(j["coverage_json"])
    assert any("not mean the file is safe" in n or "Office" in n or "user" in n.lower() for n in cov["limitations"])
    arts = conn.execute("SELECT kind, label FROM sandbox_artifacts WHERE sandbox_job_id=?", (job["id"],)).fetchall()
    assert [tuple(a) for a in arts] == [("screenshot", "0001.jpg")]  # non-image entry dropped
    assert "Token secret-token" in fake.auth_headers
    w = conn.execute("SELECT status FROM sandbox_workers WHERE name='win10'").fetchone()[0]
    assert w == "available"


def test_token_never_logged_or_stored(conn, exe_attachment, monkeypatch, caplog):
    use_cape(monkeypatch, FakeCape())
    job = sb.submit(conn, exe_attachment, "a", confirm=True)
    run_until_done(conn, job["id"])
    dump = "\n".join(str(tuple(r)) for t in ("history", "sandbox_jobs", "jobs") for r in conn.execute(f"SELECT * FROM {t}"))
    assert "secret-token" not in dump and "secret-token" not in caplog.text


def test_engine_failure(conn, exe_attachment, monkeypatch):
    use_cape(monkeypatch, FakeCape(statuses=("running", "failed_analysis")))
    job = sb.submit(conn, exe_attachment, "a", confirm=True)
    j = run_until_done(conn, job["id"])
    assert j["state"] == "failed" and j["execution_outcome"] == "failed" and j["observations_json"] is None
    assert j["reset_status"] == "verified"


def test_submit_rejected_by_engine(conn, exe_attachment, monkeypatch):
    use_cape(monkeypatch, FakeCape(fail_submit=True))
    job = sb.submit(conn, exe_attachment, "a", confirm=True)
    j = run_until_done(conn, job["id"])
    assert j["state"] == "failed" and "machine not available" in j["state_detail"]
    assert conn.execute("SELECT status FROM sandbox_workers").fetchone()[0] == "available"


def test_reset_failure_quarantines_worker_and_blocks_submissions(conn, exe_attachment, monkeypatch):
    use_cape(monkeypatch, FakeCape(machine_after=("error", False)))
    job = sb.submit(conn, exe_attachment, "a", confirm=True)
    j = run_until_done(conn, job["id"])
    assert j["state"] == "reset_failed" and j["execution_outcome"] == "completed"
    assert j["observations_json"]  # observations kept, but state flags the environment problem
    w = conn.execute("SELECT status, reason FROM sandbox_workers WHERE name='win10'").fetchone()
    assert w["status"] == "quarantined"
    with pytest.raises(sb.SubmissionRefused, match="quarantined"):
        sb.submit(conn, exe_attachment, "a", confirm=True)
    with pytest.raises(sb.SubmissionRefused):
        sb.release_worker(conn, "win10", "a", "ok")  # note too short
    sb.release_worker(conn, "win10", "a", "Restored 'clean' snapshot manually and checked boot.")
    assert sb.submit(conn, exe_attachment, "a", confirm=True)["state"] == "queued"


def test_reset_grace_timeout_counts_as_failure(conn, exe_attachment, monkeypatch):
    monkeypatch.setenv("PHB_CAPE_RESET_GRACE_S", "0")
    use_cape(monkeypatch, FakeCape(machine_after=("running", True)))
    job = sb.submit(conn, exe_attachment, "a", confirm=True)
    j = run_until_done(conn, job["id"])
    assert j["state"] == "reset_failed" and "not confirmed" in j["reset_detail"]


def test_snapshot_mismatch_is_reset_failure(conn, exe_attachment, monkeypatch):
    fake = FakeCape()
    use_cape(monkeypatch, fake, snapshot="clean")
    job = sb.submit(conn, exe_attachment, "a", confirm=True)
    sb.advance(conn, job["id"])  # submit
    sb.set_adapter_for_tests(CapeAdapter("http://cape.test", "t", "golden", transport=httpx.MockTransport(fake)))
    j = run_until_done(conn, job["id"])
    assert j["reset_status"] in ("failed",) or j["state"] == "reset_failed"


def test_timeout(conn, exe_attachment, monkeypatch):
    monkeypatch.setenv("PHB_CAPE_JOB_DEADLINE_S", "0")
    use_cape(monkeypatch, FakeCape(statuses=("running",)))
    job = sb.submit(conn, exe_attachment, "a", confirm=True, timeout_s=30)
    conn.execute("UPDATE sandbox_jobs SET deadline_at='2000-01-01T00:00:00+00:00' WHERE id=?", (job["id"],))
    conn.execute("UPDATE sandbox_jobs SET external_task_id='42' WHERE id=?", (job["id"],))
    j = run_until_done(conn, job["id"])
    assert j["state"] == "timed_out"


def test_cancel_before_and_during(conn, exe_attachment, monkeypatch):
    use_cape(monkeypatch, FakeCape(statuses=("running",)))
    j1 = sb.submit(conn, exe_attachment, "a", confirm=True)
    sb.request_cancel(conn, j1["id"])
    assert run_until_done(conn, j1["id"])["state"] == "cancelled"
    j2 = sb.submit(conn, exe_attachment, "a", confirm=True)
    sb.advance(conn, j2["id"])  # handed to engine
    sb.advance(conn, j2["id"])  # running
    sb.request_cancel(conn, j2["id"])
    fin = run_until_done(conn, j2["id"])
    assert fin["state"] == "cancelled" and fin["reset_status"] == "verified"


def test_queued_job_waits_for_reset_of_previous(conn, exe_attachment, monkeypatch):
    use_cape(monkeypatch, FakeCape(statuses=("running",)))
    a = sb.submit(conn, exe_attachment, "a", confirm=True)
    sb.advance(conn, a["id"])  # worker now busy
    b = sb.submit(conn, exe_attachment, "a", confirm=True)
    sb.advance(conn, b["id"])
    row = conn.execute("SELECT external_task_id, state_detail FROM sandbox_jobs WHERE id=?", (b["id"],)).fetchone()
    assert row["external_task_id"] is None and "waiting" in row["state_detail"]


def test_demo_results_are_always_labelled(conn, exe_attachment, monkeypatch):
    monkeypatch.setenv("PHB_SANDBOX_MODE", "demo")
    from app.config import reset_settings

    reset_settings()

    class LyingDemo(DemoAdapter):
        def results(self, external_id):
            r = super().results(external_id)
            r["is_demo"] = False  # an adapter must not be able to pass demo data off as real
            return r

    sb.set_adapter_for_tests(LyingDemo(run_seconds=0))
    job = sb.submit(conn, exe_attachment, "a", confirm=True)
    assert job["is_demo"] is True
    conn.execute("UPDATE sandbox_jobs SET submitted_at=submitted_at")
    for _ in range(20):
        if sb.advance(conn, job["id"]) is None:
            break
        time.sleep(0.6)
    j = conn.execute("SELECT * FROM sandbox_jobs WHERE id=?", (job["id"],)).fetchone()
    assert j["is_demo"] == 1 and j["state"] == "completed"
    assert json.loads(j["observations_json"])["is_demo"] is True


def test_api_marks_demo_vs_live(client, monkeypatch):
    monkeypatch.setenv("PHB_SANDBOX_MODE", "demo")
    from app.config import reset_settings

    reset_settings()
    st = client.get("/api/sandbox/status").json()
    assert st["is_demo"] is True and "DEMO" in st["capabilities"]["notes"][0]


def test_unsupported_type_refused(conn, monkeypatch):
    use_cape(monkeypatch, FakeCape())
    ev = services.import_email(conn, sample("06_encrypted_unsupported.eml"), "06.eml")["evidence_id"]
    drain(conn)
    seven = conn.execute("SELECT evidence_id FROM attachments WHERE email_evidence_id=? AND detected_type='7z'", (ev,)).fetchone()[0]
    with pytest.raises(sb.SubmissionRefused, match="cannot meaningfully run"):
        sb.submit(conn, seven, "a", confirm=True)
