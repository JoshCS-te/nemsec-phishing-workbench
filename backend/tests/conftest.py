from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(REPO / "samples"))
os.environ.setdefault("PHB_DATA_DIR", str(BACKEND / ".pytest-data" / "session"))


@pytest.fixture()
def data_dir(tmp_path, monkeypatch):
    from app.config import reset_settings

    monkeypatch.setenv("PHB_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PHB_SANDBOX_MODE", "disabled")
    reset_settings()
    yield tmp_path / "data"
    from app.sandbox import service

    service.set_adapter_for_tests(None)
    reset_settings()


@pytest.fixture()
def conn(data_dir):
    from app.db import connect, migrate

    migrate()
    c = connect()
    yield c
    c.close()


@pytest.fixture()
def client(data_dir):
    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app()) as c:
        yield c


def sample(name: str) -> bytes:
    return (REPO / "samples" / "emails" / name).read_bytes()


def make_email(headers: str, body: str = "hello") -> bytes:
    return (headers.strip("\n") + "\n\n" + body).replace("\n", "\r\n").encode("utf-8")
