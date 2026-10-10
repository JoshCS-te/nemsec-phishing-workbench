"""SQLite access + tiny migration runner.

Migrations are numbered ``.sql`` files in ``app/migrations``; each is applied
once inside a transaction and recorded in ``schema_migrations``.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .config import get_settings

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(5).upper()}"


def connect() -> sqlite3.Connection:
    s = get_settings()
    s.data_dir.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(s.db_path, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def migrate() -> list[str]:
    applied: list[str] = []
    with get_conn() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)")
        done = {r["version"] for r in conn.execute("SELECT version FROM schema_migrations")}
        for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
            version = path.stem
            if version in done:
                continue
            sql = path.read_text(encoding="utf-8")
            conn.execute("BEGIN IMMEDIATE")
            try:
                for stmt in _split_sql(sql):
                    conn.execute(stmt)
                conn.execute("INSERT INTO schema_migrations VALUES (?, ?)", (version, utcnow()))
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            applied.append(version)
    return applied


def _split_sql(sql: str) -> list[str]:
    lines = [ln for ln in sql.splitlines() if not ln.strip().startswith("--")]
    return [s.strip() for s in "\n".join(lines).split(";") if s.strip()]


def row_to_dict(row: sqlite3.Row | None, json_fields: tuple[str, ...] = ()) -> dict[str, Any] | None:
    if row is None:
        return None
    d = dict(row)
    for f in json_fields:
        if f in d and isinstance(d[f], str):
            try:
                d[f] = json.loads(d[f])
            except json.JSONDecodeError:
                pass
    return d


def record_history(conn: sqlite3.Connection, entity_type: str, entity_id: str, action: str,
                   detail: dict[str, Any] | None = None, case_id: str | None = None) -> None:
    from .logsafe import redact

    conn.execute(
        "INSERT INTO history (case_id, entity_type, entity_id, action, detail_json, at) VALUES (?,?,?,?,?,?)",
        (case_id, entity_type, entity_id, action, json.dumps(redact(detail or {})), utcnow()),
    )
