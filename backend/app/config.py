"""Runtime configuration.

All values can be overridden with environment variables prefixed ``PHB_``
(see ``backend/.env.example``). Defaults are deliberately conservative:
localhost-only binding, small upload limits, sandbox disabled.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader: KEY=VALUE lines; real environment variables win."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.split(" #", 1)[0].strip().strip('"').strip("'")
        os.environ.setdefault(key.strip(), value)


if "PYTEST_CURRENT_TEST" not in os.environ and not os.environ.get("PHB_NO_DOTENV"):
    _load_dotenv(BACKEND_ROOT / ".env")


def _env(name: str, default: str) -> str:
    return os.environ.get(f"PHB_{name}", default)


def _resolve(p: str) -> Path:
    path = Path(p)
    return (path if path.is_absolute() else BACKEND_ROOT / path).resolve()


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(default_factory=lambda: _resolve(_env("DATA_DIR", str(BACKEND_ROOT / "data"))))
    host: str = field(default_factory=lambda: _env("HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: _env_int("PORT", 8000))
    frontend_origin: str = field(default_factory=lambda: _env("FRONTEND_ORIGIN", "http://localhost:3000"))

    # Upload / evidence limits
    max_upload_bytes: int = field(default_factory=lambda: _env_int("MAX_UPLOAD_BYTES", 25 * 1024 * 1024))
    max_attachment_bytes: int = field(default_factory=lambda: _env_int("MAX_ATTACHMENT_BYTES", 20 * 1024 * 1024))

    # Static analysis worker limits
    static_timeout_s: int = field(default_factory=lambda: _env_int("STATIC_TIMEOUT_S", 20))
    static_memory_mb: int = field(default_factory=lambda: _env_int("STATIC_MEMORY_MB", 512))
    archive_max_depth: int = field(default_factory=lambda: _env_int("ARCHIVE_MAX_DEPTH", 3))
    archive_max_entries: int = field(default_factory=lambda: _env_int("ARCHIVE_MAX_ENTRIES", 500))
    archive_max_total_bytes: int = field(default_factory=lambda: _env_int("ARCHIVE_MAX_TOTAL_BYTES", 100 * 1024 * 1024))
    archive_max_ratio: int = field(default_factory=lambda: _env_int("ARCHIVE_MAX_RATIO", 100))
    max_strings: int = field(default_factory=lambda: _env_int("MAX_STRINGS", 300))

    # Sandbox
    sandbox_mode: str = field(default_factory=lambda: _env("SANDBOX_MODE", "disabled"))  # disabled | demo | cape
    cape_url: str = field(default_factory=lambda: _env("CAPE_URL", "http://192.168.56.10:8000"))
    cape_token: str = field(default_factory=lambda: _env("CAPE_TOKEN", ""))
    cape_machine: str = field(default_factory=lambda: _env("CAPE_MACHINE", "win10"))
    cape_snapshot: str = field(default_factory=lambda: _env("CAPE_SNAPSHOT", ""))
    cape_timeout_s: int = field(default_factory=lambda: _env_int("CAPE_TIMEOUT_S", 120))
    cape_job_deadline_s: int = field(default_factory=lambda: _env_int("CAPE_JOB_DEADLINE_S", 900))
    cape_reset_grace_s: int = field(default_factory=lambda: _env_int("CAPE_RESET_GRACE_S", 180))

    worker_poll_s: float = field(default_factory=lambda: float(_env("WORKER_POLL_S", "1.0")))

    @property
    def db_path(self) -> Path:
        return self.data_dir / "phishbench.sqlite3"

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / "evidence"

    @property
    def artifacts_dir(self) -> Path:
        return self.data_dir / "artifacts"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def reset_settings() -> None:
    """Used by tests after changing environment variables."""
    global _settings
    _settings = None
