"""Keep credentials and tokens out of logs and the history table."""
from __future__ import annotations

import logging
import re
from typing import Any

SENSITIVE_KEYS = re.compile(r"(token|secret|password|passwd|authorization|api[_-]?key|cookie|credential)", re.I)
INLINE_PATTERNS = [
    (re.compile(r"(Authorization:\s*)(Token|Bearer)\s+\S+", re.I), r"\1\2 [REDACTED]"),
    (re.compile(r"((?:token|api[_-]?key|password)=)[^&\s]+", re.I), r"\1[REDACTED]"),
    # credentials embedded in URLs: scheme://user:pass@host
    (re.compile(r"(\b[a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@", re.I), r"\1\2:[REDACTED]@"),
]


def redact_text(text: str) -> str:
    for pat, repl in INLINE_PATTERNS:
        text = pat.sub(repl, text)
    return text


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if SENSITIVE_KEYS.search(str(k)) else redact(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage()
        except Exception:
            return True
        record.msg = redact_text(msg)
        record.args = ()
        return True


def setup_logging(level: int = logging.INFO) -> None:
    root = logging.getLogger()
    if not any(isinstance(f, RedactingFilter) for h in root.handlers for f in h.filters):
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        handler.addFilter(RedactingFilter())
        root.addHandler(handler)
    root.setLevel(level)
