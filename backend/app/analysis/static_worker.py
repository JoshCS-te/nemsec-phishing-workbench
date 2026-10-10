"""Child-process entry point for static analysis.

Usage (by runner.py only):  python -m app.analysis.static_worker <limits-json>
The attachment bytes arrive on stdin; JSON checkpoints are written to stdout,
one per line. The parent enforces wall-clock and memory limits and keeps the
last checkpoint if this process has to be killed.
"""
from __future__ import annotations

import json
import os
import sys
import time


def main() -> int:
    params = json.loads(sys.argv[1])
    if os.name == "posix" and params.get("memory_mb"):
        try:
            import resource

            limit = int(params["memory_mb"]) * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except Exception:
            pass

    from .static import Limits, analyse

    data = sys.stdin.buffer.read()
    delay = float(os.environ.get("PHB_STATIC_TEST_DELAY_S", "0") or 0)  # test hook: simulate a slow parser

    def checkpoint(result: dict) -> None:
        sys.stdout.write(json.dumps(result, default=str) + "\n")
        sys.stdout.flush()
        if delay and "strings" in result.get("stages_completed", []):
            time.sleep(delay)

    limits = Limits(params["max_depth"], params["max_entries"], params["max_total"], params["max_ratio"], params["max_strings"])
    analyse(data, params.get("filename"), params.get("declared_mime"), limits, checkpoint)
    return 0


if __name__ == "__main__":
    sys.exit(main())
