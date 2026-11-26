"""One-line JSON audit logging.

Never pass tokens, passwords, community strings, hashes, or raw credential
material to this module.  Callers pass the already-redacted argv.
"""

from __future__ import annotations

import json
import sys
import threading
from datetime import datetime, timezone
from typing import Any

_lock = threading.Lock()


def audit(level: str, **fields: Any) -> None:
    event = {
        "ts": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "level": level,
    }
    event.update(fields)
    line = json.dumps(event, ensure_ascii=False, separators=(",", ":"), default=str)
    with _lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()
