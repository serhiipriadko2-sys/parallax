from __future__ import annotations

import sys
from pathlib import Path


def ensure_runtime_path() -> None:
    runtime = Path(__file__).resolve().parents[1] / "runtime"
    value = str(runtime)
    if value not in sys.path:
        sys.path.insert(0, value)
