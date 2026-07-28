#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "runtime"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require", choices=("agents-sdk", "mcp", "all"), default="all")
    args = parser.parse_args()
    modules = []
    if args.require in {"agents-sdk", "all"}:
        modules.append("agents_sdk.agent")
    if args.require in {"mcp", "all"}:
        modules.append("adapters.mcp_server")

    imported = []
    errors = []
    for module in modules:
        try:
            importlib.import_module(module)
            imported.append(module)
        except Exception as exc:
            errors.append({"module": module, "error": f"{type(exc).__name__}: {exc}"})
    print(
        json.dumps(
            {
                "status": "PASS" if not errors else "FAIL",
                "imported": imported,
                "errors": errors,
            },
            ensure_ascii=False,
        )
    )
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
