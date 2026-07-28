#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "runtime"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(RUNTIME) not in sys.path:
    sys.path.insert(0, str(RUNTIME))

RUNTIME_MODULES = ("fastapi", "pydantic", "httpx")
OPENAI_MODULES = ("agents", "mcp")


def missing_modules(names: tuple[str, ...]) -> list[str]:
    return [name for name in names if importlib.util.find_spec(name) is None]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--profile",
        choices=("core", "runtime", "openai"),
        default="core",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    required: tuple[str, ...] = ()
    if args.profile in {"runtime", "openai"}:
        required += RUNTIME_MODULES
    if args.profile == "openai":
        required += OPENAI_MODULES
    missing = missing_modules(required)
    if missing:
        print(
            json.dumps(
                {
                    "status": "DEPENDENCY_MISSING",
                    "profile": args.profile,
                    "missing": missing,
                },
                ensure_ascii=False,
            )
        )
        return 2

    pattern = "test_*.py"
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), pattern=pattern)
    result = unittest.TextTestRunner(verbosity=2 if args.verbose else 1).run(suite)
    skipped = len(result.skipped)
    if args.profile in {"runtime", "openai"} and skipped:
        status = "FAIL"
    else:
        status = "PASS" if result.wasSuccessful() else "FAIL"
    summary = {
        "status": status,
        "profile": args.profile,
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": skipped,
    }
    print(json.dumps(summary, ensure_ascii=False))
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
