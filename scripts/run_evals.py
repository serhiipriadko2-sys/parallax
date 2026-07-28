#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "id", "schema_version", "category", "severity", "mode", "prompt",
    "oracle", "control_refs", "tags",
}
REQUIRED_CATEGORIES = {
    "truth", "security", "action", "memory", "status", "artifact", "degrade",
    "privacy", "receipt", "governance", "highstakes", "multiagent", "metrics",
    "fork", "voice", "authority",
}
REQUIRED_CONTROLS = {
    "AUTH-HOST-OWNED", "AUTH-EXACT-ALLOWLIST", "TRUTH-TEMPORAL",
    "MEM-CANDIDATE-BINDING", "REC-TAMPER-EVIDENCE", "REL-TEST-SEMANTICS",
}


def main() -> int:
    cases: list[dict[str, object]] = []
    path = ROOT / "evals/cases.jsonl"
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        case = json.loads(line)
        if set(case) != REQUIRED:
            raise SystemExit(f"line {lineno}: fields differ: {sorted(set(case) ^ REQUIRED)}")
        if not re.fullmatch(r"E\d{3}", str(case["id"])):
            raise SystemExit(f"line {lineno}: invalid id")
        if case["schema_version"] != "2.0" or case["mode"] != "behavioral_manual":
            raise SystemExit(f"line {lineno}: unsupported schema or mode")
        if case["severity"] not in {"low", "medium", "high", "critical"}:
            raise SystemExit(f"line {lineno}: invalid severity")
        for key in ("category", "prompt"):
            if not isinstance(case[key], str) or not case[key].strip():
                raise SystemExit(f"line {lineno}: empty {key}")
        oracle = case["oracle"]
        if not isinstance(oracle, dict) or set(oracle) != {"required_behaviors", "forbidden_behaviors"}:
            raise SystemExit(f"line {lineno}: invalid oracle")
        for key in ("required_behaviors", "forbidden_behaviors"):
            values = oracle[key]
            if not isinstance(values, list) or not values or not all(isinstance(v, str) and v.strip() for v in values):
                raise SystemExit(f"line {lineno}: invalid oracle.{key}")
        for key in ("control_refs", "tags"):
            values = case[key]
            if not isinstance(values, list) or not values or len(values) != len(set(values)):
                raise SystemExit(f"line {lineno}: invalid {key}")
        cases.append(case)

    ids = [str(case["id"]) for case in cases]
    if len(ids) != len(set(ids)):
        raise SystemExit("duplicate eval id")
    categories = Counter(str(case["category"]) for case in cases)
    missing_categories = REQUIRED_CATEGORIES - categories.keys()
    if missing_categories:
        raise SystemExit(f"missing categories: {sorted(missing_categories)}")
    controls = {str(control) for case in cases for control in case["control_refs"]}
    missing_controls = REQUIRED_CONTROLS - controls
    if missing_controls:
        raise SystemExit(f"missing controls: {sorted(missing_controls)}")
    if len(cases) < 70:
        raise SystemExit("at least 70 evals required")

    print(json.dumps({
        "status": "SCHEMA_PASS",
        "behavioral_status": "NOT_RUN",
        "cases": len(cases),
        "categories": dict(sorted(categories.items())),
        "control_refs": len(controls),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
