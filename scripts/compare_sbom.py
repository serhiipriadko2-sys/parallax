#!/usr/bin/env python3
"""Compare two CycloneDX SBOM exports for dependency-inventory equality.

`uv export --format cyclonedx1.5` stamps a fresh random `serialNumber` and a
generation `metadata.timestamp` into every run, so a byte comparison of two
exports of the *same* locked graph can never succeed. Those two fields carry no
supply-chain meaning. Everything else — the component inventory, versions,
hashes, and dependency edges — is deterministic and is exactly what a drift
check must pin, so this comparator normalizes the volatile fields away and then
requires strict equality on the remainder.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

VOLATILE_TOP_LEVEL = ("serialNumber",)
VOLATILE_METADATA = ("timestamp",)


def normalize(document: Any) -> Any:
    """Return the document without fields that vary between identical exports."""
    if not isinstance(document, dict):
        raise ValueError("SBOM root must be a JSON object")
    normalized = {key: value for key, value in document.items() if key not in VOLATILE_TOP_LEVEL}
    metadata = normalized.get("metadata")
    if isinstance(metadata, dict):
        normalized["metadata"] = {
            key: value for key, value in metadata.items() if key not in VOLATILE_METADATA
        }
    return normalized


def load(path: Path) -> Any:
    return normalize(json.loads(path.read_text(encoding="utf-8")))


def component_ids(document: Any) -> set[str]:
    components = document.get("components")
    if not isinstance(components, list):
        return set()
    identifiers: set[str] = set()
    for item in components:
        if isinstance(item, dict):
            identifiers.add(str(item.get("purl") or f"{item.get('name')}@{item.get('version')}"))
    return identifiers


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("expected", type=Path)
    parser.add_argument("actual", type=Path)
    args = parser.parse_args()

    try:
        expected = load(args.expected)
        actual = load(args.actual)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, sort_keys=True))
        return 1

    if expected == actual:
        print(
            json.dumps(
                {"status": "PASS", "components": len(component_ids(actual))},
                sort_keys=True,
            )
        )
        return 0

    expected_ids = component_ids(expected)
    actual_ids = component_ids(actual)
    print(
        json.dumps(
            {
                "status": "FAIL",
                "error": "sbom_drift",
                "only_in_expected": sorted(expected_ids - actual_ids),
                "only_in_actual": sorted(actual_ids - expected_ids),
            },
            sort_keys=True,
        )
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
