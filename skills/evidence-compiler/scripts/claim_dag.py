#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from collections import defaultdict, deque
from datetime import datetime, timezone

ALLOWED_TYPES = {"FACT", "INTERP", "HYP", "UNKNOWN", "CONFLICT", "DECISION"}


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def main() -> int:
    data = json.load(sys.stdin)
    claims = data.get("claims")
    if not isinstance(claims, list):
        raise SystemExit("claims must be an array")
    ids = [item.get("id") for item in claims]
    if any(not isinstance(value, str) or not value for value in ids):
        raise SystemExit("every claim requires a non-empty id")
    if len(ids) != len(set(ids)):
        raise SystemExit("duplicate claim id")

    nodes = {item["id"]: item for item in claims}
    indegree = {key: 0 for key in nodes}
    edges: dict[str, list[str]] = defaultdict(list)
    errors: list[str] = []
    stale: list[str] = []
    as_of = parse_utc(data["as_of"]) if data.get("as_of") else datetime.now(timezone.utc)

    for key, item in nodes.items():
        if item.get("type") not in ALLOWED_TYPES:
            errors.append(f"{key}:invalid_type")
        confidence = item.get("confidence", 0.0)
        if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 0.95:
            errors.append(f"{key}:invalid_confidence")
        for dependency in item.get("dependencies", []):
            if dependency not in nodes:
                errors.append(f"{key}:missing_dependency:{dependency}")
                continue
            indegree[key] += 1
            edges[dependency].append(key)
        if item.get("type") == "FACT":
            evidence = item.get("evidence", [])
            if not evidence:
                errors.append(f"{key}:fact_without_evidence")
            current = False
            for ref in evidence:
                try:
                    observed = parse_utc(ref["observed_at"])
                    valid_until = parse_utc(ref["valid_until"]) if ref.get("valid_until") else None
                except (KeyError, TypeError, ValueError):
                    errors.append(f"{key}:invalid_evidence_time")
                    continue
                if observed <= as_of and (valid_until is None or valid_until >= as_of):
                    current = True
            if evidence and not current:
                stale.append(key)

    queue = deque(sorted(key for key, degree in indegree.items() if degree == 0))
    order: list[str] = []
    while queue:
        current = queue.popleft()
        order.append(current)
        for child in sorted(edges[current]):
            indegree[child] -= 1
            if indegree[child] == 0:
                queue.append(child)
    if len(order) != len(nodes):
        errors.append("cycle_detected")

    for key in order:
        item = nodes[key]
        dependencies = item.get("dependencies", [])
        if dependencies:
            ceiling = min(float(nodes[dep].get("confidence", 0.0)) for dep in dependencies)
            if float(item.get("confidence", 0.0)) > ceiling:
                errors.append(f"{key}:confidence_above_dependency_ceiling:{ceiling:.3f}")

    result = {
        "status": "PASS" if not errors and not stale else "FAIL",
        "acyclic": "cycle_detected" not in errors,
        "order": order,
        "stale_facts": stale,
        "errors": errors,
    }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
