#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys

REQUIRED = {
    "R0": ["trusted_policy"],
    "R1": ["trusted_policy"],
    "R2": ["trusted_policy", "current_evidence", "action_bound_approval"],
    "R3": [
        "trusted_policy",
        "current_evidence",
        "action_bound_approval",
        "current_state_read",
        "rollback_plan",
        "idempotency_key",
        "postcondition",
    ],
    "R4": [
        "trusted_policy",
        "current_evidence",
        "independent_source_classes",
        "action_bound_approval",
        "current_state_read",
        "rollback_plan",
        "idempotency_key",
        "postcondition",
        "dual_control",
    ],
}


def canonical_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def main() -> int:
    payload = json.load(sys.stdin)
    action = payload.get("action")
    gates = payload.get("gates")
    if not isinstance(action, dict) or not isinstance(gates, dict):
        raise SystemExit("input requires object fields: action, gates")
    risk = action.get("risk")
    if risk not in REQUIRED:
        raise SystemExit("risk must be R0-R4")
    missing = [name for name in REQUIRED[risk] if gates.get(name) is not True]
    irreversible = action.get("irreversible") is True
    if irreversible and "dual_control" not in REQUIRED[risk] and gates.get("dual_control") is not True:
        missing.append("dual_control")
    if missing and (risk == "R4" or irreversible):
        disposition = "proposal_only"
    elif missing:
        disposition = "require_approval" if risk in {"R2", "R3"} else "deny"
    else:
        disposition = "allow"
    print(
        json.dumps(
            {
                "disposition": disposition,
                "action_fingerprint": canonical_hash(action),
                "missing": sorted(set(missing)),
                "execution_performed": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
