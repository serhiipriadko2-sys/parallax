#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from importlib import metadata
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5


def component(distribution: metadata.Distribution) -> dict[str, object]:
    name = distribution.metadata.get("Name") or distribution.metadata.get("Summary") or "unknown"
    version = distribution.version
    normalized = name.lower().replace("_", "-")
    return {
        "type": "library",
        "name": name,
        "version": version,
        "purl": f"pkg:pypi/{normalized}@{version}",
        "bom-ref": f"pkg:pypi/{normalized}@{version}",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    components = sorted(
        (component(dist) for dist in metadata.distributions()),
        key=lambda item: (str(item["name"]).lower(), str(item["version"])),
    )
    serial_seed = "|".join(str(item["bom-ref"]) for item in components)
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid5(NAMESPACE_URL, serial_seed)}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "parallax-omega-agent",
                "version": "1.0.0-rc.3",
            }
        },
        "components": components,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": "PASS", "components": len(components), "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
