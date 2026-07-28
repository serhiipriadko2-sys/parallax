#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "adapters/mcp_server.py"
DEFAULT_MANIFEST = ROOT / "mcp/tool-manifest.json"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def annotation_text(node: ast.expr | None) -> str | None:
    return ast.unparse(node) if node is not None else None


def is_mcp_tool(node: ast.FunctionDef) -> bool:
    for decorator in node.decorator_list:
        if (
            isinstance(decorator, ast.Call)
            and isinstance(decorator.func, ast.Attribute)
            and decorator.func.attr == "tool"
        ):
            return True
    return False


def descriptor(node: ast.FunctionDef) -> dict[str, object]:
    defaults_offset = len(node.args.args) - len(node.args.defaults)
    parameters: list[dict[str, object]] = []
    for index, argument in enumerate(node.args.args):
        default_index = index - defaults_offset
        default = None
        required = default_index < 0
        if not required:
            default = ast.unparse(node.args.defaults[default_index])
        parameters.append(
            {
                "name": argument.arg,
                "annotation": annotation_text(argument.annotation),
                "required": required,
                "default": default,
            }
        )
    return {
        "name": node.name,
        "description": ast.get_docstring(node, clean=True) or "",
        "parameters": parameters,
        "returns": annotation_text(node.returns),
    }


def current_document() -> dict[str, object]:
    source_bytes = SOURCE.read_bytes()
    tree = ast.parse(source_bytes.decode("utf-8"), filename=str(SOURCE))
    tools = [descriptor(node) for node in tree.body if isinstance(node, ast.FunctionDef) and is_mcp_tool(node)]
    payload = {
        "schema_version": "1.0",
        "surface": "mcp",
        "version": "1.0.0-rc.3",
        "source": "adapters/mcp_server.py",
        "source_sha256": sha256_bytes(source_bytes),
        "tools": sorted(tools, key=lambda item: str(item["name"])),
        "attestation": {
            "required": True,
            "type": "github-build-provenance",
            "subject": "mcp/tool-manifest.json",
        },
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload["manifest_payload_sha256"] = sha256_bytes(canonical)
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("build", "verify"))
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    current = current_document()
    if args.command == "build":
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({"status": "PASS", "manifest": str(args.manifest), "tools": len(current["tools"])}))
        return 0
    expected = json.loads(args.manifest.read_text(encoding="utf-8"))
    status = "PASS" if expected == current else "FAIL"
    print(json.dumps({"status": status, "manifest": str(args.manifest)}, sort_keys=True))
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
