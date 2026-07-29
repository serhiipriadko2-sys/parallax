#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
DEFAULT_MANIFEST = ROOT / "governance/ALLOWED_SKILLS.json"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def skill_entry(directory: Path) -> dict[str, object]:
    files = []
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"symlink rejected: {path}")
        if path.is_file():
            files.append(
                {
                    "path": path.relative_to(directory).as_posix(),
                    "bytes": path.stat().st_size,
                    "sha256": digest(path),
                }
            )
    payload = json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "name": directory.name,
        "tree_sha256": hashlib.sha256(payload).hexdigest(),
        "files": files,
    }


def current_document() -> dict[str, object]:
    entries = [skill_entry(path) for path in sorted(SKILLS.iterdir()) if path.is_dir()]
    return {
        "schema_version": "1.0",
        "version": "1.0.0-rc.3",
        "default": "deny",
        "skills": entries,
        "attestation": {
            "required": True,
            "type": "github-build-provenance",
            "subject": "governance/ALLOWED_SKILLS.json",
        },
    }


def verify(manifest: Path) -> None:
    expected = json.loads(manifest.read_text(encoding="utf-8"))
    if expected != current_document():
        raise ValueError("skill_manifest_mismatch")


def install(manifest: Path, target: Path) -> None:
    verify(manifest)
    if target.exists() and any(target.iterdir()):
        raise ValueError("install target must be empty")
    target.mkdir(parents=True, exist_ok=True)
    for source in sorted(SKILLS.iterdir()):
        if source.is_dir():
            shutil.copytree(source, target / source.name)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("build", "verify", "install"))
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--target", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "build":
            args.manifest.parent.mkdir(parents=True, exist_ok=True)
            args.manifest.write_text(
                json.dumps(current_document(), indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        elif args.command == "verify":
            verify(args.manifest)
        else:
            if args.target is None:
                raise ValueError("--target is required for install")
            install(args.manifest, args.target)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"status": "PASS", "command": args.command}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
