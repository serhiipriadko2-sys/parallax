#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.0.0-rc.2"
FIXED_TIME = (2026, 7, 28, 0, 0, 0)
EXCLUDE_NAMES = {"SHA256SUMS", "MANIFEST.json"}
NOISE_PARTS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "build"}


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def is_release_file(path: Path) -> bool:
    if not path.is_file() or path.is_symlink() or path.name in EXCLUDE_NAMES:
        return False
    if path.suffix.lower() in {".pyc", ".pyo"}:
        return False
    if any(part in NOISE_PARTS or part.endswith(".egg-info") for part in path.parts):
        return False
    return True


def files_for_ledger() -> list[Path]:
    return [path for path in sorted(ROOT.rglob("*")) if is_release_file(path)]


def add_deterministic(archive: zipfile.ZipFile, path: Path, arcname: str) -> None:
    data = path.read_bytes()
    info = zipfile.ZipInfo(arcname, FIXED_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (0o100644 & 0xFFFF) << 16
    info.create_system = 3
    archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT.parent / f"{ROOT.name}-rc2.zip")
    args = parser.parse_args()

    files = files_for_ledger()
    (ROOT / "SHA256SUMS").write_text(
        "".join(f"{digest(path)}  {path.relative_to(ROOT).as_posix()}\n" for path in files),
        encoding="utf-8",
        newline="\n",
    )
    manifest = {
        "schema_version": "2.0",
        "name": ROOT.name,
        "version": VERSION,
        "status": "locally-verified-packaged-not-deployed-not-verified-live",
        "built_at": "2026-07-28",
        "file_count_ledger": len(files),
        "total_bytes_ledger": sum(path.stat().st_size for path in files),
        "knowledge_files": len(list((ROOT / "knowledge").glob("*.md"))),
        "skills": len(list((ROOT / "skills").glob("*/SKILL.md"))),
        "skill_archives": len(list((ROOT / "dist/skills").glob("*/skill.zip"))),
        "eval_cases": sum(1 for line in (ROOT / "evals/cases.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()),
        "behavioral_eval_status": "NOT_RUN",
        "security_default": "deny-all; writes-and-memory-not-exposed",
        "entrypoints": {
            "workspace_agent": "agent/WORKSPACE_AGENT_INSTRUCTIONS.md",
            "custom_gpt": "agent/CUSTOM_GPT_INSTRUCTIONS.md",
            "api": "runtime/parallax_omega/api.py",
            "mcp": "adapters/mcp_server.py",
            "agents_sdk": "agents_sdk/agent.py",
        },
    }
    (ROOT / "MANIFEST.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.output.exists():
        args.output.unlink()
    include = files + [ROOT / "SHA256SUMS", ROOT / "MANIFEST.json"]
    with zipfile.ZipFile(args.output, "w") as archive:
        for path in sorted(include):
            add_deterministic(
                archive,
                path,
                f"{ROOT.name}/{path.relative_to(ROOT).as_posix()}",
            )
    print(json.dumps({
        "zip": str(args.output),
        "bytes": args.output.stat().st_size,
        "sha256": digest(args.output),
        "files": len(include),
        "source_date_epoch": os.environ.get("SOURCE_DATE_EPOCH", "fixed:2026-07-28"),
    }, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
