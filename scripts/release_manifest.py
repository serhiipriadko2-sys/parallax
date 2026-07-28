#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import stat
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath

NOISE_NAMES = {".DS_Store", "Thumbs.db"}
NOISE_PARTS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "build"}
NOISE_SUFFIXES = {".pyc", ".pyo"}
MAX_FILES = 10_000
MAX_UNCOMPRESSED = 100 * 1024 * 1024
MAX_RATIO = 100.0


@dataclass(frozen=True)
class Entry:
    path: str
    bytes: int
    sha256: str


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_rel(name: str) -> PurePosixPath:
    rel = PurePosixPath(name)
    if not name or rel.is_absolute() or ".." in rel.parts or "\\" in name:
        raise ValueError(f"unsafe path: {name}")
    if any(part in NOISE_PARTS or part.endswith(".egg-info") for part in rel.parts):
        raise ValueError(f"generated noise: {name}")
    if rel.name in NOISE_NAMES or rel.suffix.lower() in NOISE_SUFFIXES:
        raise ValueError(f"generated noise: {name}")
    return rel


def inventory_directory(root: Path) -> list[Entry]:
    if not root.is_dir():
        raise ValueError(f"not a directory: {root}")
    entries: list[Entry] = []
    seen_case: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"symlink rejected: {path}")
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        validate_rel(rel)
        folded = rel.casefold()
        if folded in seen_case and seen_case[folded] != rel:
            raise ValueError(f"case-fold collision: {seen_case[folded]} vs {rel}")
        seen_case[folded] = rel
        entries.append(Entry(rel, path.stat().st_size, digest_file(path)))
    return bounded(entries)


def inventory_zip(path: Path) -> list[Entry]:
    if not zipfile.is_zipfile(path):
        raise ValueError(f"not a readable zip: {path}")
    entries: list[Entry] = []
    seen: set[str] = set()
    seen_case: dict[str, str] = {}
    total_uncompressed = 0
    with zipfile.ZipFile(path) as archive:
        bad = archive.testzip()
        if bad:
            raise ValueError(f"CRC failure: {bad}")
        for info in archive.infolist():
            if info.is_dir():
                continue
            rel = validate_rel(info.filename).as_posix()
            if rel in seen:
                raise ValueError(f"duplicate member: {rel}")
            seen.add(rel)
            folded = rel.casefold()
            if folded in seen_case and seen_case[folded] != rel:
                raise ValueError(f"case-fold collision: {seen_case[folded]} vs {rel}")
            seen_case[folded] = rel
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError(f"symlink member rejected: {rel}")
            total_uncompressed += info.file_size
            if info.compress_size == 0 and info.file_size > 0:
                raise ValueError(f"suspicious compression metadata: {rel}")
            if info.compress_size and info.file_size / info.compress_size > MAX_RATIO:
                raise ValueError(f"compression ratio exceeds limit: {rel}")
            data = archive.read(info)
            entries.append(Entry(rel, len(data), digest_bytes(data)))
    if total_uncompressed > MAX_UNCOMPRESSED:
        raise ValueError("archive uncompressed size exceeds limit")
    return bounded(entries)


def bounded(entries: list[Entry]) -> list[Entry]:
    if len(entries) > MAX_FILES:
        raise ValueError("file count exceeds limit")
    if sum(item.bytes for item in entries) > MAX_UNCOMPRESSED:
        raise ValueError("artifact bytes exceed limit")
    return entries


def inventory(path: Path) -> tuple[str, list[Entry]]:
    if path.is_dir():
        return "directory", inventory_directory(path)
    if path.is_file() and path.suffix.lower() == ".zip":
        return "zip", inventory_zip(path)
    raise ValueError(f"unsupported artifact: {path}")


def build(path: Path, output: Path) -> dict[str, object]:
    kind, entries = inventory(path)
    document = {
        "schema_version": "1.0",
        "artifact_name": path.name,
        "artifact_type": kind,
        "artifact_bytes": path.stat().st_size if path.is_file() else sum(e.bytes for e in entries),
        "artifact_sha256": digest_file(path) if path.is_file() else None,
        "file_count": len(entries),
        "content_bytes": sum(e.bytes for e in entries),
        "entries": [asdict(e) for e in entries],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return document


def verify(path: Path, manifest_path: Path) -> dict[str, object]:
    expected = json.loads(manifest_path.read_text(encoding="utf-8"))
    kind, entries = inventory(path)
    actual_entries = [asdict(e) for e in entries]
    errors: list[str] = []
    if expected.get("schema_version") != "1.0":
        errors.append("unsupported_manifest_schema")
    if expected.get("artifact_type") != kind:
        errors.append("artifact_type")
    if expected.get("file_count") != len(entries):
        errors.append("file_count")
    if expected.get("content_bytes") != sum(e.bytes for e in entries):
        errors.append("content_bytes")
    if expected.get("entries") != actual_entries:
        errors.append("entry_set_or_hash")
    if path.is_file():
        if expected.get("artifact_bytes") != path.stat().st_size:
            errors.append("artifact_bytes")
        if expected.get("artifact_sha256") != digest_file(path):
            errors.append("artifact_sha256")
    result = {"status": "PASS" if not errors else "FAIL", "errors": errors, "files": len(entries)}
    if errors:
        raise ValueError(json.dumps(result, sort_keys=True))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    build_parser = sub.add_parser("build")
    build_parser.add_argument("artifact", type=Path)
    build_parser.add_argument("--output", type=Path, required=True)
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("artifact", type=Path)
    verify_parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "build":
            result = build(args.artifact, args.output)
            print(json.dumps({"status": "PASS", "manifest": str(args.output), "files": result["file_count"]}))
        else:
            print(json.dumps(verify(args.artifact, args.manifest), sort_keys=True))
    except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        print(json.dumps({"status": "FAIL", "error": str(exc)}, sort_keys=True))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
