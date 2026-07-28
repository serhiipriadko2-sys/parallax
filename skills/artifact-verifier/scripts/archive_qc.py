#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import stat
import zipfile
from pathlib import Path, PurePosixPath

NOISE = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".DS_Store", "Thumbs.db"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--max-files", type=int, default=5000)
    parser.add_argument("--max-uncompressed-bytes", type=int, default=100_000_000)
    parser.add_argument("--max-ratio", type=float, default=200.0)
    args = parser.parse_args()

    errors: list[str] = []
    names: set[str] = set()
    folded: dict[str, str] = {}
    total_uncompressed = 0
    with zipfile.ZipFile(args.archive) as archive:
        bad_crc = archive.testzip()
        if bad_crc:
            errors.append(f"crc:{bad_crc}")
        infos = archive.infolist()
        if len(infos) > args.max_files:
            errors.append("file_count_limit")
        for info in infos:
            name = info.filename
            rel = PurePosixPath(name)
            if rel.is_absolute() or ".." in rel.parts:
                errors.append(f"unsafe_path:{name}")
            if name in names:
                errors.append(f"duplicate_member:{name}")
            names.add(name)
            key = name.casefold()
            if key in folded and folded[key] != name:
                errors.append(f"case_collision:{folded[key]}:{name}")
            folded[key] = name
            if any(part in NOISE or part.endswith(".egg-info") for part in rel.parts):
                errors.append(f"generated_noise:{name}")
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                errors.append(f"symlink:{name}")
            total_uncompressed += info.file_size
            if info.compress_size == 0:
                ratio = float("inf") if info.file_size else 1.0
            else:
                ratio = info.file_size / info.compress_size
            if ratio > args.max_ratio:
                errors.append(f"compression_ratio:{name}:{ratio:.1f}")
    if total_uncompressed > args.max_uncompressed_bytes:
        errors.append("uncompressed_size_limit")

    result = {
        "status": "PASS" if not errors else "FAIL",
        "archive": str(args.archive),
        "bytes": args.archive.stat().st_size,
        "sha256": sha256(args.archive),
        "members": len(names),
        "uncompressed_bytes": total_uncompressed,
        "errors": errors,
    }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
