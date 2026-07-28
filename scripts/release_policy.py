from __future__ import annotations

from pathlib import Path

EXCLUDE_NAMES = {"SHA256SUMS", "MANIFEST.json"}
NOISE_PARTS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "build"}
# Version-control metadata is never part of the release file set. Both the builder and the
# validator run from a repository root, so excluding it here keeps the two sides identical.
VCS_PARTS = {".git", ".hg", ".svn"}


def is_release_file(root: Path, path: Path) -> bool:
    if not path.is_file() or path.is_symlink() or path.name in EXCLUDE_NAMES:
        return False
    relative = path.relative_to(root)
    if path.suffix.lower() in {".pyc", ".pyo"}:
        return False
    if any(part in NOISE_PARTS or part.endswith(".egg-info") for part in relative.parts):
        return False
    return not any(part in VCS_PARTS for part in relative.parts)


def files_for_ledger(root: Path) -> list[Path]:
    return [path for path in sorted(root.rglob("*")) if is_release_file(root, path)]
