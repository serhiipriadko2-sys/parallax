#!/usr/bin/env python3
from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import hashlib
import json
import re
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

from release_policy import VCS_PARTS, files_for_ledger

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.0.0-rc.3"
REQUIRED = [
    "README.md", "ARCHITECTURE.md", "SECURITY.md", "PRIVACY.md", "LICENSE",
    "pyproject.toml", "agent/WORKSPACE_AGENT_INSTRUCTIONS.md",
    "agent/CUSTOM_GPT_INSTRUCTIONS.md", "actions/openapi.yaml",
    "runtime/parallax_omega/claim_graph.py", "runtime/parallax_omega/policy.py",
    "policy/host-policy.schema.json", "governance/ASSURANCE_CASE.md",
    "threat-model/THREAT_MODEL.md", "evals/cases.jsonl", "evals/cases.schema.json",
    "scripts/release_manifest.py",
]
NOISE_PARTS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "build"}
NOISE_NAMES = {".DS_Store", "Thumbs.db"}
# yaml.YAMLError only exists when PyYAML imported; build the handler tuple once so the
# `except` clause stays a plain tuple of exception classes.
SKILL_PARSE_ERRORS: tuple[type[BaseException], ...] = (
    (ValueError, RuntimeError, yaml.YAMLError) if yaml is not None else (ValueError, RuntimeError)
)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fail(errors: list[str], item: str) -> None:
    if item not in errors:
        errors.append(item)


def parse_frontmatter(path: Path) -> dict[str, object]:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        raise ValueError("missing YAML frontmatter")
    raw = text.split("\n---\n", 1)[0][4:]
    if yaml is None:
        raise RuntimeError("PyYAML is required for package validation")
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise ValueError("frontmatter must be an object")
    return data


def parse_ledger_text(text: str, errors: list[str], label: str) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        try:
            digest, rel = line.split("  ", 1)
        except ValueError:
            fail(errors, f"{label}_format:{line_number}")
            continue
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest.lower()):
            fail(errors, f"{label}_digest:{line_number}")
            continue
        if not rel or rel in entries:
            fail(errors, f"{label}_duplicate:{rel or line_number}")
            continue
        entries[rel] = digest.lower()
    return entries


def validate_embedded_ledger(
    archive: zipfile.ZipFile,
    names: set[str],
    errors: list[str],
    label: str,
) -> None:
    ledger_members = sorted(name for name in names if name.endswith("SHA256SUMS"))
    if not ledger_members:
        return
    if len(ledger_members) != 1:
        fail(errors, f"embedded_ledger_count:{label}")
        return
    ledger_member = ledger_members[0]
    prefix = ledger_member[: -len("SHA256SUMS")]
    manifest_member = f"{prefix}MANIFEST.json"
    if manifest_member not in names:
        fail(errors, f"embedded_manifest_missing:{label}")
        return
    outside = sorted(name for name in names if not name.startswith(prefix))
    for name in outside:
        fail(errors, f"zip_outside_release_root:{label}:{name}")

    entries = parse_ledger_text(
        archive.read(ledger_member).decode("utf-8"), errors, f"embedded_ledger:{label}"
    )
    payload = {
        name[len(prefix):]
        for name in names
        if name.startswith(prefix) and name not in {ledger_member, manifest_member}
    }
    ledger_set = set(entries)
    for rel in sorted(payload - ledger_set):
        fail(errors, f"embedded_unlisted_file:{label}:{rel}")
    for rel in sorted(ledger_set - payload):
        fail(errors, f"embedded_missing_file:{label}:{rel}")
    for rel, digest in entries.items():
        member = f"{prefix}{rel}"
        if member in names and hashlib.sha256(archive.read(member)).hexdigest() != digest:
            fail(errors, f"embedded_hash:{label}:{rel}")
    try:
        manifest = json.loads(archive.read(manifest_member).decode("utf-8"))
        if manifest.get("file_count_ledger") != len(entries):
            fail(errors, f"embedded_manifest_ledger_count:{label}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail(errors, f"embedded_manifest_parse:{label}")


def validate_zip(path: Path, errors: list[str]) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            label = path.relative_to(ROOT).as_posix()
            if archive.testzip():
                fail(errors, f"zip_crc:{label}")
            names: set[str] = set()
            folded: dict[str, str] = {}
            for info in archive.infolist():
                if info.is_dir():
                    continue
                rel = PurePosixPath(info.filename)
                if rel.is_absolute() or ".." in rel.parts or "\\" in info.filename:
                    fail(errors, f"unsafe_zip:{label}:{info.filename}")
                if info.filename in names:
                    fail(errors, f"duplicate_zip:{label}:{info.filename}")
                names.add(info.filename)
                key = info.filename.casefold()
                if key in folded and folded[key] != info.filename:
                    fail(errors, f"case_collision_zip:{label}:{info.filename}")
                folded[key] = info.filename
            validate_embedded_ledger(archive, names, errors, label)
    except (zipfile.BadZipFile, UnicodeDecodeError):
        fail(errors, f"bad_zip:{path.relative_to(ROOT)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-ledger", action="store_true")
    args = parser.parse_args()
    errors: list[str] = []

    for rel in REQUIRED:
        path = ROOT / rel
        if not path.is_file() or path.stat().st_size == 0:
            fail(errors, f"missing_or_empty:{rel}")

    paths = [
        path
        for path in ROOT.rglob("*")
        if path.is_file()
        and not any(part in VCS_PARTS for part in path.relative_to(ROOT).parts)
    ]
    folded: dict[str, str] = {}
    for path in paths:
        rel = path.relative_to(ROOT).as_posix()
        if path.is_symlink():
            fail(errors, f"symlink:{rel}")
        if path.name in NOISE_NAMES or any(part in NOISE_PARTS or part.endswith(".egg-info") for part in path.parts):
            fail(errors, f"generated_noise:{rel}")
        if path.suffix.lower() in {".pyc", ".pyo"}:
            fail(errors, f"generated_noise:{rel}")
        key = rel.casefold()
        if key in folded and folded[key] != rel:
            fail(errors, f"case_collision:{folded[key]}:{rel}")
        folded[key] = rel

    if len(list((ROOT / "knowledge").glob("*.md"))) != 10:
        fail(errors, "knowledge_count")
    skill_dirs = sorted(path for path in (ROOT / "skills").iterdir() if path.is_dir())
    if len(skill_dirs) != 7:
        fail(errors, "skill_count")
    for skill in skill_dirs:
        for rel in ("SKILL.md", "agents/openai.yaml", "assets/icon.svg"):
            if not (skill / rel).is_file():
                fail(errors, f"skill_missing:{skill.name}/{rel}")
        try:
            frontmatter = parse_frontmatter(skill / "SKILL.md")
            if set(frontmatter) != {"name", "description"}:
                fail(errors, f"skill_frontmatter_fields:{skill.name}")
            if frontmatter.get("name") != skill.name:
                fail(errors, f"skill_name:{skill.name}")
            description = frontmatter.get("description")
            if not isinstance(description, str) or len(description.split()) < 20:
                fail(errors, f"skill_description:{skill.name}")
            if yaml is not None:
                metadata = yaml.safe_load((skill / "agents/openai.yaml").read_text(encoding="utf-8"))
                if not isinstance(metadata, dict) or "interface" not in metadata:
                    fail(errors, f"skill_openai_yaml:{skill.name}")
        except SKILL_PARSE_ERRORS:
            fail(errors, f"skill_parse:{skill.name}")

    try:
        config = json.loads((ROOT / "agent/custom-gpt-config.json").read_text(encoding="utf-8"))
        for rel in config["knowledge_files"]:
            if not (ROOT / rel).is_file():
                fail(errors, f"bad_config_ref:{rel}")
    except (json.JSONDecodeError, KeyError, TypeError):
        fail(errors, "custom_gpt_config_parse")

    try:
        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        if pyproject["project"]["version"] != "1.0.0rc3":
            fail(errors, "pyproject_version")
    except (tomllib.TOMLDecodeError, KeyError, TypeError):
        fail(errors, "pyproject_parse")

    if yaml is None:
        fail(errors, "pyyaml_dependency_missing")
    else:
        try:
            openapi = yaml.safe_load((ROOT / "actions/openapi.yaml").read_text(encoding="utf-8"))
            paths_object = openapi.get("paths", {})
            if set(paths_object) != {"/health", "/v1/actions/preflight", "/v1/memory/candidates"}:
                fail(errors, "openapi_paths")
            serialized = json.dumps(openapi, sort_keys=True)
            for forbidden in ("policy_allows", "dual_control", "approval_fingerprint", "/execute", "/commit"):
                if forbidden in serialized:
                    fail(errors, f"openapi_authority_field:{forbidden}")
            schemas = openapi.get("components", {}).get("schemas", {})
            for name in ("ActionProposal", "MemoryProposal"):
                if schemas.get(name, {}).get("additionalProperties") is not False:
                    fail(errors, f"openapi_additional_properties:{name}")
        except (yaml.YAMLError, AttributeError, TypeError):
            fail(errors, "openapi_parse")

    text_files = [p for p in paths if p.suffix.lower() in {".md", ".json", ".yaml", ".yml", ".toml", ".py"} and p != Path(__file__).resolve()]
    combined = "\n".join(p.read_text(encoding="utf-8", errors="ignore") for p in text_files)
    if re.search(r"(?i)status:\s*verified-live", combined):
        fail(errors, "unearned_verified_live")
    if "example.invalid" in combined:
        fail(errors, "placeholder_example_invalid")
    if re.search(r"(?m)^\s*(TODO|FIXME)\b", combined):
        fail(errors, "todo_marker")
    if combined.count("https://YOUR_DEPLOYMENT.example.com") != 1:
        fail(errors, "deployment_placeholder_count")

    for zip_path in ROOT.rglob("*.zip"):
        validate_zip(zip_path, errors)

    if not args.skip_ledger:
        sums = ROOT / "SHA256SUMS"
        manifest_path = ROOT / "MANIFEST.json"
        if not sums.is_file() or not manifest_path.is_file():
            fail(errors, "ledger_missing")
        else:
            entries = parse_ledger_text(
                sums.read_text(encoding="utf-8"), errors, "ledger"
            )
            disk_files = files_for_ledger(ROOT)
            disk_set = {path.relative_to(ROOT).as_posix() for path in disk_files}
            ledger_set = set(entries)
            for rel in sorted(disk_set - ledger_set):
                fail(errors, f"unlisted_file:{rel}")
            for rel in sorted(ledger_set - disk_set):
                fail(errors, f"ledger_missing_file:{rel}")
            for rel, digest in entries.items():
                path = ROOT / rel
                if path.is_file() and sha(path) != digest:
                    fail(errors, f"hash:{rel}")
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                if manifest.get("version") != VERSION:
                    fail(errors, "manifest_version")
                if manifest.get("file_count_ledger") != len(entries):
                    fail(errors, "manifest_ledger_count")
                if manifest.get("file_count_ledger") != len(disk_set):
                    fail(errors, "manifest_disk_count")
                if manifest.get("total_bytes_ledger") != sum(
                    path.stat().st_size for path in disk_files
                ):
                    fail(errors, "manifest_ledger_bytes")
                if manifest.get("eval_cases") != 74:
                    fail(errors, "manifest_eval_count")
            except json.JSONDecodeError:
                fail(errors, "manifest_parse")

    result = {
        "status": "PASS" if not errors else "FAIL",
        "version": VERSION,
        "errors": sorted(errors),
        "files": len(paths),
    }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
