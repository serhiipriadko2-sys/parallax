#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {
    "openai_key": re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "private_key": re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"),
    "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
}
SKIP = {"SHA256SUMS", "MANIFEST.json", "PACKAGE_RECEIPT.md", "QC_REPORT.md"}


def main() -> int:
    findings = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.name in SKIP or ".git" in path.parts:
            continue
        if path.suffix.lower() in {".zip", ".png", ".jpg", ".jpeg", ".webp"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for name, pattern in PATTERNS.items():
            if pattern.search(text):
                findings.append(f"{path.relative_to(ROOT)}:{name}")
    if findings:
        print("FAIL", *findings, sep="\n")
        return 1
    print("PASS: no credential-shaped secrets found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
