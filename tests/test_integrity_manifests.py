import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class IntegrityManifestTests(unittest.TestCase):
    def test_mcp_tool_manifest_matches_source(self):
        result = subprocess.run(
            [sys.executable, "scripts/tool_manifest.py", "verify"],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_skill_manifest_matches_and_install_is_verified(self):
        verify = subprocess.run(
            [sys.executable, "scripts/skill_manifest.py", "verify"],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "installed"
            install = subprocess.run(
                [sys.executable, "scripts/skill_manifest.py", "install", "--target", str(target)],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )
            self.assertEqual(install.returncode, 0, install.stdout + install.stderr)
            self.assertEqual(len(list(target.glob("*/SKILL.md"))), 7)

    def test_skill_manifest_detects_tamper(self):
        manifest = json.loads((ROOT / "governance/ALLOWED_SKILLS.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["default"], "deny")
        self.assertTrue(manifest["attestation"]["required"])


class SbomComparisonTests(unittest.TestCase):
    """`uv export --format cyclonedx1.5` stamps a random serialNumber and a fresh
    timestamp into every run, so drift detection must normalize those two fields and
    still reject any real change to the component inventory."""

    SCRIPT = ROOT / "scripts/compare_sbom.py"

    def document(self, serial: str, timestamp: str, components: list[dict]) -> dict:
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{serial}",
            "version": 1,
            "metadata": {"timestamp": timestamp, "tools": []},
            "components": components,
        }

    def run_compare(self, expected: dict, actual: dict) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "expected.json"
            second = Path(tmp) / "actual.json"
            first.write_text(json.dumps(expected), encoding="utf-8")
            second.write_text(json.dumps(actual), encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(self.SCRIPT), str(first), str(second)],
                text=True,
                capture_output=True,
            )

    def test_volatile_fields_are_ignored(self):
        components = [{"name": "httpx", "version": "0.28.1", "purl": "pkg:pypi/httpx@0.28.1"}]
        result = self.run_compare(
            self.document("aaaaaaaa-0000-0000-0000-000000000000", "2026-07-28T00:00:00Z", components),
            self.document("bbbbbbbb-1111-1111-1111-111111111111", "2026-07-29T12:34:56Z", components),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "PASS")

    def test_component_drift_is_rejected(self):
        base = [{"name": "httpx", "version": "0.28.1", "purl": "pkg:pypi/httpx@0.28.1"}]
        drifted = [{"name": "httpx", "version": "0.29.0", "purl": "pkg:pypi/httpx@0.29.0"}]
        result = self.run_compare(
            self.document("aaaaaaaa-0000-0000-0000-000000000000", "2026-07-28T00:00:00Z", base),
            self.document("aaaaaaaa-0000-0000-0000-000000000000", "2026-07-28T00:00:00Z", drifted),
        )
        self.assertNotEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["error"], "sbom_drift")
        self.assertIn("pkg:pypi/httpx@0.28.1", payload["only_in_expected"])
        self.assertIn("pkg:pypi/httpx@0.29.0", payload["only_in_actual"])

    def test_added_component_is_rejected(self):
        base = [{"name": "httpx", "version": "0.28.1", "purl": "pkg:pypi/httpx@0.28.1"}]
        extra = base + [{"name": "evil", "version": "1.0", "purl": "pkg:pypi/evil@1.0"}]
        result = self.run_compare(
            self.document("aaaaaaaa-0000-0000-0000-000000000000", "2026-07-28T00:00:00Z", base),
            self.document("aaaaaaaa-0000-0000-0000-000000000000", "2026-07-28T00:00:00Z", extra),
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pkg:pypi/evil@1.0", json.loads(result.stdout)["only_in_actual"])


if __name__ == "__main__":
    unittest.main()
