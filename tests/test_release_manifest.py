import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/release_manifest.py"


class ReleaseManifestTests(unittest.TestCase):
    def test_directory_manifest_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "artifact"
            artifact.mkdir()
            (artifact / "a.txt").write_text("alpha", encoding="utf-8")
            manifest = Path(tmp) / "manifest.json"
            build = subprocess.run([sys.executable, str(SCRIPT), "build", str(artifact), "--output", str(manifest)], text=True, capture_output=True)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            verify = subprocess.run([sys.executable, str(SCRIPT), "verify", str(artifact), "--manifest", str(manifest)], text=True, capture_output=True)
            self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
            self.assertEqual(json.loads(verify.stdout)["status"], "PASS")

    def test_manifest_detects_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            artifact = Path(tmp) / "artifact"
            artifact.mkdir()
            target = artifact / "a.txt"
            target.write_text("alpha", encoding="utf-8")
            manifest = Path(tmp) / "manifest.json"
            subprocess.run([sys.executable, str(SCRIPT), "build", str(artifact), "--output", str(manifest)], check=True, capture_output=True)
            target.write_text("beta", encoding="utf-8")
            verify = subprocess.run([sys.executable, str(SCRIPT), "verify", str(artifact), "--manifest", str(manifest)], text=True, capture_output=True)
            self.assertNotEqual(verify.returncode, 0)

    def test_zip_rejects_case_collision(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "bad.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("Foo.md", "a")
                zf.writestr("foo.md", "b")
            manifest = Path(tmp) / "manifest.json"
            result = subprocess.run([sys.executable, str(SCRIPT), "build", str(archive), "--output", str(manifest)], text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("case-fold collision", result.stdout)


if __name__ == "__main__":
    unittest.main()
