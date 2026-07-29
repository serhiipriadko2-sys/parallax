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


    def test_archive_qc_rejects_member_not_in_embedded_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "release.zip"
            root = "parallax/"
            content = b"alpha"
            digest = __import__("hashlib").sha256(content).hexdigest()
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr(root + "a.txt", content)
                zf.writestr(root + "EXTRA.md", "unlisted")
                zf.writestr(root + "SHA256SUMS", f"{digest}  a.txt\n")
                zf.writestr(root + "MANIFEST.json", json.dumps({"file_count_ledger": 1}))
            qc = ROOT / "skills/artifact-verifier/scripts/archive_qc.py"
            result = subprocess.run(
                [sys.executable, str(qc), str(archive)],
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("unlisted_file:EXTRA.md", result.stdout)

    def test_ledger_file_set_excludes_vcs_metadata(self):
        """The builder and validator both run from a repository root, so version-control
        metadata must never enter the release file set on either side."""
        sys.path.insert(0, str(ROOT / "scripts"))
        try:
            from release_policy import files_for_ledger, is_release_file
        finally:
            sys.path.pop(0)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "kept.md").write_text("release content", encoding="utf-8")
            for vcs in (".git", ".hg", ".svn"):
                nested = root / vcs / "objects"
                nested.mkdir(parents=True)
                (nested / "blob").write_text("internal", encoding="utf-8")
                (root / vcs / "HEAD").write_text("ref: refs/heads/main", encoding="utf-8")
            selected = {path.relative_to(root).as_posix() for path in files_for_ledger(root)}
            self.assertEqual(selected, {"kept.md"})
            self.assertFalse(is_release_file(root, root / ".git" / "HEAD"))
            self.assertTrue(is_release_file(root, root / "kept.md"))

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
