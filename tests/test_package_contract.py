import ast
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PackageContractTests(unittest.TestCase):
    def test_ten_knowledge_files(self):
        self.assertEqual(len(list((ROOT / "knowledge").glob("*.md"))), 10)

    def test_seven_skills(self):
        self.assertEqual(len(list((ROOT / "skills").glob("*/SKILL.md"))), 7)

    def test_custom_gpt_refs_exist(self):
        config = json.loads((ROOT / "agent/custom-gpt-config.json").read_text(encoding="utf-8"))
        for rel in config["knowledge_files"]:
            self.assertTrue((ROOT / rel).is_file(), rel)

    def test_actions_are_advisory_only(self):
        schema = (ROOT / "actions/openapi.yaml").read_text(encoding="utf-8")
        self.assertIn("/v1/actions/preflight", schema)
        self.assertNotIn("/execute", schema)
        self.assertNotIn("/commit", schema)
        self.assertNotIn("policy_allows:", schema)
        self.assertNotIn("dual_control:", schema)
        self.assertIn("execution_performed", schema)

    def test_no_unearned_live_claim(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
        self.assertIn("not verified live", readme)

    def test_license_exists_for_declared_license(self):
        self.assertTrue((ROOT / "LICENSE").is_file())
        self.assertIn("MIT License", (ROOT / "LICENSE").read_text(encoding="utf-8"))

    def test_no_symlinks(self):
        self.assertFalse([path for path in ROOT.rglob("*") if path.is_symlink()])

    def test_python_sources_parse(self):
        for path in ROOT.rglob("*.py"):
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    def test_workspace_descriptor_is_explicitly_non_importable(self):
        text = (ROOT / "agent/workspace-agent.source.yaml").read_text(encoding="utf-8")
        self.assertIn("not a direct import manifest", text.lower())



if __name__ == "__main__":
    unittest.main()
