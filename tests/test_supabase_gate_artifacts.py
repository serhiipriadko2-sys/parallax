import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class SupabaseGateArtifactTests(unittest.TestCase):
    def test_memory_gate_migration_and_drift_test_exist(self):
        migration = ROOT / "supabase/migrations/20260728193000_parallax_memory_gate.sql"
        drift = ROOT / "supabase/tests/001_parallax_memory_gate.sql"
        self.assertTrue(migration.is_file())
        self.assertTrue(drift.is_file())
        text = migration.read_text(encoding="utf-8")
        self.assertIn("memory_consent_registry", text)
        self.assertIn("consent_id text primary key", text)
        self.assertIn("using (false) with check (false)", text)
        self.assertIn("client grants remain", drift.read_text(encoding="utf-8"))

    def test_security_definer_allowlist_is_exactly_thirteen_reviewed_functions(self):
        path = ROOT / "deployment/supabase-security-definer-allowlist.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        functions = payload["functions"]
        self.assertEqual(len(functions), 13)
        self.assertEqual(len({item["name"] for item in functions}), 13)
        for item in functions:
            self.assertRegex(item["definition_md5"], r"^[0-9a-f]{32}$")


if __name__ == "__main__":
    unittest.main()
