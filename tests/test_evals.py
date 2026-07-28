import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class EvalContractTests(unittest.TestCase):
    def test_eval_bank_schema_and_coverage(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts/run_evals.py")],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr or proc.stdout)
        result = json.loads(proc.stdout)
        self.assertEqual(result["status"], "SCHEMA_PASS")
        self.assertEqual(result["behavioral_status"], "NOT_RUN")
        self.assertGreaterEqual(result["cases"], 70)

    def test_eval_bank_never_claims_behavioral_pass(self):
        text = (ROOT / "evals/cases.jsonl").read_text(encoding="utf-8")
        self.assertNotIn('"mode": "automated_pass"', text)


if __name__ == "__main__":
    unittest.main()
