import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests._bootstrap import ensure_runtime_path

ensure_runtime_path()

from parallax_omega.models import ActionRequest, RiskLevel
from parallax_omega.policy import HostPolicyAdapter, PolicyMode, PolicyRule


class PolicyTests(unittest.TestCase):
    def test_unknown_environment_value_fails_closed(self):
        with patch.dict(os.environ, {"PARALLAX_POLICY_MODE": "unknown"}, clear=False):
            adapter = HostPolicyAdapter.from_env()
        self.assertEqual(adapter.mode, PolicyMode.DENY_ALL)
        self.assertFalse(adapter.context_for(ActionRequest("a", "local", "parse", "input", RiskLevel.R0)).policy_allows)

    def test_builtin_read_only_is_exact_not_generic(self):
        with patch.dict(os.environ, {"PARALLAX_POLICY_MODE": "read_only"}, clear=False):
            adapter = HostPolicyAdapter.from_env()
        allowed = ActionRequest("a", "local", "parse", "input/document", RiskLevel.R0)
        wrong_tool = ActionRequest("b", "network", "fetch", "input/document", RiskLevel.R0)
        wrong_scope = ActionRequest("c", "local", "parse", "private/secret", RiskLevel.R0)
        higher_risk = ActionRequest("d", "local", "parse", "input/document", RiskLevel.R1)
        self.assertTrue(adapter.context_for(allowed).policy_allows)
        self.assertFalse(adapter.context_for(wrong_tool).policy_allows)
        self.assertFalse(adapter.context_for(wrong_scope).policy_allows)
        self.assertFalse(adapter.context_for(higher_risk).policy_allows)

    def test_file_policy_is_fail_closed_and_exact(self):
        policy = {
            "schema_version": "1.0",
            "default": "deny",
            "rules": [{
                "tool": "repo",
                "operation": "read",
                "max_risk": "R1",
                "scope_prefixes": ["repo:public/"]
            }]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps(policy), encoding="utf-8")
            adapter = HostPolicyAdapter.from_file(path)
        self.assertEqual(adapter.mode, PolicyMode.ALLOWLIST)
        self.assertTrue(adapter.context_for(ActionRequest("a", "repo", "read", "repo:public/a", RiskLevel.R1)).policy_allows)
        self.assertFalse(adapter.context_for(ActionRequest("b", "repo", "write", "repo:public/a", RiskLevel.R1)).policy_allows)
        self.assertFalse(adapter.context_for(ActionRequest("c", "repo", "read", "repo:private/a", RiskLevel.R1)).policy_allows)

    def test_invalid_file_from_env_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text('{"schema_version":"1.0","default":"allow","rules":[]}', encoding="utf-8")
            with patch.dict(os.environ, {"PARALLAX_POLICY_FILE": str(path)}, clear=False):
                adapter = HostPolicyAdapter.from_env()
        self.assertEqual(adapter.mode, PolicyMode.DENY_ALL)
        self.assertEqual(adapter.source, "invalid-policy-file")

    def test_rule_rejects_empty_scope(self):
        with self.assertRaises(ValueError):
            PolicyRule("tool", "read", RiskLevel.R0, ())


if __name__ == "__main__":
    unittest.main()
