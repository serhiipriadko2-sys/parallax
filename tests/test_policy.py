import hashlib
import hmac
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests._bootstrap import ensure_runtime_path

ensure_runtime_path()

from parallax_omega.models import ActionRequest, RiskLevel
from parallax_omega.policy import (
    POLICY_RELOAD_DOMAIN,
    HostPolicyAdapter,
    PolicyMode,
    PolicyRule,
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class PolicyTests(unittest.TestCase):
    def test_unknown_environment_value_fails_closed(self):
        with patch.dict(os.environ, {"PARALLAX_POLICY_MODE": "unknown"}, clear=False):
            adapter = HostPolicyAdapter.from_env()
        self.assertEqual(adapter.mode, PolicyMode.DENY_ALL)
        self.assertFalse(
            adapter.context_for(
                ActionRequest("a", "local", "parse", "input", RiskLevel.R0)
            ).policy_allows
        )

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
        self.assertEqual(len(adapter.policy_hash), 64)

    def policy_payload(self) -> dict:
        return {
            "schema_version": "1.1",
            "default": "deny",
            "rules": [{
                "tool": "repo",
                "operation": "read",
                "risk_floor": "R1",
                "max_risk": "R1",
                "irreversible": False,
                "scope_prefixes": ["repo:public/"]
            }],
        }

    def test_file_policy_requires_hash_pin_and_is_immutable_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps(self.policy_payload()), encoding="utf-8")
            digest = sha256(path)
            adapter = HostPolicyAdapter.from_file(path, expected_sha256=digest)
            path.write_text(
                json.dumps({"schema_version": "1.1", "default": "deny", "rules": []}),
                encoding="utf-8",
            )
        allowed = adapter.context_for(
            ActionRequest("a", "repo", "read", "repo:public/a", RiskLevel.R0)
        )
        self.assertTrue(allowed.policy_allows)
        self.assertEqual(allowed.risk_floor, RiskLevel.R1)
        self.assertEqual(allowed.policy_hash, digest)

    def test_hash_pin_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps(self.policy_payload()), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hash pin mismatch"):
                HostPolicyAdapter.from_file(path, expected_sha256="0" * 64)

    def test_file_policy_from_env_without_hash_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps(self.policy_payload()), encoding="utf-8")
            with patch.dict(
                os.environ,
                {"PARALLAX_POLICY_FILE": str(path)},
                clear=True,
            ):
                adapter = HostPolicyAdapter.from_env()
        self.assertEqual(adapter.mode, PolicyMode.DENY_ALL)
        self.assertEqual(adapter.source, "missing-policy-hash-pin")

    def test_signed_reload_rejects_bad_signature_and_accepts_good_signature(self):
        key = b"test-only-reload-key"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps(self.policy_payload()), encoding="utf-8")
            digest = sha256(path)
            with self.assertRaisesRegex(ValueError, "invalid policy reload signature"):
                HostPolicyAdapter.reload_signed(
                    path,
                    expected_sha256=digest,
                    signature_hex="00" * 32,
                    hmac_key=key,
                )
            signature = hmac.new(
                key,
                POLICY_RELOAD_DOMAIN + digest.encode("ascii"),
                hashlib.sha256,
            ).hexdigest()
            adapter = HostPolicyAdapter.reload_signed(
                path,
                expected_sha256=digest,
                signature_hex=signature,
                hmac_key=key,
            )
        self.assertEqual(adapter.policy_hash, digest)
        self.assertEqual(adapter.mode, PolicyMode.ALLOWLIST)

    def test_old_policy_schema_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(
                json.dumps({"schema_version": "1.0", "default": "deny", "rules": []}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "schema_version"):
                HostPolicyAdapter.from_file(path, expected_sha256=sha256(path))

    def test_rule_rejects_empty_scope(self):
        with self.assertRaises(ValueError):
            PolicyRule("tool", "read", RiskLevel.R0, RiskLevel.R0, False, ())

    def test_rule_rejects_floor_above_ceiling(self):
        with self.assertRaisesRegex(ValueError, "risk_floor"):
            PolicyRule("tool", "read", RiskLevel.R3, RiskLevel.R1, False, ("repo",))

    def test_caller_cannot_lower_host_risk_or_irreversibility(self):
        adapter = HostPolicyAdapter(
            mode=PolicyMode.ALLOWLIST,
            source="test",
            rules=(
                PolicyRule(
                    "supabase",
                    "execute_sql",
                    RiskLevel.R4,
                    RiskLevel.R4,
                    True,
                    ("workspace:read-only/",),
                ),
            ),
        )
        request = ActionRequest(
            "a",
            "supabase",
            "execute_sql",
            "workspace:read-only/drop-table",
            RiskLevel.R1,
            irreversible=False,
        )
        context = adapter.context_for(request)
        self.assertTrue(context.policy_allows)
        self.assertEqual(context.risk_floor, RiskLevel.R4)
        self.assertTrue(context.operation_irreversible)
        self.assertEqual(context.policy_hash, adapter.policy_hash)

    def test_unclassified_operation_fails_closed(self):
        adapter = HostPolicyAdapter(
            mode=PolicyMode.ALLOWLIST,
            source="test",
            rules=(
                PolicyRule(
                    "repo",
                    "read",
                    RiskLevel.R1,
                    RiskLevel.R1,
                    False,
                    ("repo:public/",),
                ),
            ),
        )
        context = adapter.context_for(
            ActionRequest("a", "repo", "delete", "repo:public/a", RiskLevel.R0)
        )
        self.assertFalse(context.policy_allows)
        self.assertIsNone(context.risk_floor)


class ScopeGrammarTests(unittest.TestCase):
    def rule(self) -> PolicyRule:
        return PolicyRule(
            "repo",
            "read",
            RiskLevel.R0,
            RiskLevel.R1,
            False,
            ("repo:public/",),
        )

    def test_segment_boundary_blocks_prefix_confusion(self):
        rule = self.rule()
        self.assertTrue(
            rule.allows(ActionRequest("a", "repo", "read", "repo:public/a", RiskLevel.R0))
        )
        self.assertFalse(
            rule.allows(
                ActionRequest("b", "repo", "read", "repo:publicity/a", RiskLevel.R0)
            )
        )
        self.assertFalse(
            rule.allows(
                ActionRequest("c", "repo", "read", "repo:public-secrets/a", RiskLevel.R0)
            )
        )

    def test_scope_traversal_and_percent_encoding_fail_closed(self):
        rule = self.rule()
        for scope in (
            "repo:public/../private",
            "repo:public/%2e%2e/private",
            "repo:public\\private",
            "repo:public//private",
        ):
            with self.subTest(scope=scope):
                self.assertFalse(
                    rule.allows(ActionRequest("x", "repo", "read", scope, RiskLevel.R0))
                )

    def test_policy_root_blocks_outside_file(self):
        policy = {"schema_version": "1.1", "default": "deny", "rules": []}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "allowed"
            root.mkdir()
            outside = Path(tmp) / "outside.json"
            outside.write_text(json.dumps(policy), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "outside"):
                HostPolicyAdapter.from_file(
                    outside,
                    expected_sha256=sha256(outside),
                    allowed_root=root,
                )


if __name__ == "__main__":
    unittest.main()
