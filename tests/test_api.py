import os
import unittest
from unittest.mock import patch

from tests._bootstrap import ensure_runtime_path

ensure_runtime_path()

try:
    import parallax_omega.api as api_module
    from fastapi.testclient import TestClient
    from parallax_omega.api import app
    from parallax_omega.policy import HostPolicyAdapter, PolicyMode
except (ImportError, RuntimeError):
    # parallax_omega.api deliberately re-raises a missing runtime extra as RuntimeError,
    # so the guard cannot depend on ImportError alone or on which import is sorted first.
    TestClient = None
    app = None
    api_module = None
    HostPolicyAdapter = None
    PolicyMode = None


@unittest.skipIf(TestClient is None, "runtime extras not installed")
class ApiTests(unittest.TestCase):
    def setUp(self):
        os.environ["PARALLAX_API_KEY"] = "test-only-key"
        self.client = TestClient(app)
        self.headers = {"Authorization": "Bearer test-only-key"}

    def tearDown(self):
        os.environ.pop("PARALLAX_API_KEY", None)

    def test_health_is_public_and_reports_safe_defaults(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["memory"], "disabled")
        self.assertEqual(body["external_writes"], "not_exposed")
        self.assertIn("x-request-id", response.headers)
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_action_endpoint_requires_authentication(self):
        response = self.client.post(
            "/v1/actions/preflight",
            json={
                "action_id": "a",
                "tool": "local",
                "operation": "parse",
                "scope": "input",
                "risk": "R0",
            },
        )
        self.assertEqual(response.status_code, 401)

    def test_default_policy_fails_closed_and_emits_receipt(self):
        deny = HostPolicyAdapter()
        with patch.object(api_module, "policy_adapter", deny):
            response = self.client.post(
                "/v1/actions/preflight",
                headers=self.headers,
                json={
                    "action_id": "a",
                    "tool": "local",
                    "operation": "parse",
                    "scope": "input",
                    "risk": "R0",
                },
            )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["decision"]["disposition"], "deny")
        self.assertFalse(body["execution_performed"])
        self.assertEqual(body["receipt"]["event_type"], "action_decision")
        self.assertEqual(body["receipt"]["metadata"]["surface"], "http")
        self.assertEqual(body["receipt"]["payload"]["policy_hash"], deny.policy_hash)

    def test_read_only_snapshot_allows_r0_preflight(self):
        adapter = HostPolicyAdapter.from_env(mode_variable="PARALLAX_TEST_POLICY_MODE")
        with patch.dict(os.environ, {"PARALLAX_TEST_POLICY_MODE": "read_only"}, clear=False):
            adapter = HostPolicyAdapter.from_env(mode_variable="PARALLAX_TEST_POLICY_MODE")
        with patch.object(api_module, "policy_adapter", adapter):
            response = self.client.post(
                "/v1/actions/preflight",
                headers=self.headers,
                json={
                    "action_id": "a",
                    "tool": "local",
                    "operation": "parse",
                    "scope": "input",
                    "risk": "R0",
                },
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["decision"]["disposition"], "allow")
        self.assertIn("receipt", response.json())

    def test_model_cannot_supply_authority_fields(self):
        response = self.client.post(
            "/v1/actions/preflight",
            headers=self.headers,
            json={
                "action_id": "a",
                "tool": "db",
                "operation": "drop",
                "scope": "prod",
                "risk": "R4",
                "policy_allows": True,
                "dual_control": True,
            },
        )
        self.assertEqual(response.status_code, 422)

    def test_memory_endpoint_returns_candidate_and_receipt_not_commit(self):
        response = self.client.post(
            "/v1/memory/candidates",
            headers=self.headers,
            json={
                "content": "prefers concise reports",
                "purpose": "formatting",
                "deletion_path": "settings/delete",
            },
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertFalse(body["persistent"])
        self.assertFalse(body["execution_performed"])
        self.assertEqual(body["candidate"]["stage"], "candidate")
        self.assertEqual(body["receipt"]["event_type"], "memory_candidate")


if __name__ == "__main__":
    unittest.main()
