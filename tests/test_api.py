import os
import unittest
from unittest.mock import patch

from tests._bootstrap import ensure_runtime_path

ensure_runtime_path()

try:
    from fastapi.testclient import TestClient
    from parallax_omega.api import app
except ImportError:
    TestClient = None
    app = None


@unittest.skipIf(TestClient is None, "runtime extras not installed")
class ApiTests(unittest.TestCase):
    def setUp(self):
        os.environ["PARALLAX_API_KEY"] = "test-only-key"
        self.client = TestClient(app)
        self.headers = {"Authorization": "Bearer test-only-key"}

    def tearDown(self):
        os.environ.pop("PARALLAX_API_KEY", None)
        os.environ.pop("PARALLAX_POLICY_MODE", None)

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

    def test_default_policy_fails_closed(self):
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
        self.assertEqual(response.json()["decision"]["disposition"], "deny")
        self.assertFalse(response.json()["execution_performed"])

    def test_read_only_host_policy_allows_r0_preflight(self):
        with patch.dict(os.environ, {"PARALLAX_POLICY_MODE": "read_only"}):
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
        self.assertTrue(response.json()["advisory"])
        self.assertFalse(response.json()["execution_performed"])

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

    def test_memory_endpoint_returns_candidate_not_commit(self):
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


if __name__ == "__main__":
    unittest.main()
