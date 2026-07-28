import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def function_args(path: Path, name: str) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return [arg.arg for arg in node.args.args]
    raise AssertionError(f"function not found: {name}")


class SurfaceContractTests(unittest.TestCase):
    def test_agents_sdk_authority_is_not_model_controlled(self):
        path = ROOT / "agents_sdk/agent.py"
        args = function_args(path, "action_preflight")
        self.assertNotIn("policy_allows", args)
        text = path.read_text(encoding="utf-8")
        self.assertIn("RunContextWrapper", text)
        self.assertIn("HostPolicyAdapter", text)
        self.assertIn("Path(__file__).resolve()", text)

    def test_mcp_authority_is_not_model_controlled(self):
        path = ROOT / "adapters/mcp_server.py"
        args = function_args(path, "evaluate_action")
        self.assertNotIn("policy_allows", args)
        text = path.read_text(encoding="utf-8")
        self.assertIn("PARALLAX_MCP_POLICY_MODE", text)
        self.assertNotIn("def execute_", text)
        self.assertNotIn("def commit_", text)

    def test_api_has_no_external_mutation_route(self):
        text = (ROOT / "runtime/parallax_omega/api.py").read_text(encoding="utf-8")
        self.assertNotIn('@app.post("/v1/actions/execute")', text)
        self.assertNotIn('@app.post("/v1/memory/commit")', text)
        self.assertIn("hmac.compare_digest", text)
        self.assertIn('ConfigDict(extra="forbid")', text)


if __name__ == "__main__":
    unittest.main()
