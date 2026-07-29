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
    def test_agents_sdk_authority_is_not_model_controlled_and_emits_receipt(self):
        path = ROOT / "agents_sdk/agent.py"
        args = function_args(path, "action_preflight")
        self.assertNotIn("policy_allows", args)
        text = path.read_text(encoding="utf-8")
        self.assertIn("RunContextWrapper", text)
        self.assertIn("HostPolicyAdapter", text)
        self.assertIn("ParallaxKernel", text)
        self.assertIn('"receipt": result["receipt"]', text)

    def test_mcp_authority_is_not_model_controlled_and_emits_receipt(self):
        path = ROOT / "adapters/mcp_server.py"
        args = function_args(path, "evaluate_action")
        self.assertNotIn("policy_allows", args)
        text = path.read_text(encoding="utf-8")
        self.assertIn("PARALLAX_MCP_POLICY_SHA256", text)
        self.assertIn("ParallaxKernel", text)
        self.assertIn('"receipt": result["receipt"]', text)
        self.assertNotIn("def execute_", text)
        self.assertNotIn("def commit_", text)

    def test_api_has_no_external_mutation_route_and_emits_receipts(self):
        text = (ROOT / "runtime/parallax_omega/api.py").read_text(encoding="utf-8")
        self.assertNotIn('@app.post("/v1/actions/execute")', text)
        self.assertNotIn('@app.post("/v1/memory/commit")', text)
        self.assertIn("hmac.compare_digest", text)
        self.assertIn('ConfigDict(extra="forbid")', text)
        self.assertIn("ParallaxKernel", text)
        self.assertGreaterEqual(text.count('"receipt": result["receipt"]'), 2)


if __name__ == "__main__":
    unittest.main()
