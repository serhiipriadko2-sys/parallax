"""Optional MCP server with advisory-only, server-owned authorization policy."""
from __future__ import annotations

from dataclasses import asdict

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover
    raise RuntimeError("Install the openai extra: pip install -e '.[openai]'") from exc

from parallax_omega.authority import ActionGovernor
from parallax_omega.claim_graph import ClaimGraph
from parallax_omega.memory import MemorySteward
from parallax_omega.models import ActionRequest, RiskLevel
from parallax_omega.policy import HostPolicyAdapter

mcp = FastMCP("PARALLAX Ω")
graph = ClaimGraph()
governor = ActionGovernor()
steward = MemorySteward()


@mcp.tool()
def server_status() -> dict:
    """Report safe defaults. This tool performs no external action."""
    adapter = HostPolicyAdapter.from_env("PARALLAX_MCP_POLICY_MODE", "PARALLAX_MCP_POLICY_FILE")
    return {
        "service": "parallax-omega-mcp",
        "version": "1.0.0-rc.2",
        "policy_mode": adapter.mode.value,
        "external_writes": "not_exposed",
        "memory": "candidate_only",
    }


@mcp.tool()
def evaluate_action(
    action_id: str,
    tool: str,
    operation: str,
    scope: str,
    risk: str,
    irreversible: bool = False,
) -> dict:
    """Return an advisory decision. Model arguments cannot grant policy authority."""
    request = ActionRequest(
        action_id=action_id,
        tool=tool,
        operation=operation,
        scope=scope,
        risk=RiskLevel(risk),
        irreversible=irreversible,
    )
    adapter = HostPolicyAdapter.from_env("PARALLAX_MCP_POLICY_MODE", "PARALLAX_MCP_POLICY_FILE")
    decision = governor.decide(request, adapter.context_for(request), graph)
    return {
        "advisory": True,
        "execution_performed": False,
        "policy_mode": adapter.mode.value,
        "action_fingerprint": request.fingerprint(),
        "decision": asdict(decision),
    }


@mcp.tool()
def propose_memory(
    content: str,
    purpose: str,
    target: str = "journal",
    retention_days: int = 30,
    deletion_path: str = "deployment-defined",
) -> dict:
    """Create a non-persistent memory candidate for explicit user review."""
    candidate = steward.propose(
        content=content,
        purpose=purpose,
        sensitivity="normal",
        retention_days=retention_days,
        target=target,
        deletion_path=deletion_path,
    )
    return {
        "persistent": False,
        "execution_performed": False,
        "candidate": asdict(candidate),
        "candidate_fingerprint": candidate.fingerprint(),
    }


if __name__ == "__main__":
    mcp.run()
