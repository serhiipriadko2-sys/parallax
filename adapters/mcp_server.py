"""Optional MCP server with advisory-only, server-owned authorization policy."""
from __future__ import annotations

import os

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover
    raise RuntimeError("Install the openai extra: pip install -e '.[openai]'") from exc

from parallax_omega.kernel import ParallaxKernel
from parallax_omega.models import ActionRequest, RiskLevel
from parallax_omega.policy import HostPolicyAdapter
from parallax_omega.rate_limit import RateLimitPolicy, SlidingWindowRateLimiter

mcp = FastMCP("PARALLAX Ω")


def _positive_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        return default
    return value if value > 0 else default


_limiter = SlidingWindowRateLimiter(
    RateLimitPolicy(
        limit=_positive_int("PARALLAX_MCP_RATE_LIMIT", 60),
        window_seconds=float(_positive_int("PARALLAX_MCP_RATE_WINDOW_SECONDS", 60)),
    )
)
_policy_adapter = HostPolicyAdapter.from_env(
    "PARALLAX_MCP_POLICY_MODE",
    "PARALLAX_MCP_POLICY_FILE",
    "PARALLAX_MCP_POLICY_ROOT",
    "PARALLAX_MCP_POLICY_SHA256",
)


@mcp.tool()
def server_status() -> dict:
    """Report safe defaults. This tool performs no external action."""
    _limiter.check("server_status")
    return {
        "service": "parallax-omega-mcp",
        "version": "1.0.0-rc.3",
        "policy_mode": _policy_adapter.mode.value,
        "policy_hash": _policy_adapter.policy_hash,
        "external_writes": "not_exposed",
        "memory": "candidate_only",
        "state_model": "stateless-per-call",
        "rate_limit": "process-backstop; identity-aware gateway required",
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
    _limiter.check("evaluate_action")
    request = ActionRequest(
        action_id=action_id,
        tool=tool,
        operation=operation,
        scope=scope,
        risk=RiskLevel(risk),
        irreversible=irreversible,
    )
    result = ParallaxKernel().evaluate_action(
        request,
        _policy_adapter.context_for(request),
        surface="mcp",
    )
    decision = result["decision"]
    return {
        "advisory": True,
        "execution_performed": False,
        "policy_mode": _policy_adapter.mode.value,
        "action_fingerprint": decision["action_fingerprint"],
        "decision": decision,
        "receipt": result["receipt"],
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
    _limiter.check("propose_memory")
    result = ParallaxKernel().propose_memory(
        surface="mcp",
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
        "candidate": result["candidate"],
        "candidate_fingerprint": result["receipt"]["payload"]["candidate_fingerprint"],
        "receipt": result["receipt"],
    }


if __name__ == "__main__":
    mcp.run()
