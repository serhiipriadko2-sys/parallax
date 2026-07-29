"""Optional OpenAI Agents SDK composition.

The model proposes. A host-owned immutable policy snapshot governs. No external
write tool is registered in this release candidate.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

try:
    from agents import Agent, RunContextWrapper, function_tool
except ImportError as exc:  # pragma: no cover
    raise RuntimeError("Install the openai extra: pip install -e '.[openai]'") from exc

from parallax_omega.kernel import ParallaxKernel
from parallax_omega.models import ActionRequest, RiskLevel
from parallax_omega.policy import HostPolicyAdapter

ROOT = Path(__file__).resolve().parents[1]


@dataclass
class ParallaxRunContext:
    """Host-supplied context. Model tool arguments cannot construct this object."""

    policy: HostPolicyAdapter = field(default_factory=HostPolicyAdapter.from_env)


@function_tool
def action_preflight(
    ctx: RunContextWrapper[ParallaxRunContext],
    action_id: str,
    tool: str,
    operation: str,
    scope: str,
    risk: str,
    irreversible: bool = False,
) -> dict:
    """Return an advisory authorization decision without executing the action."""
    request = ActionRequest(
        action_id=action_id,
        tool=tool,
        operation=operation,
        scope=scope,
        risk=RiskLevel(risk),
        irreversible=irreversible,
    )
    adapter = ctx.context.policy
    result = ParallaxKernel().evaluate_action(
        request,
        adapter.context_for(request),
        surface="agents_sdk",
    )
    decision = result["decision"]
    return {
        "advisory": True,
        "execution_performed": False,
        "policy_mode": adapter.mode.value,
        "policy_source": adapter.source,
        "policy_hash": adapter.policy_hash,
        "action_fingerprint": decision["action_fingerprint"],
        "decision": decision,
        "receipt": result["receipt"],
    }


agent = Agent[ParallaxRunContext](
    name="PARALLAX Ω",
    handoff_description="Evidence-first analysis and governed action preflight.",
    instructions=(ROOT / "agent" / "WORKSPACE_AGENT_INSTRUCTIONS.md").read_text(encoding="utf-8"),
    tools=[action_preflight],
)
