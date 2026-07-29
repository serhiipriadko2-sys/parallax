from __future__ import annotations

from datetime import datetime

from .claim_graph import ClaimGraph
from .models import (
    ActionDecision,
    ActionDisposition,
    ActionRequest,
    AuthorizationContext,
    RiskLevel,
)

_RISK_ORDER = {
    RiskLevel.R0: 0,
    RiskLevel.R1: 1,
    RiskLevel.R2: 2,
    RiskLevel.R3: 3,
    RiskLevel.R4: 4,
}


def _higher_risk(left: RiskLevel, right: RiskLevel) -> RiskLevel:
    return left if _RISK_ORDER[left] >= _RISK_ORDER[right] else right


class ActionGovernor:
    """Fail-closed authority gate. Context must come from a trusted host adapter."""

    def decide(
        self,
        request: ActionRequest,
        context: AuthorizationContext,
        graph: ClaimGraph,
        *,
        at: datetime | None = None,
    ) -> ActionDecision:
        if not context.trusted_source:
            return ActionDecision(
                ActionDisposition.DENY,
                ("untrusted_authorization_context",),
                action_fingerprint=request.fingerprint(),
            )
        if not context.policy_allows:
            return ActionDecision(
                ActionDisposition.DENY,
                ("policy_denied",),
                action_fingerprint=request.fingerprint(),
            )
        if context.risk_floor is None or context.operation_irreversible is None:
            return ActionDecision(
                ActionDisposition.DENY,
                ("host_operation_classification_missing",),
                action_fingerprint=request.fingerprint(),
            )

        effective_risk = _higher_risk(request.risk, context.risk_floor)
        effective_irreversible = request.irreversible or context.operation_irreversible
        fingerprint = request.fingerprint(
            effective_risk=effective_risk,
            effective_irreversible=effective_irreversible,
        )
        reasons: list[str] = []
        missing: list[str] = []

        blockers = graph.blocking_claims(request.evidence_claim_ids)
        if blockers:
            missing.append(f"verified_claims:{','.join(blockers)}")

        evidence_count = graph.verified_evidence_count(request.evidence_claim_ids, at=at)
        required_evidence = {
            RiskLevel.R0: 0,
            RiskLevel.R1: 0,
            RiskLevel.R2: 1,
            RiskLevel.R3: 1,
            RiskLevel.R4: 2,
        }[effective_risk]
        if evidence_count < required_evidence:
            missing.append(f"current_evidence:{required_evidence}")

        if effective_risk is RiskLevel.R4 and graph.verified_source_class_count(
            request.evidence_claim_ids,
            at=at,
        ) < 2:
            missing.append("independent_source_classes:2")

        if effective_risk in {RiskLevel.R2, RiskLevel.R3, RiskLevel.R4}:
            if not context.explicit_user_approval:
                missing.append("explicit_user_approval")
            if context.approval_scope != request.scope:
                missing.append("exact_approval_scope")
            if context.approval_fingerprint != fingerprint:
                missing.append("action_bound_approval")
            if not context.approval_is_current(at):
                missing.append("unexpired_approval")

        if effective_risk in {RiskLevel.R3, RiskLevel.R4}:
            if not context.current_state_observed or not context.state_observation_ref:
                missing.append("current_state_read")
            if not context.rollback_available or not (context.rollback_plan or "").strip():
                missing.append("rollback_plan")
            if not context.idempotency_key:
                missing.append("idempotency_key")
            if not context.effect_verifiable or not (context.postcondition or "").strip():
                missing.append("verifiable_postcondition")

        if (
            effective_irreversible or effective_risk is RiskLevel.R4
        ) and not context.dual_control:
            return ActionDecision(
                ActionDisposition.PROPOSAL_ONLY,
                ("high_impact_requires_platform_dual_control",),
                tuple(sorted(set(missing + ["dual_control"]))),
                fingerprint,
                effective_risk,
                effective_irreversible,
            )

        if missing:
            disposition = (
                ActionDisposition.REQUIRE_APPROVAL
                if effective_risk in {RiskLevel.R2, RiskLevel.R3}
                else ActionDisposition.DENY
            )
            return ActionDecision(
                disposition,
                ("gate_incomplete",),
                tuple(sorted(set(missing))),
                fingerprint,
                effective_risk,
                effective_irreversible,
            )

        reasons.append("all_required_gates_satisfied")
        return ActionDecision(
            ActionDisposition.ALLOW,
            tuple(reasons),
            action_fingerprint=fingerprint,
            effective_risk=effective_risk,
            effective_irreversible=effective_irreversible,
        )
