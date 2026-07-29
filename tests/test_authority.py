import unittest
from datetime import UTC, datetime, timedelta

from tests._bootstrap import ensure_runtime_path

ensure_runtime_path()

from parallax_omega.authority import ActionGovernor
from parallax_omega.claim_graph import ClaimGraph
from parallax_omega.models import (
    ActionDisposition,
    ActionRequest,
    AuthorizationContext,
    Claim,
    ClaimType,
    EvidenceRef,
    RiskLevel,
)


def iso(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(UTC).replace(microsecond=0)
        self.graph = ClaimGraph()
        first = Claim("e1", "evidence", ClaimType.FACT, evidence=[EvidenceRef("src1", "repo")])
        self.graph.add(first)
        self.graph.verify("e1", 0.9, at=self.now)
        second = Claim("e2", "evidence2", ClaimType.FACT, evidence=[EvidenceRef("src2", "live")])
        self.graph.add(second)
        self.graph.verify("e2", 0.9, at=self.now)
        self.gov = ActionGovernor()

    def trusted(self, request: ActionRequest, **overrides) -> AuthorizationContext:
        risk_floor = overrides.pop("risk_floor", request.risk)
        operation_irreversible = overrides.pop("operation_irreversible", request.irreversible)
        values = dict(
            policy_allows=True,
            trusted_source=True,
            policy_source="test",
            risk_floor=risk_floor,
            operation_irreversible=operation_irreversible,
            explicit_user_approval=True,
            approval_scope=request.scope,
            approval_fingerprint=request.fingerprint(
                effective_risk=max((request.risk, risk_floor), key=lambda item: int(item.value[1:])),
                effective_irreversible=request.irreversible or operation_irreversible,
            ),
            approval_expires_at=iso(self.now + timedelta(minutes=5)),
            current_state_observed=True,
            state_observation_ref="state:1",
            rollback_available=True,
            rollback_plan="revert exact change",
            idempotency_key="idem-1",
            effect_verifiable=True,
            postcondition="read-back equals requested state",
            dual_control=True,
        )
        values.update(overrides)
        return AuthorizationContext(**values)

    def test_untrusted_context_is_denied(self):
        req = ActionRequest("a", "tool", "read", "x", RiskLevel.R0)
        decision = self.gov.decide(req, AuthorizationContext(True), self.graph, at=self.now)
        self.assertEqual(decision.disposition, ActionDisposition.DENY)
        self.assertIn("untrusted_authorization_context", decision.reasons)


    def test_missing_host_classification_is_denied(self):
        req = ActionRequest("a", "tool", "read", "x", RiskLevel.R0)
        ctx = AuthorizationContext(True, trusted_source=True, policy_source="test")
        decision = self.gov.decide(req, ctx, self.graph, at=self.now)
        self.assertEqual(decision.disposition, ActionDisposition.DENY)
        self.assertIn("host_operation_classification_missing", decision.reasons)

    def test_host_risk_floor_cannot_be_lowered_by_caller(self):
        req = ActionRequest("a", "db", "drop", "prod/table", RiskLevel.R1, irreversible=False)
        ctx = self.trusted(
            req,
            risk_floor=RiskLevel.R4,
            operation_irreversible=True,
            dual_control=False,
        )
        decision = self.gov.decide(req, ctx, self.graph, at=self.now)
        self.assertEqual(decision.disposition, ActionDisposition.PROPOSAL_ONLY)
        self.assertEqual(decision.effective_risk, RiskLevel.R4)
        self.assertTrue(decision.effective_irreversible)
        self.assertNotEqual(decision.action_fingerprint, req.fingerprint())

    def test_policy_denial_wins(self):
        req = ActionRequest("a", "tool", "read", "x", RiskLevel.R0)
        ctx = AuthorizationContext(False, trusted_source=True, policy_source="test")
        decision = self.gov.decide(req, ctx, self.graph, at=self.now)
        self.assertEqual(decision.disposition, ActionDisposition.DENY)

    def test_r0_allowed(self):
        req = ActionRequest("a", "local", "parse", "x", RiskLevel.R0)
        ctx = AuthorizationContext(
            True,
            trusted_source=True,
            policy_source="test",
            risk_floor=RiskLevel.R0,
            operation_irreversible=False,
        )
        self.assertEqual(
            self.gov.decide(req, ctx, self.graph, at=self.now).disposition,
            ActionDisposition.ALLOW,
        )

    def test_r3_requires_action_bound_approval(self):
        req = ActionRequest("a", "github", "update", "repo/file", RiskLevel.R3, ("e1",))
        ctx = self.trusted(req, approval_fingerprint="wrong")
        decision = self.gov.decide(req, ctx, self.graph, at=self.now)
        self.assertEqual(decision.disposition, ActionDisposition.REQUIRE_APPROVAL)
        self.assertIn("action_bound_approval", decision.missing)

    def test_r3_requires_current_state_and_specific_rollback(self):
        req = ActionRequest("a", "github", "update", "repo/file", RiskLevel.R3, ("e1",))
        ctx = self.trusted(
            req,
            current_state_observed=False,
            state_observation_ref=None,
            rollback_plan=None,
        )
        decision = self.gov.decide(req, ctx, self.graph, at=self.now)
        self.assertIn("current_state_read", decision.missing)
        self.assertIn("rollback_plan", decision.missing)

    def test_r3_allowed_with_complete_context(self):
        req = ActionRequest("a", "github", "update", "repo/file", RiskLevel.R3, ("e1",))
        decision = self.gov.decide(req, self.trusted(req), self.graph, at=self.now)
        self.assertEqual(decision.disposition, ActionDisposition.ALLOW)
        self.assertEqual(decision.action_fingerprint, req.fingerprint())

    def test_expired_approval_blocks(self):
        req = ActionRequest("a", "github", "update", "repo/file", RiskLevel.R3, ("e1",))
        ctx = self.trusted(req, approval_expires_at=iso(self.now - timedelta(seconds=1)))
        self.assertIn(
            "unexpired_approval",
            self.gov.decide(req, ctx, self.graph, at=self.now).missing,
        )

    def test_r4_requires_independent_source_classes(self):
        graph = ClaimGraph()
        for cid, ref in (("e1", "src1"), ("e2", "src2")):
            graph.add(Claim(cid, cid, ClaimType.FACT, evidence=[EvidenceRef(ref, "same-class")]))
            graph.verify(cid, 0.9, at=self.now)
        req = ActionRequest("a", "db", "drop", "prod.table", RiskLevel.R4, ("e1", "e2"), True)
        decision = self.gov.decide(req, self.trusted(req), graph, at=self.now)
        self.assertIn("independent_source_classes:2", decision.missing)

    def test_r4_proposal_without_dual_control(self):
        req = ActionRequest("a", "db", "drop", "prod.table", RiskLevel.R4, ("e1", "e2"), True)
        ctx = self.trusted(req, dual_control=False)
        self.assertEqual(
            self.gov.decide(req, ctx, self.graph, at=self.now).disposition,
            ActionDisposition.PROPOSAL_ONLY,
        )


if __name__ == "__main__":
    unittest.main()
