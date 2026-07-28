from __future__ import annotations

from dataclasses import asdict
from uuid import uuid4

from .authority import ActionGovernor
from .claim_graph import ClaimGraph
from .memory import MemorySteward
from .models import ActionRequest, AuthorizationContext, Claim
from .receipts import ReceiptChain


class ParallaxKernel:
    """Deterministic control plane; model generation and external effects live outside it."""

    def __init__(self) -> None:
        self.graph = ClaimGraph()
        self.governor = ActionGovernor()
        self.memory = MemorySteward()
        self.receipts = ReceiptChain()

    def add_claim(self, claim: Claim) -> dict:
        self.graph.add(claim)
        receipt = self.receipts.append(
            "claim_added",
            "created",
            {"claim_id": claim.claim_id, "claim_type": claim.claim_type.value},
        )
        return {"claim": asdict(self.graph.get(claim.claim_id)), "receipt": asdict(receipt)}

    def evaluate_action(self, request: ActionRequest, context: AuthorizationContext) -> dict:
        decision = self.governor.decide(request, context, self.graph)
        receipt = self.receipts.append(
            "action_decision",
            decision.disposition.value,
            {
                "action_id": request.action_id,
                "action_fingerprint": request.fingerprint(),
                "decision": asdict(decision),
                "execution_performed": False,
            },
        )
        return {"decision": asdict(decision), "receipt": asdict(receipt)}

    def status(self) -> dict:
        return {
            "request_id": str(uuid4()),
            "claims": len(self.graph.claims),
            "receipt_chain_valid": self.receipts.verify(),
            "memory_backend": "disabled",
            "external_writes": "disabled",
            "status": "operational-local",
        }
