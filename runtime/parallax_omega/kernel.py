from __future__ import annotations

from dataclasses import asdict
from typing import Any
from uuid import uuid4

from .authority import ActionGovernor
from .claim_graph import ClaimGraph
from .memory import MemorySteward
from .models import ActionRequest, AuthorizationContext, Claim
from .receipts import ReceiptChain


class ParallaxKernel:
    """Deterministic control plane; model generation and effects live outside it."""

    def __init__(
        self,
        *,
        graph: ClaimGraph | None = None,
        governor: ActionGovernor | None = None,
        memory: MemorySteward | None = None,
        receipts: ReceiptChain | None = None,
    ) -> None:
        self.graph = graph or ClaimGraph()
        self.governor = governor or ActionGovernor()
        self.memory = memory or MemorySteward()
        self.receipts = receipts or ReceiptChain()

    def add_claim(self, claim: Claim, *, surface: str = "kernel") -> dict[str, Any]:
        self.graph.add(claim)
        receipt = self.receipts.append(
            "claim_added",
            "created",
            {"claim_id": claim.claim_id, "claim_type": claim.claim_type.value},
            metadata={"surface": surface},
        )
        return {"claim": asdict(self.graph.get(claim.claim_id)), "receipt": asdict(receipt)}

    def evaluate_action(
        self,
        request: ActionRequest,
        context: AuthorizationContext,
        *,
        surface: str = "kernel",
    ) -> dict[str, Any]:
        decision = self.governor.decide(request, context, self.graph)
        receipt = self.receipts.append(
            "action_decision",
            decision.disposition.value,
            {
                "action_id": request.action_id,
                "action_fingerprint": decision.action_fingerprint,
                "decision": asdict(decision),
                "policy_source": context.policy_source,
                "policy_hash": context.policy_hash,
                "execution_performed": False,
            },
            metadata={"surface": surface, "policy_hash": context.policy_hash},
        )
        return {"decision": asdict(decision), "receipt": asdict(receipt)}

    def propose_memory(self, *, surface: str = "kernel", **proposal: object) -> dict[str, Any]:
        candidate = self.memory.propose(**proposal)  # type: ignore[arg-type]
        receipt = self.receipts.append(
            "memory_candidate",
            "candidate",
            {
                "candidate_id": candidate.candidate_id,
                "candidate_fingerprint": candidate.fingerprint(),
                "persistent": False,
                "execution_performed": False,
            },
            metadata={"surface": surface},
        )
        return {"candidate": asdict(candidate), "receipt": asdict(receipt)}

    def status(self) -> dict[str, Any]:
        return {
            "request_id": str(uuid4()),
            "claims": len(self.graph.claims),
            "receipt_chain_valid": self.receipts.verify(),
            "memory_backend": "disabled",
            "external_writes": "disabled",
            "status": "operational-local",
        }
