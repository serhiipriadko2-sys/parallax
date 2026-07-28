from __future__ import annotations

from collections import defaultdict, deque
from copy import deepcopy
from datetime import datetime

from .models import Claim, ClaimStatus, ClaimType


class ClaimGraphError(ValueError):
    pass


class ClaimGraph:
    """Deterministic claim DAG with temporal checks and transitive invalidation."""

    def __init__(self) -> None:
        self._claims: dict[str, Claim] = {}
        self._dependents: dict[str, set[str]] = defaultdict(set)

    @property
    def claims(self) -> dict[str, Claim]:
        return {key: deepcopy(value) for key, value in self._claims.items()}

    def add(self, claim: Claim) -> None:
        if claim.status is ClaimStatus.VERIFIED:
            raise ClaimGraphError("verified claims must pass through verify()")
        if claim.claim_id in self._claims:
            raise ClaimGraphError(f"duplicate claim: {claim.claim_id}")
        missing = claim.dependencies.difference(self._claims)
        if missing:
            raise ClaimGraphError(f"missing dependencies: {sorted(missing)}")
        self._claims[claim.claim_id] = deepcopy(claim)
        for dependency in claim.dependencies:
            self._dependents[dependency].add(claim.claim_id)
        if not self.is_acyclic():
            self._claims.pop(claim.claim_id, None)
            for dependency in claim.dependencies:
                self._dependents[dependency].discard(claim.claim_id)
            raise ClaimGraphError("claim graph must be acyclic")
        self._enforce_dependency_status(claim.claim_id)

    def get(self, claim_id: str) -> Claim:
        return deepcopy(self._require(claim_id))

    def verify(self, claim_id: str, confidence: float, *, at: datetime | None = None) -> None:
        if not 0.0 <= confidence <= 0.95:
            raise ClaimGraphError("confidence must be between 0 and 0.95")
        claim = self._require(claim_id)
        blocking = [
            dep
            for dep in claim.dependencies
            if self._claims[dep].status is not ClaimStatus.VERIFIED
        ]
        if blocking:
            raise ClaimGraphError(f"unverified dependencies: {blocking}")

        if claim.claim_type is ClaimType.FACT:
            if not claim.evidence:
                raise ClaimGraphError("fact requires evidence")
            if not any(item.is_current(at) for item in claim.evidence):
                raise ClaimGraphError("fact requires at least one current evidence reference")

        if claim.dependencies:
            ceiling = min(self._claims[dep].confidence for dep in claim.dependencies)
            if confidence > ceiling:
                raise ClaimGraphError(f"confidence exceeds dependency ceiling: {ceiling:.3f}")

        claim.status = ClaimStatus.VERIFIED
        claim.confidence = confidence
        claim.invalid_reason = None

    def mark_conflict(self, claim_id: str, reason: str) -> list[str]:
        if not reason.strip():
            raise ClaimGraphError("conflict reason is required")
        claim = self._require(claim_id)
        claim.status = ClaimStatus.CONFLICT
        claim.invalid_reason = reason
        return self._invalidate_descendants(claim_id, f"dependency conflict: {claim_id}")

    def invalidate(self, claim_id: str, reason: str) -> list[str]:
        if not reason.strip():
            raise ClaimGraphError("invalidation reason is required")
        return self._invalidate_from(claim_id, reason)

    def revalidate_time(self, *, at: datetime | None = None) -> list[str]:
        expired_roots = [
            claim_id
            for claim_id, claim in self._claims.items()
            if claim.claim_type is ClaimType.FACT
            and claim.status is ClaimStatus.VERIFIED
            and not any(item.is_current(at) for item in claim.evidence)
        ]
        affected: list[str] = []
        seen: set[str] = set()
        for claim_id in sorted(expired_roots):
            for current in self._invalidate_from(claim_id, "all evidence expired"):
                if current not in seen:
                    seen.add(current)
                    affected.append(current)
        return affected

    def descendants(self, claim_id: str) -> set[str]:
        self._require(claim_id)
        result: set[str] = set()
        queue = deque(self._dependents.get(claim_id, ()))
        while queue:
            current = queue.popleft()
            if current in result:
                continue
            result.add(current)
            queue.extend(self._dependents.get(current, ()))
        return result

    def topological_order(self) -> list[str]:
        indegree = {key: len(claim.dependencies) for key, claim in self._claims.items()}
        queue = deque(sorted(key for key, degree in indegree.items() if degree == 0))
        order: list[str] = []
        while queue:
            current = queue.popleft()
            order.append(current)
            for dependent in sorted(self._dependents.get(current, ())):
                indegree[dependent] -= 1
                if indegree[dependent] == 0:
                    queue.append(dependent)
        if len(order) != len(self._claims):
            raise ClaimGraphError("cycle detected")
        return order

    def is_acyclic(self) -> bool:
        try:
            self.topological_order()
            return True
        except ClaimGraphError:
            return False

    def verified_evidence_count(
        self,
        claim_ids: tuple[str, ...],
        *,
        at: datetime | None = None,
    ) -> int:
        """Count distinct current evidence references, not duplicated claim wrappers."""
        refs: set[tuple[str, str, str | None]] = set()
        for claim_id in claim_ids:
            claim = self._claims.get(claim_id)
            if claim and claim.status is ClaimStatus.VERIFIED:
                refs.update(
                    (item.ref, item.source_class, item.content_hash)
                    for item in claim.evidence
                    if item.is_current(at)
                )
        return len(refs)

    def verified_source_class_count(
        self,
        claim_ids: tuple[str, ...],
        *,
        at: datetime | None = None,
    ) -> int:
        classes: set[str] = set()
        for claim_id in claim_ids:
            claim = self._claims.get(claim_id)
            if claim and claim.status is ClaimStatus.VERIFIED:
                classes.update(item.source_class for item in claim.evidence if item.is_current(at))
        return len(classes)

    def blocking_claims(self, claim_ids: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(
            sorted(
                claim_id
                for claim_id in claim_ids
                if claim_id not in self._claims
                or self._claims[claim_id].status is not ClaimStatus.VERIFIED
            )
        )

    def _invalidate_from(self, claim_id: str, reason: str) -> list[str]:
        affected: list[str] = []
        queue: deque[str] = deque([claim_id])
        seen: set[str] = set()
        while queue:
            current = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            claim = self._require(current)
            claim.status = ClaimStatus.INVALID
            claim.confidence = 0.0
            claim.invalid_reason = reason if current == claim_id else f"dependency invalid: {claim_id}"
            affected.append(current)
            queue.extend(sorted(self._dependents.get(current, ())))
        return affected

    def _invalidate_descendants(self, claim_id: str, reason: str) -> list[str]:
        affected: list[str] = []
        for descendant in sorted(self.descendants(claim_id)):
            claim = self._claims[descendant]
            claim.status = ClaimStatus.INVALID
            claim.confidence = 0.0
            claim.invalid_reason = reason
            affected.append(descendant)
        return affected

    def _enforce_dependency_status(self, claim_id: str) -> None:
        claim = self._claims[claim_id]
        if any(
            self._claims[dep].status in {ClaimStatus.INVALID, ClaimStatus.CONFLICT}
            for dep in claim.dependencies
        ):
            claim.status = ClaimStatus.INVALID
            claim.confidence = 0.0
            claim.invalid_reason = "dependency invalid or conflicted at insertion"

    def _require(self, claim_id: str) -> Claim:
        try:
            return self._claims[claim_id]
        except KeyError as exc:
            raise ClaimGraphError(f"unknown claim: {claim_id}") from exc
