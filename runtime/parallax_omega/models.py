from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


def utc_now_dt() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def utc_now() -> str:
    return utc_now_dt().isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(UTC)


def canonical_hash(payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class ClaimStatus(str, Enum):
    PROPOSED = "proposed"
    VERIFIED = "verified"
    PARTIAL = "partial"
    INVALID = "invalid"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"


class ClaimType(str, Enum):
    FACT = "fact"
    INTERPRETATION = "interpretation"
    HYPOTHESIS = "hypothesis"
    DECISION = "decision"


class RiskLevel(str, Enum):
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"


class ActionDisposition(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    PROPOSAL_ONLY = "proposal_only"
    DENY = "deny"


class MemoryStage(str, Enum):
    CANDIDATE = "candidate"
    CONSENTED = "consented"
    COMMITTED = "committed"
    VERIFIED = "verified"
    REJECTED = "rejected"


@dataclass(frozen=True)
class EvidenceRef:
    ref: str
    source_class: str
    observed_at: str = field(default_factory=utc_now)
    valid_until: str | None = None
    content_hash: str | None = None

    def __post_init__(self) -> None:
        if not self.ref.strip() or not self.source_class.strip():
            raise ValueError("evidence ref and source_class are required")
        observed = parse_utc(self.observed_at)
        if self.valid_until is not None and parse_utc(self.valid_until) < observed:
            raise ValueError("valid_until cannot be before observed_at")
        if self.content_hash is not None:
            normalized = self.content_hash.lower()
            if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized):
                raise ValueError("content_hash must be a SHA-256 hex digest")

    def is_current(self, at: datetime | None = None) -> bool:
        moment = (at or utc_now_dt()).astimezone(UTC)
        observed = parse_utc(self.observed_at)
        if observed > moment:
            return False
        return self.valid_until is None or parse_utc(self.valid_until) >= moment


@dataclass
class Claim:
    claim_id: str
    text: str
    claim_type: ClaimType
    status: ClaimStatus = ClaimStatus.PROPOSED
    confidence: float = 0.0
    evidence: list[EvidenceRef] = field(default_factory=list)
    dependencies: set[str] = field(default_factory=set)
    falsifier: str | None = None
    invalid_reason: str | None = None

    def __post_init__(self) -> None:
        if not self.claim_id.strip() or not self.text.strip():
            raise ValueError("claim_id and text are required")
        if not 0.0 <= self.confidence <= 0.95:
            raise ValueError("confidence must be between 0 and 0.95")
        if self.claim_id in self.dependencies:
            raise ValueError("claim cannot depend on itself")


@dataclass(frozen=True)
class AuthorizationContext:
    policy_allows: bool
    trusted_source: bool = False
    policy_source: str = "untrusted"
    policy_hash: str = ""
    risk_floor: RiskLevel | None = None
    operation_irreversible: bool | None = None
    explicit_user_approval: bool = False
    approval_scope: str | None = None
    approval_fingerprint: str | None = None
    approval_expires_at: str | None = None
    current_state_observed: bool = False
    state_observation_ref: str | None = None
    rollback_available: bool = False
    rollback_plan: str | None = None
    idempotency_key: str | None = None
    effect_verifiable: bool = False
    postcondition: str | None = None
    dual_control: bool = False

    def approval_is_current(self, at: datetime | None = None) -> bool:
        if self.approval_expires_at is None:
            return False
        return parse_utc(self.approval_expires_at) >= (at or utc_now_dt()).astimezone(UTC)


@dataclass(frozen=True)
class ActionRequest:
    action_id: str
    tool: str
    operation: str
    scope: str
    risk: RiskLevel
    evidence_claim_ids: tuple[str, ...] = ()
    irreversible: bool = False

    def __post_init__(self) -> None:
        if not all(value.strip() for value in (self.action_id, self.tool, self.operation, self.scope)):
            raise ValueError("action_id, tool, operation, and scope are required")

    def fingerprint(
        self,
        *,
        effective_risk: RiskLevel | None = None,
        effective_irreversible: bool | None = None,
    ) -> str:
        risk = effective_risk or self.risk
        irreversible = (
            self.irreversible
            if effective_irreversible is None
            else effective_irreversible
        )
        return canonical_hash(
            {
                "action_id": self.action_id,
                "tool": self.tool,
                "operation": self.operation,
                "scope": self.scope,
                "risk": risk.value,
                "evidence_claim_ids": sorted(set(self.evidence_claim_ids)),
                "irreversible": irreversible,
            }
        )


@dataclass(frozen=True)
class ActionDecision:
    disposition: ActionDisposition
    reasons: tuple[str, ...]
    missing: tuple[str, ...] = ()
    action_fingerprint: str | None = None
    effective_risk: RiskLevel | None = None
    effective_irreversible: bool | None = None


@dataclass
class MemoryCandidate:
    candidate_id: str
    content: str
    purpose: str
    sensitivity: str
    retention_days: int
    target: str
    deletion_path: str
    content_hash: str
    stage: MemoryStage = MemoryStage.CANDIDATE

    def fingerprint(self) -> str:
        return canonical_hash(
            {
                "candidate_id": self.candidate_id,
                "content_hash": self.content_hash,
                "purpose": self.purpose,
                "sensitivity": self.sensitivity,
                "retention_days": self.retention_days,
                "target": self.target,
                "deletion_path": self.deletion_path,
            }
        )


@dataclass(frozen=True)
class MemoryConsent:
    consent_id: str
    candidate_fingerprint: str
    issued_at: str
    expires_at: str
    issuer: str
    trusted_issuer: bool = False

    def __post_init__(self) -> None:
        if not all(
            value.strip()
            for value in (
                self.consent_id,
                self.candidate_fingerprint,
                self.issued_at,
                self.expires_at,
                self.issuer,
            )
        ):
            raise ValueError("complete consent binding is required")
        if parse_utc(self.expires_at) < parse_utc(self.issued_at):
            raise ValueError("consent expires before it is issued")

    def is_current(self, at: datetime | None = None) -> bool:
        moment = (at or utc_now_dt()).astimezone(UTC)
        return parse_utc(self.issued_at) <= moment <= parse_utc(self.expires_at)


@dataclass(frozen=True)
class Receipt:
    schema_version: int
    receipt_id: str
    timestamp: str
    event_type: str
    status: str
    payload: dict[str, Any]
    payload_hash: str
    previous_hash: str | None
    receipt_hash: str
    metadata: dict[str, Any]
    authoritative: bool = False
