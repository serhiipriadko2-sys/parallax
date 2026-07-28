from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import datetime
from typing import Protocol
from uuid import uuid4

from .models import MemoryCandidate, MemoryConsent, MemoryStage


class MemoryProtocolError(ValueError):
    pass


class MemoryBackend(Protocol):
    def write(self, candidate: MemoryCandidate, consent: MemoryConsent) -> str: ...
    def read_hash(self, record_id: str) -> str: ...


class DisabledMemoryBackend:
    def write(self, candidate: MemoryCandidate, consent: MemoryConsent) -> str:
        raise MemoryProtocolError("memory_write_unavailable")

    def read_hash(self, record_id: str) -> str:
        raise MemoryProtocolError("memory_read_unavailable")


class MemorySteward:
    PROHIBITED_SENSITIVITY = {
        "secret",
        "credential",
        "medical",
        "intimate",
        "payment",
        "biometric",
        "private-third-party",
    }
    ALLOWED_TARGETS = {"journal", "open_loop", "shadow"}

    def __init__(self, backend: MemoryBackend | None = None) -> None:
        self.backend = backend or DisabledMemoryBackend()
        self._used_consents: set[str] = set()

    def propose(
        self,
        *,
        content: str,
        purpose: str,
        sensitivity: str,
        retention_days: int,
        target: str,
        deletion_path: str,
    ) -> MemoryCandidate:
        if not content.strip() or not purpose.strip() or not deletion_path.strip():
            raise MemoryProtocolError("content, purpose, and deletion_path are required")
        if sensitivity.lower() in self.PROHIBITED_SENSITIVITY:
            raise MemoryProtocolError("sensitive_memory_prohibited")
        if target == "archive":
            raise MemoryProtocolError("direct_archive_write_forbidden")
        if target not in self.ALLOWED_TARGETS:
            raise MemoryProtocolError("unsupported_memory_target")
        if not 1 <= retention_days <= 365:
            raise MemoryProtocolError("retention_days_out_of_range")
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return MemoryCandidate(
            candidate_id=str(uuid4()),
            content=content,
            purpose=purpose,
            sensitivity=sensitivity,
            retention_days=retention_days,
            target=target,
            deletion_path=deletion_path,
            content_hash=digest,
        )

    def commit(
        self,
        candidate: MemoryCandidate,
        consent: MemoryConsent,
        *,
        at: datetime | None = None,
    ) -> tuple[MemoryCandidate, str]:
        if candidate.stage is not MemoryStage.CANDIDATE:
            raise MemoryProtocolError("candidate_not_committable")
        if not consent.trusted_issuer:
            raise MemoryProtocolError("untrusted_consent_issuer")
        if consent.consent_id in self._used_consents:
            raise MemoryProtocolError("consent_replay_detected")
        if consent.candidate_fingerprint != candidate.fingerprint():
            raise MemoryProtocolError("consent_candidate_mismatch")
        if not consent.is_current(at):
            raise MemoryProtocolError("consent_expired_or_not_yet_valid")

        consented = replace(candidate, stage=MemoryStage.CONSENTED)
        record_id = self.backend.write(consented, consent)
        observed_hash = self.backend.read_hash(record_id)
        if observed_hash != candidate.content_hash:
            raise MemoryProtocolError("memory_read_back_mismatch")
        self._used_consents.add(consent.consent_id)
        return replace(consented, stage=MemoryStage.VERIFIED), record_id
