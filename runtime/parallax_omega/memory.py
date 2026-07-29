from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from .models import MemoryCandidate, MemoryConsent, MemoryStage
from .sensitivity import PROHIBITED_SENSITIVITY as PROHIBITED_SENSITIVITY_LABELS
from .sensitivity import detect_credentials, normalize_label


class MemoryProtocolError(ValueError):
    pass


class MemoryBackend(Protocol):
    idempotent_by_consent: bool

    def write(self, candidate: MemoryCandidate, consent: MemoryConsent) -> str: ...
    def read_hash(self, record_id: str) -> str: ...
    def quarantine(self, record_id: str, reason: str) -> None: ...


class ConsentRegistry(Protocol):
    durable: bool

    def reserve(
        self,
        consent_id: str,
        candidate_fingerprint: str,
        expires_at: str,
    ) -> bool: ...

    def mark_committed(self, consent_id: str, record_id: str) -> None: ...
    def mark_quarantined(
        self,
        consent_id: str,
        record_id: str | None,
        reason: str,
    ) -> None: ...


class DisabledMemoryBackend:
    idempotent_by_consent = False

    def write(self, candidate: MemoryCandidate, consent: MemoryConsent) -> str:
        raise MemoryProtocolError("memory_write_unavailable")

    def read_hash(self, record_id: str) -> str:
        raise MemoryProtocolError("memory_read_unavailable")

    def quarantine(self, record_id: str, reason: str) -> None:
        del record_id, reason


class InMemoryConsentRegistry:
    durable = False

    def __init__(self) -> None:
        self._states: dict[str, str] = {}

    def reserve(self, consent_id: str, candidate_fingerprint: str, expires_at: str) -> bool:
        del candidate_fingerprint, expires_at
        if consent_id in self._states:
            return False
        self._states[consent_id] = "reserved"
        return True

    def mark_committed(self, consent_id: str, record_id: str) -> None:
        del record_id
        self._states[consent_id] = "committed"

    def mark_quarantined(
        self,
        consent_id: str,
        record_id: str | None,
        reason: str,
    ) -> None:
        del record_id, reason
        self._states[consent_id] = "quarantined"


class SQLiteConsentRegistry:
    """Durable one-time consent lifecycle for local or single-node deployments."""

    durable = True

    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """
                create table if not exists memory_consents (
                    consent_id text primary key,
                    candidate_fingerprint text not null,
                    expires_at text not null,
                    state text not null check (state in ('reserved','committed','quarantined')),
                    record_id text,
                    quarantine_reason text,
                    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                    updated_at text not null default (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
                )
                """
            )

    def reserve(self, consent_id: str, candidate_fingerprint: str, expires_at: str) -> bool:
        try:
            with sqlite3.connect(self.path, isolation_level="IMMEDIATE") as connection:
                connection.execute(
                    """
                    insert into memory_consents (
                        consent_id, candidate_fingerprint, expires_at, state
                    ) values (?, ?, ?, 'reserved')
                    """,
                    (consent_id, candidate_fingerprint, expires_at),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def mark_committed(self, consent_id: str, record_id: str) -> None:
        with sqlite3.connect(self.path, isolation_level="IMMEDIATE") as connection:
            cursor = connection.execute(
                """
                update memory_consents
                   set state='committed', record_id=?, updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')
                 where consent_id=? and state='reserved'
                """,
                (record_id, consent_id),
            )
            if cursor.rowcount != 1:
                raise MemoryProtocolError("consent_state_transition_failed")

    def mark_quarantined(
        self,
        consent_id: str,
        record_id: str | None,
        reason: str,
    ) -> None:
        with sqlite3.connect(self.path, isolation_level="IMMEDIATE") as connection:
            connection.execute(
                """
                update memory_consents
                   set state='quarantined', record_id=?, quarantine_reason=?,
                       updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')
                 where consent_id=? and state='reserved'
                """,
                (record_id, reason[:500], consent_id),
            )

    def state(self, consent_id: str) -> str | None:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "select state from memory_consents where consent_id=?",
                (consent_id,),
            ).fetchone()
        return None if row is None else str(row[0])


class SQLiteMemoryBackend:
    """Idempotent staging backend keyed by host-issued consent_id."""

    idempotent_by_consent = True

    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as connection:
            connection.execute(
                """
                create table if not exists memory_records (
                    consent_id text primary key,
                    record_id text not null unique,
                    candidate_fingerprint text not null,
                    content_hash text not null,
                    content text not null,
                    status text not null default 'active'
                        check (status in ('active','quarantined')),
                    quarantine_reason text,
                    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
                )
                """
            )

    def write(self, candidate: MemoryCandidate, consent: MemoryConsent) -> str:
        record_id = hashlib.sha256(
            f"parallax.memory.record.v1:{consent.consent_id}".encode()
        ).hexdigest()
        fingerprint = candidate.fingerprint()
        with sqlite3.connect(self.path, isolation_level="IMMEDIATE") as connection:
            connection.execute(
                """
                insert into memory_records (
                    consent_id, record_id, candidate_fingerprint, content_hash, content
                ) values (?, ?, ?, ?, ?)
                on conflict(consent_id) do nothing
                """,
                (
                    consent.consent_id,
                    record_id,
                    fingerprint,
                    candidate.content_hash,
                    candidate.content,
                ),
            )
            row = connection.execute(
                """
                select record_id, candidate_fingerprint, content_hash
                  from memory_records where consent_id=?
                """,
                (consent.consent_id,),
            ).fetchone()
        if row is None:
            raise MemoryProtocolError("memory_write_failed")
        if str(row[1]) != fingerprint or str(row[2]) != candidate.content_hash:
            raise MemoryProtocolError("memory_idempotency_conflict")
        return str(row[0])

    def read_hash(self, record_id: str) -> str:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "select content_hash from memory_records where record_id=?",
                (record_id,),
            ).fetchone()
        if row is None:
            raise MemoryProtocolError("memory_record_missing")
        return str(row[0])

    def quarantine(self, record_id: str, reason: str) -> None:
        with sqlite3.connect(self.path, isolation_level="IMMEDIATE") as connection:
            connection.execute(
                """
                update memory_records
                   set status='quarantined', quarantine_reason=?
                 where record_id=?
                """,
                (reason[:500], record_id),
            )

    def status(self, record_id: str) -> str | None:
        with sqlite3.connect(self.path) as connection:
            row = connection.execute(
                "select status from memory_records where record_id=?",
                (record_id,),
            ).fetchone()
        return None if row is None else str(row[0])


class MemorySteward:
    # Shared with the sensitivity module so the label set has exactly one definition.
    PROHIBITED_SENSITIVITY = PROHIBITED_SENSITIVITY_LABELS
    ALLOWED_TARGETS = {"journal", "open_loop", "shadow"}
    MAX_CONTENT_CHARS = 4096

    def __init__(
        self,
        backend: MemoryBackend | None = None,
        consent_registry: ConsentRegistry | None = None,
    ) -> None:
        self.backend = backend or DisabledMemoryBackend()
        self.consent_registry = consent_registry or InMemoryConsentRegistry()
        if backend is not None:
            if not self.consent_registry.durable:
                raise MemoryProtocolError("durable_consent_registry_required")
            if not getattr(self.backend, "idempotent_by_consent", False):
                raise MemoryProtocolError("idempotent_memory_backend_required")

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
        if len(content) > self.MAX_CONTENT_CHARS:
            raise MemoryProtocolError("memory_content_too_large")
        normalized_sensitivity = normalize_label(sensitivity)
        if not normalized_sensitivity:
            raise MemoryProtocolError("sensitivity_label_required")
        # A label that survives normalization but is still non-ASCII is a confusable
        # spelling of a prohibited term (NFKC does not fold Cyrillic to Latin), so it is
        # refused rather than compared and silently accepted.
        if not normalized_sensitivity.isascii():
            raise MemoryProtocolError("sensitivity_label_not_ascii")
        if normalized_sensitivity in self.PROHIBITED_SENSITIVITY:
            raise MemoryProtocolError("sensitive_memory_prohibited")
        # The label is caller-declared, so it cannot be the only gate: inspect the payload
        # regardless of what was claimed.
        if detect_credentials(content):
            raise MemoryProtocolError("credential_content_prohibited")
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
        if consent.candidate_fingerprint != candidate.fingerprint():
            raise MemoryProtocolError("consent_candidate_mismatch")
        if not consent.is_current(at):
            raise MemoryProtocolError("consent_expired_or_not_yet_valid")
        if not self.consent_registry.reserve(
            consent.consent_id,
            consent.candidate_fingerprint,
            consent.expires_at,
        ):
            raise MemoryProtocolError("consent_replay_detected")

        consented = replace(candidate, stage=MemoryStage.CONSENTED)
        record_id: str | None = None
        try:
            record_id = self.backend.write(consented, consent)
            observed_hash = self.backend.read_hash(record_id)
            if observed_hash != candidate.content_hash:
                self.backend.quarantine(record_id, "memory_read_back_mismatch")
                self.consent_registry.mark_quarantined(
                    consent.consent_id,
                    record_id,
                    "memory_read_back_mismatch",
                )
                raise MemoryProtocolError("memory_read_back_mismatch")
            self.consent_registry.mark_committed(consent.consent_id, record_id)
            return replace(consented, stage=MemoryStage.VERIFIED), record_id
        except Exception as exc:
            if not isinstance(exc, MemoryProtocolError) or str(exc) != "memory_read_back_mismatch":
                self.consent_registry.mark_quarantined(
                    consent.consent_id,
                    record_id,
                    f"write_or_read_failure:{type(exc).__name__}",
                )
            raise
