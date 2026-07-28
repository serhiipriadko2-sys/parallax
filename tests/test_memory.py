import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from tests._bootstrap import ensure_runtime_path

ensure_runtime_path()

from parallax_omega.memory import (
    MemoryProtocolError,
    MemorySteward,
    SQLiteConsentRegistry,
    SQLiteMemoryBackend,
)
from parallax_omega.models import MemoryConsent


def iso(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


class FakeBackend:
    idempotent_by_consent = True

    def __init__(self, mismatch: bool = False):
        self.mismatch = mismatch
        self.values: dict[str, str] = {}
        self.by_consent: dict[str, str] = {}
        self.write_count = 0
        self.quarantined: set[str] = set()

    def write(self, candidate, consent):
        if consent.consent_id in self.by_consent:
            return self.by_consent[consent.consent_id]
        self.write_count += 1
        record_id = str(self.write_count)
        self.by_consent[consent.consent_id] = record_id
        self.values[record_id] = candidate.content_hash
        return record_id

    def read_hash(self, record_id):
        return "bad" if self.mismatch else self.values[record_id]

    def quarantine(self, record_id, reason):
        del reason
        self.quarantined.add(record_id)


class NonIdempotentBackend(FakeBackend):
    idempotent_by_consent = False


class DurableFakeRegistry:
    durable = True

    def __init__(self):
        self.values: dict[str, str] = {}

    def reserve(self, consent_id, candidate_fingerprint, expires_at):
        del candidate_fingerprint, expires_at
        if consent_id in self.values:
            return False
        self.values[consent_id] = "reserved"
        return True

    def mark_committed(self, consent_id, record_id):
        del record_id
        self.values[consent_id] = "committed"

    def mark_quarantined(self, consent_id, record_id, reason):
        del record_id, reason
        self.values[consent_id] = "quarantined"


class MemoryTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(UTC).replace(microsecond=0)

    def proposal(self, steward):
        return steward.propose(
            content="prefers concise reports",
            purpose="formatting",
            sensitivity="normal",
            retention_days=30,
            target="journal",
            deletion_path="settings/delete",
        )

    def consent(self, candidate, **overrides):
        values = dict(
            consent_id="consent-1",
            candidate_fingerprint=candidate.fingerprint(),
            issued_at=iso(self.now - timedelta(seconds=1)),
            expires_at=iso(self.now + timedelta(minutes=5)),
            issuer="test-host",
            trusted_issuer=True,
        )
        values.update(overrides)
        return MemoryConsent(**values)

    def enabled_steward(self, backend=None, registry=None):
        return MemorySteward(backend or FakeBackend(), registry or DurableFakeRegistry())

    def test_direct_archive_forbidden(self):
        with self.assertRaises(MemoryProtocolError):
            MemorySteward().propose(
                content="x",
                purpose="p",
                sensitivity="normal",
                retention_days=30,
                target="archive",
                deletion_path="d",
            )

    def test_sensitive_forbidden(self):
        with self.assertRaises(MemoryProtocolError):
            MemorySteward().propose(
                content="x",
                purpose="p",
                sensitivity="credential",
                retention_days=30,
                target="journal",
                deletion_path="d",
            )

    def test_content_size_is_bounded(self):
        with self.assertRaisesRegex(MemoryProtocolError, "too_large"):
            MemorySteward().propose(
                content="x" * 4097,
                purpose="p",
                sensitivity="normal",
                retention_days=30,
                target="journal",
                deletion_path="d",
            )

    def test_disabled_backend_fails_closed(self):
        steward = MemorySteward()
        candidate = self.proposal(steward)
        with self.assertRaisesRegex(MemoryProtocolError, "memory_write_unavailable"):
            steward.commit(candidate, self.consent(candidate), at=self.now)

    def test_enabled_backend_requires_durable_registry(self):
        with self.assertRaisesRegex(MemoryProtocolError, "durable_consent_registry_required"):
            MemorySteward(FakeBackend())

    def test_enabled_backend_requires_idempotency_contract(self):
        with self.assertRaisesRegex(MemoryProtocolError, "idempotent_memory_backend_required"):
            MemorySteward(NonIdempotentBackend(), DurableFakeRegistry())

    def test_read_back_verifies_and_commits_registry(self):
        registry = DurableFakeRegistry()
        steward = self.enabled_steward(registry=registry)
        candidate = self.proposal(steward)
        committed, record_id = steward.commit(candidate, self.consent(candidate), at=self.now)
        self.assertEqual(committed.stage.value, "verified")
        self.assertEqual(record_id, "1")
        self.assertEqual(registry.values["consent-1"], "committed")

    def test_read_back_mismatch_quarantines_and_cannot_rewrite(self):
        backend = FakeBackend(True)
        registry = DurableFakeRegistry()
        steward = self.enabled_steward(backend, registry)
        candidate = self.proposal(steward)
        consent = self.consent(candidate)
        with self.assertRaisesRegex(MemoryProtocolError, "read_back_mismatch"):
            steward.commit(candidate, consent, at=self.now)
        self.assertEqual(backend.write_count, 1)
        self.assertEqual(registry.values["consent-1"], "quarantined")
        self.assertEqual(backend.quarantined, {"1"})
        with self.assertRaisesRegex(MemoryProtocolError, "replay"):
            steward.commit(candidate, consent, at=self.now)
        self.assertEqual(backend.write_count, 1)

    def test_untrusted_consent_rejected(self):
        steward = self.enabled_steward()
        candidate = self.proposal(steward)
        with self.assertRaisesRegex(MemoryProtocolError, "untrusted_consent"):
            steward.commit(
                candidate,
                self.consent(candidate, trusted_issuer=False),
                at=self.now,
            )

    def test_candidate_mismatch_rejected(self):
        steward = self.enabled_steward()
        candidate = self.proposal(steward)
        with self.assertRaisesRegex(MemoryProtocolError, "candidate_mismatch"):
            steward.commit(
                candidate,
                self.consent(candidate, candidate_fingerprint="wrong"),
                at=self.now,
            )

    def test_expired_consent_rejected(self):
        steward = self.enabled_steward()
        candidate = self.proposal(steward)
        with self.assertRaisesRegex(MemoryProtocolError, "expired"):
            steward.commit(
                candidate,
                self.consent(candidate, expires_at=iso(self.now - timedelta(seconds=1))),
                at=self.now,
            )

    def test_consent_is_one_time(self):
        registry = DurableFakeRegistry()
        steward = self.enabled_steward(registry=registry)
        first = self.proposal(steward)
        consent = self.consent(first)
        steward.commit(first, consent, at=self.now)
        with self.assertRaisesRegex(MemoryProtocolError, "replay"):
            steward.commit(first, consent, at=self.now)

    def test_sqlite_registry_and_backend_survive_restart_and_are_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory.sqlite3"
            first = MemorySteward(SQLiteMemoryBackend(path), SQLiteConsentRegistry(path))
            candidate = self.proposal(first)
            consent = self.consent(candidate)
            committed, record_id = first.commit(candidate, consent, at=self.now)
            self.assertEqual(committed.stage.value, "verified")

            backend = SQLiteMemoryBackend(path)
            self.assertEqual(backend.write(candidate, consent), record_id)

            restarted = MemorySteward(backend, SQLiteConsentRegistry(path))
            with self.assertRaisesRegex(MemoryProtocolError, "replay"):
                restarted.commit(candidate, consent, at=self.now)


if __name__ == "__main__":
    unittest.main()
