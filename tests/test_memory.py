import unittest
from datetime import datetime, timedelta, timezone

from tests._bootstrap import ensure_runtime_path

ensure_runtime_path()

from parallax_omega.memory import MemoryProtocolError, MemorySteward
from parallax_omega.models import MemoryConsent


def iso(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


class FakeBackend:
    def __init__(self, mismatch: bool = False):
        self.mismatch = mismatch
        self.values: dict[str, str] = {}

    def write(self, candidate, consent):
        self.values["1"] = candidate.content_hash
        return "1"

    def read_hash(self, record_id):
        return "bad" if self.mismatch else self.values[record_id]


class MemoryTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc).replace(microsecond=0)

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

    def test_disabled_backend_fails_closed(self):
        steward = MemorySteward()
        candidate = self.proposal(steward)
        with self.assertRaisesRegex(MemoryProtocolError, "memory_write_unavailable"):
            steward.commit(candidate, self.consent(candidate), at=self.now)

    def test_read_back_verifies(self):
        steward = MemorySteward(FakeBackend())
        candidate = self.proposal(steward)
        committed, record_id = steward.commit(candidate, self.consent(candidate), at=self.now)
        self.assertEqual(committed.stage.value, "verified")
        self.assertEqual(record_id, "1")

    def test_read_back_mismatch_fails(self):
        steward = MemorySteward(FakeBackend(True))
        candidate = self.proposal(steward)
        with self.assertRaisesRegex(MemoryProtocolError, "read_back_mismatch"):
            steward.commit(candidate, self.consent(candidate), at=self.now)

    def test_untrusted_consent_rejected(self):
        steward = MemorySteward(FakeBackend())
        candidate = self.proposal(steward)
        with self.assertRaisesRegex(MemoryProtocolError, "untrusted_consent"):
            steward.commit(
                candidate,
                self.consent(candidate, trusted_issuer=False),
                at=self.now,
            )

    def test_candidate_mismatch_rejected(self):
        steward = MemorySteward(FakeBackend())
        candidate = self.proposal(steward)
        with self.assertRaisesRegex(MemoryProtocolError, "candidate_mismatch"):
            steward.commit(
                candidate,
                self.consent(candidate, candidate_fingerprint="wrong"),
                at=self.now,
            )

    def test_expired_consent_rejected(self):
        steward = MemorySteward(FakeBackend())
        candidate = self.proposal(steward)
        with self.assertRaisesRegex(MemoryProtocolError, "expired"):
            steward.commit(
                candidate,
                self.consent(candidate, expires_at=iso(self.now - timedelta(seconds=1))),
                at=self.now,
            )

    def test_consent_is_one_time(self):
        steward = MemorySteward(FakeBackend())
        first = self.proposal(steward)
        consent = self.consent(first)
        steward.commit(first, consent, at=self.now)
        second = self.proposal(steward)
        replay = self.consent(
            second,
            consent_id=consent.consent_id,
            candidate_fingerprint=second.fingerprint(),
        )
        with self.assertRaisesRegex(MemoryProtocolError, "replay"):
            steward.commit(second, replay, at=self.now)


if __name__ == "__main__":
    unittest.main()
