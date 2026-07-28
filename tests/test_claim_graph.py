import unittest
from datetime import datetime, timedelta, timezone

from tests._bootstrap import ensure_runtime_path

ensure_runtime_path()

from parallax_omega.claim_graph import ClaimGraph, ClaimGraphError
from parallax_omega.models import Claim, ClaimStatus, ClaimType, EvidenceRef


class ClaimGraphTests(unittest.TestCase):
    def fact(self, cid: str, *, source_class: str = "primary", valid_until: str | None = None) -> Claim:
        return Claim(
            cid,
            cid,
            ClaimType.FACT,
            evidence=[EvidenceRef(f"src:{cid}", source_class, valid_until=valid_until)],
        )

    def test_fact_requires_evidence_to_verify(self):
        graph = ClaimGraph()
        graph.add(Claim("a", "a", ClaimType.FACT))
        with self.assertRaises(ClaimGraphError):
            graph.verify("a", 0.8)

    def test_dependency_must_exist(self):
        graph = ClaimGraph()
        with self.assertRaises(ClaimGraphError):
            graph.add(Claim("b", "b", ClaimType.INTERPRETATION, dependencies={"a"}))

    def test_verification_requires_verified_dependency(self):
        graph = ClaimGraph()
        graph.add(self.fact("a"))
        graph.add(Claim("b", "b", ClaimType.INTERPRETATION, dependencies={"a"}))
        with self.assertRaises(ClaimGraphError):
            graph.verify("b", 0.8)

    def test_dependency_confidence_is_a_ceiling(self):
        graph = ClaimGraph()
        graph.add(self.fact("a"))
        graph.verify("a", 0.7)
        graph.add(Claim("b", "b", ClaimType.INTERPRETATION, dependencies={"a"}))
        with self.assertRaisesRegex(ClaimGraphError, "dependency ceiling"):
            graph.verify("b", 0.8)
        graph.verify("b", 0.7)

    def test_invalidation_propagates(self):
        graph = ClaimGraph()
        graph.add(self.fact("a"))
        graph.verify("a", 0.9)
        graph.add(Claim("b", "b", ClaimType.INTERPRETATION, dependencies={"a"}))
        graph.verify("b", 0.8)
        graph.add(Claim("c", "c", ClaimType.DECISION, dependencies={"b"}))
        graph.verify("c", 0.7)
        self.assertEqual(graph.invalidate("a", "falsified"), ["a", "b", "c"])
        self.assertEqual(graph.get("c").status, ClaimStatus.INVALID)

    def test_conflict_propagates_to_descendants(self):
        graph = ClaimGraph()
        graph.add(self.fact("a"))
        graph.verify("a", 0.9)
        graph.add(Claim("b", "b", ClaimType.INTERPRETATION, dependencies={"a"}))
        graph.verify("b", 0.8)
        self.assertEqual(graph.mark_conflict("a", "sources disagree"), ["b"])
        self.assertEqual(graph.get("a").status, ClaimStatus.CONFLICT)
        self.assertEqual(graph.get("b").status, ClaimStatus.INVALID)

    def test_expired_evidence_cannot_verify(self):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        expired = (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        observed = (now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
        graph = ClaimGraph()
        graph.add(
            Claim(
                "a",
                "a",
                ClaimType.FACT,
                evidence=[EvidenceRef("src", "web", observed_at=observed, valid_until=expired)],
            )
        )
        with self.assertRaisesRegex(ClaimGraphError, "current evidence"):
            graph.verify("a", 0.8, at=now)

    def test_time_revalidation_invalidates_descendants(self):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        expires = (now + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        later = now + timedelta(seconds=2)
        graph = ClaimGraph()
        graph.add(self.fact("a", valid_until=expires))
        graph.verify("a", 0.8, at=now)
        graph.add(Claim("b", "b", ClaimType.INTERPRETATION, dependencies={"a"}))
        graph.verify("b", 0.7, at=now)
        self.assertEqual(graph.revalidate_time(at=later), ["a", "b"])

    def test_topological_order(self):
        graph = ClaimGraph()
        graph.add(self.fact("a"))
        graph.add(self.fact("b"))
        graph.add(Claim("c", "c", ClaimType.INTERPRETATION, dependencies={"a", "b"}))
        order = graph.topological_order()
        self.assertLess(order.index("a"), order.index("c"))
        self.assertLess(order.index("b"), order.index("c"))

    def test_duplicate_rejected(self):
        graph = ClaimGraph()
        graph.add(self.fact("a"))
        with self.assertRaises(ClaimGraphError):
            graph.add(self.fact("a"))

    def test_negative_confidence_rejected(self):
        graph = ClaimGraph()
        graph.add(self.fact("a"))
        with self.assertRaises(ClaimGraphError):
            graph.verify("a", -0.1)

    def test_preverified_insert_rejected(self):
        graph = ClaimGraph()
        claim = self.fact("a")
        claim.status = ClaimStatus.VERIFIED
        with self.assertRaises(ClaimGraphError):
            graph.add(claim)

    def test_duplicate_evidence_reference_counts_once(self):
        graph = ClaimGraph()
        evidence = EvidenceRef("same", "test")
        graph.add(Claim("a", "a", ClaimType.FACT, evidence=[evidence]))
        graph.verify("a", 0.9)
        graph.add(Claim("b", "b", ClaimType.FACT, evidence=[evidence]))
        graph.verify("b", 0.9)
        self.assertEqual(graph.verified_evidence_count(("a", "b")), 1)


if __name__ == "__main__":
    unittest.main()
