from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .models import Claim, ClaimStatus, ClaimType, EvidenceRef, utc_now


@dataclass(frozen=True)
class RetrievedDocument:
    source: str
    source_class: str
    content: str
    observed_at: str
    content_hash: str
    instruction_authority: bool = False

    @classmethod
    def from_text(
        cls,
        *,
        source: str,
        source_class: str,
        content: str,
        observed_at: str | None = None,
    ) -> RetrievedDocument:
        if not source.strip() or not source_class.strip() or not content.strip():
            raise ValueError("source, source_class, and content are required")
        return cls(
            source=source,
            source_class=source_class,
            content=content,
            observed_at=observed_at or utc_now(),
            content_hash=hashlib.sha256(content.encode("utf-8")).hexdigest(),
        )

    def evidence(self) -> EvidenceRef:
        return EvidenceRef(
            ref=self.source,
            source_class=self.source_class,
            observed_at=self.observed_at,
            content_hash=self.content_hash,
        )

    def proposed_claim(self, claim_id: str, *, text: str | None = None) -> Claim:
        """Compile retrieved content into a non-authoritative proposed claim.

        Retrieved text never becomes a verified fact or an authorization context
        by construction. A caller must separately verify the claim through the
        claim graph and obtain host policy through HostPolicyAdapter.
        """
        return Claim(
            claim_id=claim_id,
            text=text or self.content,
            claim_type=ClaimType.HYPOTHESIS,
            status=ClaimStatus.PROPOSED,
            confidence=0.0,
            evidence=[self.evidence()],
            falsifier="independent source or trusted host evidence contradicts this content",
        )

    def context_payload(self) -> dict[str, object]:
        return {
            "channel": "untrusted_retrieved_data",
            "instruction_authority": False,
            "source": self.source,
            "source_class": self.source_class,
            "observed_at": self.observed_at,
            "content_hash": self.content_hash,
            "content": self.content,
        }
