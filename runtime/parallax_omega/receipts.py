from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any
from uuid import uuid4

from .models import Receipt, canonical_hash, utc_now


class ReceiptChain:
    """Tamper-evident chain. Integrity is not identity authentication or non-repudiation."""

    SCHEMA_VERSION = 2

    def __init__(self) -> None:
        self._receipts: list[Receipt] = []

    @property
    def receipts(self) -> tuple[Receipt, ...]:
        return tuple(deepcopy(self._receipts))

    @property
    def last_hash(self) -> str | None:
        return self._receipts[-1].receipt_hash if self._receipts else None

    def append(
        self,
        event_type: str,
        status: str,
        payload: dict[str, Any],
        metadata: dict[str, Any] | None = None,
        *,
        authoritative: bool = False,
    ) -> Receipt:
        if not event_type.strip() or not status.strip():
            raise ValueError("event_type and status are required")
        canonical_payload = json.loads(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        )
        payload_hash = canonical_hash(canonical_payload)
        previous_hash = self.last_hash
        envelope = {
            "schema_version": self.SCHEMA_VERSION,
            "receipt_id": str(uuid4()),
            "timestamp": utc_now(),
            "event_type": event_type,
            "status": status,
            "payload": canonical_payload,
            "payload_hash": payload_hash,
            "previous_hash": previous_hash,
            "metadata": metadata or {},
            "authoritative": authoritative,
        }
        receipt_hash = canonical_hash(envelope)
        receipt = Receipt(receipt_hash=receipt_hash, **envelope)
        self._receipts.append(receipt)
        return deepcopy(receipt)

    def verify(self) -> bool:
        previous_hash: str | None = None
        for receipt in self._receipts:
            if canonical_hash(receipt.payload) != receipt.payload_hash:
                return False
            envelope = {
                "schema_version": receipt.schema_version,
                "receipt_id": receipt.receipt_id,
                "timestamp": receipt.timestamp,
                "event_type": receipt.event_type,
                "status": receipt.status,
                "payload": receipt.payload,
                "payload_hash": receipt.payload_hash,
                "previous_hash": receipt.previous_hash,
                "metadata": receipt.metadata,
                "authoritative": receipt.authoritative,
            }
            expected = hashlib.sha256(
                json.dumps(
                    envelope,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            if receipt.previous_hash != previous_hash or receipt.receipt_hash != expected:
                return False
            previous_hash = receipt.receipt_hash
        return True
