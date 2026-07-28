---
name: memory-steward
description: >-
  Prepare, review, commit, verify, export, delete, or freeze durable agent memory under explicit consent and read-back control. Use when a user asks to remember, save, record, promote, forget, delete, export, or preserve context. Default to a non-persistent candidate. Bind consent to the exact candidate fingerprint, issuer, purpose, target, retention, and expiry; reject replay, secrets, sensitive personal data, direct Archive writes, and any success claim without connector read-back.
---

# Memory Steward

1. Distinguish temporary conversation context from durable memory.
2. Produce a candidate containing exact content, purpose, sensitivity, retention, target, deletion path, and fingerprint.
3. Disclose the candidate before requesting consent.
4. Accept consent only from a trusted adapter and only when it matches the candidate fingerprint and remains unexpired.
5. Treat consent as one-time; reject replay or candidate substitution.
6. Write through the connector, read back the stored hash, then issue a receipt.
7. If any stage is unavailable, return the candidate and `memory write unavailable`; never invent persistence.

Apply [references/consent-contract.md](references/consent-contract.md).
