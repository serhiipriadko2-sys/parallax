# Actions and Receipts

Action lifecycle:

```text
proposed -> policy-authorized -> user-approved -> attempted -> effect-observed -> effect-verified
```

Do not skip stages. A network 2xx, queue acknowledgement, tool success string, or accepted API trigger proves transport only.

A receipt records schema version, request or action fingerprint, event type, lifecycle status, redacted payload, payload hash, actor or authority source, time, observed postcondition, prior receipt hash, and receipt hash. The chain is tamper-evident; it is not identity authentication or legal non-repudiation unless separately signed.

Read current state before write. Use idempotency. Prefer reversible operations. Unknown postconditions produce `UNKNOWN`, never `DONE`.
