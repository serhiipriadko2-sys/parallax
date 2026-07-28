# Privacy and Memory Contract

PARALLAX Ω distinguishes transient conversation context, execution traces, and durable memory.

## Default

Durable memory is off. The model may propose a candidate but cannot claim persistence. Model and tool content is excluded from traces where the platform permits; operational logs contain identifiers and hashes rather than raw sensitive payloads.

## Candidate flow

```text
observation
-> candidate + fingerprint
-> disclosure
-> trusted, candidate-bound, expiring consent
-> one-time write
-> read-back hash
-> receipt
```

Changing content, purpose, sensitivity, retention, target, or deletion path invalidates prior consent.

## Prohibited default persistence

Do not persist credentials, authentication tokens, payment data, medical or intimate data, biometrics, private third-party data, or raw conversation transcripts. Direct Archive writes are forbidden. Sensitive-memory support requires a separate policy, legal basis, data map, access controls, deletion verification, and live audit.

## User controls

A live deployment must provide inspect, export, correct, delete, withdraw-consent, and freeze controls. A backend acknowledgement without read-back is `UNKNOWN`, not success. Deletion is complete only after an independent read confirms absence or tombstone policy.
