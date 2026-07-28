# Assurance case

This file is the top-level argument for what the package can and cannot safely claim.

| Claim | Argument | Evidence | Residual uncertainty |
|---|---|---|---|
| C1: model input cannot authorize itself | authorization context is created only by host policy adapters | policy tests, API/MCP surface tests, ADR-0002 | host deployment could bypass the adapter |
| C2: stale or false premises do not silently support decisions | evidence has validity windows; conflicts/invalidity propagate through the DAG | claim graph tests | model may omit a premise from the graph |
| C3: consequential actions fail closed | exact allowlist, action fingerprint, approval expiry, current-state read, rollback, idempotency, postcondition, dual control | authority tests and policy schema | external platform must enforce actual execution boundary |
| C4: durable memory requires exact consent and verification | candidate disclosure, one-time binding, expiry, write/read-back hash | memory tests | backend ACL/RLS and deletion must be verified live |
| C5: receipts reveal tampering | payload and previous receipt hashes are recomputed | receipt tests | hashes do not authenticate actor identity or real-world truth |
| C6: release claims are reproducible | clean manifests, deterministic ZIP, path and case-collision checks, skill packaging | release-manifest verification and QC report | Builder/UI behavior remains untested until upload |
| C7: behavioral quality is not inferred from schema validation | executable tests and manual/model behavioral bank have distinct statuses | test runner and eval README | live model eval remains NOT RUN in this package build |

## Defeaters

Any of the following defeats a production-readiness claim: model-controlled policy fields, unknown policy provenance, missing target authentication, skipped tests counted as pass, stale source without revalidation, unverified memory read-back, action without postcondition, archive hash drift, or absence of target-specific behavioral traces.
