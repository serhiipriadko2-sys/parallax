# Control catalog

| ID | Control objective | Deterministic evidence |
|---|---|---|
| AUTH-HOST-OWNED | Authorization context comes only from a trusted host adapter. | policy, API, MCP, and Agents SDK tests |
| AUTH-EXACT-ALLOWLIST | Policy matches exact tool, operation, maximum risk, and scope prefix; default deny. | policy schema and tests |
| AUTH-FAIL-CLOSED | Missing, unknown, or malformed policy denies. | policy tests |
| AUTH-ACTION-BOUND-APPROVAL | Approval binds to the complete action fingerprint and expiry. | authority tests |
| AUTH-ROLLBACK | R3/R4 require current-state read, concrete rollback, idempotency, and postcondition. | authority tests |
| AUTH-DUAL-CONTROL | R4/irreversible action remains proposal-only without platform dual control. | authority tests |
| TRUTH-TEMPORAL | Evidence is valid only inside its observation/validity interval. | claim graph tests |
| TRUTH-CONFIDENCE-CEILING | Derived confidence cannot exceed the weakest verified dependency. | claim graph tests |
| TRUTH-SOURCE-DIVERSITY | Duplicated wrappers do not count as independent evidence classes. | claim and authority tests |
| MEM-CANDIDATE-BINDING | Consent matches the exact disclosed memory candidate. | memory tests |
| MEM-ONE-TIME | Consent cannot be replayed. | memory tests |
| MEM-READ-BACK | Persistence is claimed only after hash-equivalent read-back. | memory tests |
| REC-TAMPER-EVIDENCE | Payload and chain hashes are recomputed. | receipt tests |
| REC-NON-REPUDIATION-BOUNDARY | Receipt hashing is not actor authentication or real-world proof. | assurance case and evals |
| REL-MANIFEST | Artifact contents match an external manifest after packaging. | release manifest tests |
| REL-CASE-COLLISION | Case-fold collisions, duplicates, traversal, and symlinks are rejected. | release manifest tests |
| REL-TEST-SEMANTICS | PASS, SKIP, DEPENDENCY_MISSING, and NOT_RUN are not averaged together. | test/eval runners |
| SEC-MCP-CHANGE-CONTROL | New or changed MCP tools require review and reauthorization. | threat model and staging gate |
| SEC-GUARDRAIL-COVERAGE | Guardrail scope is explicit per tool/adapter surface. | surface contracts and evals |
| CORE-STATUS-PRECISION | Created, packaged, deployed, invoked, and verified-live remain distinct. | package tests and output contract |
