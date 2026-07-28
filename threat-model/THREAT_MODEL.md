# Threat model

## Assets

User intent, credentials, private data, evidence lineage, policy files, approval tokens, claim graph, external effects, memory, receipts, traces, and release identity.

## Actors

End user; workspace owner; agent/model; trusted host; connector/MCP provider; retrieved-content author; repository contributor; CI/release operator; memory administrator; external attacker.

## Trust boundaries

Model context; retrieved content; instruction/knowledge files; ChatGPT or Workspace Agent tools; Custom GPT Actions; MCP server; API runtime; host policy adapter; external services; memory backend; CI and release system.

## Principal threats and transformed controls

| Threat | Failure | Control | Verification |
|---|---|---|---|
| prompt injection | retrieved text becomes authority | data/instruction separation and no authorization in content | injection evals |
| tool poisoning | tool description or response widens scope | exact adapter schema, tool/action allowlist, response treated as evidence | surface tests |
| excessive agency | action exceeds intent | host-owned action governor and proposal-only R4 | authority tests |
| confused deputy | agent account acts for the wrong principal | actor/scope/fingerprint binding and target OAuth review | staging test |
| approval substitution | consent for A is reused for B | exact action/candidate fingerprint and expiry | authority/memory tests |
| policy injection | client supplies policy fields | request schemas forbid authority fields; policy loaded by host | API/MCP tests |
| stale evidence | expired source supports action | `valid_until`, temporal revalidation, descendant invalidation | claim tests |
| source laundering | one source appears independent through wrappers | unique refs and independent source classes | claim/authority tests |
| memory poisoning | false or sensitive content becomes durable | candidate disclosure, sensitivity block, one-time consent, read-back | memory tests |
| replay/duplication | write or approval repeats | idempotency and consumed-consent registry | tests plus target store |
| partial effect | transport success but wrong business state | explicit postcondition and independent observation | staging effect test |
| receipt tampering | audit history is modified | payload and previous-hash verification | receipt tests |
| false non-repudiation | hash is mistaken for signed actor proof | documented receipt boundary; external signature required for actor proof | assurance review |
| supply-chain drift | SDK/tool behavior changes | bounded versions, clean CI profiles, SBOM/dependency review | scheduled maintenance |
| test inflation | skipped/manual cases counted as pass | explicit PASS/SKIP/DEPENDENCY_MISSING/NOT_RUN statuses | runner tests |
| archive confusion | traversal, duplicate, case collision, generated noise | fail-closed release manifest and ZIP QC | release verification |
| trace exfiltration | prompts or secrets enter observability | redaction, no-store, sensitive tracing opt-out | staging log review |

## Residual risk

A model can omit a premise, misclassify risk, or produce persuasive but incomplete reasoning. Deterministic controls constrain transitions but do not prove semantic completeness. External authorization, identity, effect observation, deletion, and trace handling remain deployment responsibilities.
