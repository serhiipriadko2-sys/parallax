# Architecture — PARALLAX Ω 1.0.0-rc.2

## 1. Design thesis

Most custom agents optimize the answer. PARALLAX Ω optimizes the epistemic and operational chain that makes an answer safe to trust. Its unit of work is a **proof-carrying turn**.

```text
request
  -> intake and risk
  -> source ledger
  -> temporal claim DAG
  -> bounded alternatives
  -> blind-spot scan
  -> host-owned authority gate
  -> proposal or bounded action adapter
  -> synthesis
  -> postcondition verification
  -> payload-verifying receipt
```

The model may propose claims and tool calls. Deterministic code checks graph structure, freshness, confidence ceilings, authorization context, consent binding, and receipt integrity.

## 2. Four planes

### Observation plane

Captures source identity, source class, observation time, validity window, content hash, and status. Retrieved content is evidence, never higher-priority instruction.

### Deliberation plane

Builds a directed acyclic graph of claims. Derived claims list dependencies and cannot exceed the weakest verified dependency's confidence. A false, conflicted, or expired premise invalidates descendants. Repeated wrappers around one source do not count as independent evidence.

### Authority plane

Separates:

```text
capability available
!= host policy allows
!= user approval matches
!= execution attempted
!= effect observed
!= effect verified
```

Policy and approval come from a host or connector adapter, not model-controlled arguments. Exact approval binds to the action fingerprint and expires. R3/R4 additionally require current-state read, rollback plan, idempotency, and a postcondition. R4 requires independent evidence classes and platform dual control.

### Continuity plane

Memory remains candidate-only until a trusted consent adapter binds an exact candidate fingerprint, issue/expiry times, one-time use, write, read-back hash, deletion path, and receipt. Receipt chains are tamper-evident, not cryptographic proof of actor identity unless separately signed.

## 3. Turn envelope

```json
{
  "request_id": "uuid",
  "mode": "routine|research|audit|build|crisis",
  "claims": [],
  "assumptions": [],
  "forks": [],
  "action_proposals": [],
  "authority_decisions": [],
  "memory_candidates": [],
  "output": "...",
  "postconditions": [],
  "receipt": {}
}
```

## 4. Deterministic invariants

- `INV-001`: claim dependencies form a DAG.
- `INV-002`: a claim cannot verify while a dependency is non-verified.
- `INV-003`: derived confidence cannot exceed the weakest verified dependency.
- `INV-004`: facts require at least one current evidence reference.
- `INV-005`: invalid, conflicted, or expired premises invalidate descendants.
- `INV-006`: authorization context must be marked as trusted by a host adapter.
- `INV-007`: R2+ approval matches the exact action fingerprint and is unexpired.
- `INV-008`: R3/R4 require current-state read, rollback plan, idempotency, and postcondition.
- `INV-009`: R4/irreversible operations remain proposal-only without platform dual control.
- `INV-010`: direct Archive writes are forbidden.
- `INV-011`: memory consent is candidate-bound, trusted, unexpired, and one-time use.
- `INV-012`: memory success requires write/read-back hash equality.
- `INV-013`: receipt verification recomputes payload and chain hashes.
- `INV-014`: an advisory API never reports execution.
- `INV-015`: package evidence cannot produce a `verified-live` claim.

## 5. Platform topology

```text
ChatGPT Workspace Agent or Custom GPT
       | instructions + curated files + Skills
       | optional Apps OR custom Action
       v
Advisory API / custom MCP / Agents SDK
       |-- host policy adapter
       |-- deterministic claim and authority core
       |-- proposal-only memory surface
       `-- no external mutation tool in rc.2

Future action adapter
       | exact scope + platform approval
       | idempotency + current-state read
       `-- postcondition read-back + receipt
```

## 6. Why one external agent, not an autonomous committee

PARALLAX Ω uses functional modules rather than independent personalities:

- Observer: source state and freshness;
- Compiler: claim graph;
- Adversary: falsifiers and omitted premises;
- Governor: host-bound authority;
- Steward: memory candidate and consent;
- Verifier: postconditions and artifact integrity;
- Synthesizer: one coherent response.

This reduces authority ambiguity, handoff leakage, duplicated context, and inter-agent prompt-injection surface. A future specialist handoff must filter history, minimize data, and preserve the same host authority context.

## 7. Degradation behavior

| Missing dependency | Required behavior |
|---|---|
| web or current source | mark current claim `UNKNOWN`; do not substitute memory |
| host policy adapter | deny action |
| user approval | require approval or proposal-only |
| rollback/postcondition | block R3/R4 |
| memory backend | return candidate; report write unavailable |
| tracing backend | continue core; retain local redacted receipt |
| model or Workspace Agent surface | deterministic tests remain valid; behavioral status stays NOT RUN |

## 8. Adapted best practices

The architecture adapts rather than copies external guidance:

- OpenAI's instructions/files separation becomes a hard package split: behavior in Instructions, evidence in Knowledge.
- Workspace Agent connector controls become host-owned policy and action fingerprints, not prompt-only rules.
- Agents SDK guardrails and tracing complement the deterministic governor; they do not replace it.
- MCP least privilege becomes an advisory-only server with no write tool in the release candidate.
- OWASP excessive-agency and memory-poisoning controls become executable gates.
- NIST Govern/Map/Measure/Manage becomes a release profile with explicit current and target states.
