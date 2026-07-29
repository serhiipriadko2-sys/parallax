# Research and architecture audit — second pass

Date: 2026-07-28  
Candidate: PARALLAX Ω `1.0.0-rc.3`

## Executive verdict

The second pass materially changes the security model. The first candidate had strong deterministic primitives but an unsafe adapter premise: API/MCP callers could supply policy-like fields, and the earlier release narrative did not adequately distinguish a clean-extraction test from a preconfigured environment. RC.2 moves authority to a host-owned exact allowlist and makes test status explicit.

Status remains `locally verified release candidate`, not deployed, invoked, or verified live.

## Sources and transformation method

The design used the supplied Iskra/SoT30 materials, observed GitHub and Supabase state, and current primary guidance from OpenAI, MCP, NIST AI RMF, and OWASP. Guidance was not copied as a checklist. It was translated into package-specific invariants:

- platform guardrails → host-owned control plane and adapter-specific coverage;
- least privilege → exact tool/operation/scope allowlists with default deny;
- human approval → action-bound, expiring approval rather than a boolean;
- evidence grounding → temporal DAG with confidence ceilings and source diversity;
- memory safety → disclosed candidate, exact consent, one-time use, read-back;
- tracing/audit → receipt lineage plus explicit limits of hash evidence;
- eval best practice → executable tests separated from behavioral cases and live effects;
- risk management → assurance claims, defeaters, incident and rollback runbooks.

## Second-pass findings

### F1 — model-controlled authority in adapters

The RC.1 API/MCP shape could accept policy-like booleans from the same request being judged. Even though the endpoint was advisory, this could return a misleading `ALLOW`. RC.2 forbids authority fields in request schemas and loads policy only through the host adapter.

### F2 — read-only policy was too broad

A mode flag that allowed all R0/R1 work did not encode tool, operation, or data scope. RC.2 uses exact rules and intentionally supports no wildcards.

### F3 — test proof depended on environment

A raw clean extraction initially failed imports unless the package was installed, and API tests could skip when extras were absent. RC.2 bootstraps the pure core from the tree, exposes explicit test profiles, and reports dependency-missing/SKIP separately.

### F4 — receipt semantics were underspecified

RC.1 receipts did not retain enough canonical payload data for independent recomputation. RC.2 stores the payload, verifies payload and chain hashes, and states that hashes are not actor signatures or proof of real-world truth.

### F5 — evidence freshness and independence needed enforcement

RC.2 enforces observation/expiry windows, confidence ceilings, conflict propagation, unique evidence references, and distinct source classes for high-impact decisions.

### F6 — consent needed exact binding

A token-presence pattern is insufficient. RC.2 binds consent to candidate fingerprint, issuer, issuance/expiry, one-time use, and read-back verification.

## Architectural synthesis

The unique unit is not a persona or multi-agent society. It is a **proof-carrying transition**:

`evidence state → claim state → policy state → proposed transition → observed postcondition → receipt`

Each arrow has a typed gate. The model may propose content but cannot mint authority, declare persistence, or upgrade a transport response into a verified effect.

## What-if stress results

1. Malformed policy file → deny all.
2. New MCP action after review → unavailable until explicit review/reauthorization.
3. Hosted tool outside function-tool guardrail coverage → separate host/tool control required.
4. Expired evidence → claim and descendants downgraded/invalidated.
5. Duplicate source wrappers → one source, not two.
6. Wrong approval fingerprint → block.
7. Memory backend unavailable → candidate only.
8. 202/2xx without postcondition → accepted/attempted, effect unknown.
9. Receipt edited and rehashed by unknown actor → lineage may validate, actor identity still unproven.
10. Builder upload succeeds → packaged/uploaded only until behavioral and effect gates pass.

## Remaining blind spots

- No target Workspace Agent/Custom GPT upload was performed.
- Behavioral cases are schema-validated but not run on a pinned model/surface.
- MCP and Agents SDK imports require optional dependencies and target credentials.
- Host policy authenticity is file/host trust; cryptographic policy signing is not implemented.
- External action execution is deliberately absent from the package API.
- Supabase memory remains incompatible with a verified-live memory claim until ACL/RLS/gateway/read-back are remediated and observed.

## Release decision

Release RC.2 as a locally verified, fail-closed reference stack. Promotion to `1.0.0` requires target-specific authentication review, behavioral eval execution, adversarial tool testing, restricted pilot, incident/rollback drill, and verified postcondition receipts.
