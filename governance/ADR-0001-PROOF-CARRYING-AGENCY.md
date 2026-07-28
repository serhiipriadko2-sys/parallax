# ADR-0001: Proof-Carrying Agency

Status: accepted for PARALLAX Ω package; not accepted for Iskra canon or a live deployment  
Date: 2026-07-28  
Superseded in part by: ADR-0002 for authorization ownership

## Context

Persona-heavy agents can sound coherent while hiding stale sources, invalid dependencies, unauthorized actions, or unverified effects. Static prompts are useful behavioral guidance, but they cannot alone establish source freshness, authorization, idempotency, rollback, or an observed external postcondition.

## Decision

Build PARALLAX Ω around four separable planes:

1. observation with temporal evidence;
2. deliberation with a typed claim DAG and transitive invalidation;
3. host-owned execution policy with action-bound approval;
4. candidate-first memory with one-time consent and read-back.

The deterministic core remains provider-independent. ChatGPT Actions and MCP expose proposal/preflight surfaces only by default. Receipts provide tamper evidence and lineage, not actor authentication or proof that a claimed real-world effect occurred.

## Alternatives

1. **One large system prompt:** rejected because critical controls remain model-mediated.
2. **Many autonomous agents by default:** rejected because coordination increases injection and authority ambiguity.
3. **Immediate external memory:** rejected until consent, access policy, gateway, deletion, and read-back are verified on the target.
4. **A fully autonomous execution API:** rejected because model output must not become authorization.

## Consequences

Traceability and failure containment improve. Consequential work incurs additional latency and requires host integration. Routine analysis remains compact and read-only. No static artifact can establish future model behavior or connector correctness.

## Verification

- DAG acyclicity, freshness, confidence ceilings, conflict and invalidation propagation;
- host-owned exact policy allowlists and fail-closed loading;
- action-bound approval, rollback, idempotency, postcondition, source diversity, and dual control;
- consent binding, expiry, replay rejection, read-back verification;
- receipt payload and chain tamper detection;
- package, archive, skill, secret, and status-integrity gates;
- separate behavioral eval execution on every target surface.

## Rollback

Set policy to `deny_all`, remove external adapters, and operate the pure core in local read-only mode. The core requires no external state.

## Scope boundary

Integration into the Iskra repository, canon, Workspace Agent, Custom GPT, MCP deployment, OpenAI API project, or Supabase requires a separate governed change and target-specific live verification.
