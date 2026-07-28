# ADR-0002: Host-bound authority and exact policy

Status: accepted for PARALLAX Ω `1.0.0-rc.2`  
Date: 2026-07-28

## Context

The rc.1 advisory API and MCP tool accepted `policy_allows` as a normal request argument. Although those surfaces exposed no mutation endpoint, a model or client could manufacture an `ALLOW` result. A second audit also found that a broad `read_only` mode was insufficiently specific and that the local MCP module name collided with the third-party package namespace.

## Decision

1. Remove model-controlled authorization fields from HTTP, MCP, and Agents SDK tool arguments.
2. Obtain policy only from a host-owned adapter whose source is marked trusted.
3. Default to deny and use exact tool, operation, maximum risk, and scope-prefix rules; support no wildcards.
4. Bind user approval to the complete action fingerprint, exact scope, and expiry.
5. Require current-state observation, rollback plan, idempotency, and postcondition for R3/R4.
6. Require two source classes and platform dual control for R4; otherwise return proposal-only.
7. Keep all rc.2 public tools advisory-only and report `execution_performed=false`.
8. Keep third-party package namespaces free of local adapter modules.

## Alternatives

- Prompt-only rules: rejected because model output could self-authorize.
- Shared API key as action approval: rejected because service authentication does not prove user intent or exact scope.
- Broad risk-only policy mode: rejected because tool and data scope remain ambiguous.
- Write endpoint in rc.2: rejected until a platform-specific executor, identity model, rollback, rate limits, and live postcondition tests exist.

## Consequences

The default API denies all proposals. The bundled local-analysis policy permits only exact, local R0 parsing scopes. Operators must author a separate policy file for any other capability. This is less convenient but prevents false-positive authorization signals.

## Tests

Unknown or malformed policy fails closed; request schemas reject authority fields; exact operation and scope mismatch deny; MCP/Agents SDK signatures contain no authority argument; approval mismatch/expiry blocks R2+; R3 requires current state, rollback, idempotency, and postcondition; R4 requires source diversity and dual control; optional adapters have import smoke gates.

## Rollback

Set deny-all and remove adapter credentials. Do not restore model-controlled authority or broad implicit allowlists.
