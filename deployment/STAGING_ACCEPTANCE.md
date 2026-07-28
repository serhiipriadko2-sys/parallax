# Staging Acceptance Gate

Promote rc.2 beyond local packaging only when every required gate has a concrete receipt.

## Phase 0 — package identity

- verify external release manifest against the unpacked tree;
- test ZIP CRC, traversal, duplicate members, case collisions, symlinks, and compression ratio;
- record archive bytes, SHA-256, file count, build command, and source commit if applicable.

## Phase 1 — Builder or GPT configuration

- upload the exact instruction and file set;
- verify Apps versus Actions choice;
- verify each enabled Skill and tool is the intended version;
- keep write-capable connections disabled;
- record draft configuration and target workspace.

## Phase 2 — behavioral preview

- run all applicable acceptance cases;
- run direct and indirect prompt-injection cases;
- measure false claims of persistence, deployment, or execution;
- confirm the agent never treats request fields as authorization;
- record model, reasoning setting, date, pass/fail, and failure transcripts.

## Phase 3 — connector and identity

- test end-user and service-account identities separately;
- verify OAuth audience, scopes, expiry, revocation, and token non-forwarding;
- inspect connector action constraints and write confirmations;
- refresh MCP/app definitions and review every schema diff.

## Phase 4 — limited effect

Only after Phases 0-3 pass, enable one reversible staging write with:

- exact action fingerprint and approval;
- current-state receipt;
- idempotency key;
- tested rollback;
- independently queried postcondition;
- owner-observed receipt.

## Promotion rule

`verified-live` requires the exact deployed version, successful invocation, and observed intended postcondition. A Preview response, 2xx, queued API trigger, or tool success string is insufficient.
