# Package Receipt

Package: `parallax-omega-agent-stack`  
Version: `1.0.0-rc.2`  
Date: 2026-07-28  
Status: `locally-verified / packaged after ledger build / not-deployed / not-invoked / not-verified-live`

## Decision

RC.2 is a security and assurance revision, not a wording refresh. It changes authorization ownership, temporal evidence, memory consent, receipt semantics, adapter namespaces, test-status semantics, and release reproducibility.

## Evidence

- 64 deterministic tests PASS from the source tree and a clean extraction.
- Runtime test profile PASS with zero skips.
- 72-case behavioral bank SCHEMA_PASS; behavioral execution NOT RUN.
- 7/7 Skills validated and packaged with official Skill tooling.
- Secret scan and package validator PASS.
- Offline build/install/import smoke PASS.
- Release-manifest regression tests PASS.
- Optional Agents SDK and MCP runtimes are DEPENDENCY_MISSING, not PASS.

## Boundary

This receipt proves local construction and verification only. It does not prove Builder upload, publication, model behavior, OAuth correctness, external effects, or durable memory. Exact archive bytes, SHA-256, file count, and external-manifest hash are recorded in the sibling release receipt generated after packaging.

## Next gate

Upload the exact archive to restricted staging, record instruction/knowledge/action/policy hashes, run the 72 behavioral cases, test injection and authorization boundaries, observe postconditions, and issue a separate verified-live receipt only if all target gates pass.
