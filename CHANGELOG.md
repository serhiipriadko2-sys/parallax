# Changelog

## 1.0.0-rc.2 — 2026-07-28

### Security boundary

- Moved authorization to a host-owned control plane; API, MCP, and model input cannot set policy or dual-control fields.
- Added exact tool/operation/scope allowlists with default deny and fail-closed policy-file loading.
- Bound approvals to action fingerprints and memory consent to exact candidate fingerprints with expiry and one-time use.
- Enforced temporal evidence, confidence ceilings, independent source classes, current-state reads, rollback plans, and postconditions.

### Assurance and release

- Added an assurance case, NIST AI RMF profile, OWASP control matrix, incident and rollback runbooks.
- Split executable test results from behavioral eval-bank validation; skipped/dependency-missing work no longer counts as PASS.
- Expanded the behavioral bank from 50 to 72 schema-validated cases, including host-authority, freshness, replay, case-collision, and guardrail-coverage failures.
- Added deterministic manifests, archive safety gates, clean-extraction test entrypoints, and reproducible ZIP creation.

### Compatibility

- Updated Workspace Agent, Custom GPT, Actions, MCP, and Agents SDK adapters to remain advisory by default.
- Kept memory and external writes disabled until target-specific authorization and verified-live read-back exist.

## 1.0.0-rc.1 — 2026-07-28

- Introduced proof-carrying agency architecture.
- Added typed claim DAG and transitive invalidation.
- Added risk-based authority gate and receipt chain.
- Added consent-gated, fail-closed memory protocol.
- Added Workspace Agent, Custom GPT, Actions, MCP, and Agents SDK surfaces.
- Added seven reusable skills and deterministic test suite.
