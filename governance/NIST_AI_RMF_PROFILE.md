# PARALLAX Ω AI RMF Profile

This project-specific profile adapts the NIST AI RMF functions to a custom agent control plane. It is not a certification.

## Current and target profile

| Function | rc.2 current state | Target before production write adapters |
|---|---|---|
| Govern | constitution, ADRs, status vocabulary, owner gates, release ledger | named operational owners, incident process, periodic access review, approved risk appetite |
| Map | source, actor, authority, data, lifecycle, and trust-boundary maps | target-specific data inventory, affected-user analysis, connector and subprocess map |
| Measure | deterministic tests, threat matrix, secret scan, archive QC, acceptance bank | live behavioral evals, red-team prompts, latency/cost/error baselines, rollback drills, false-allow rate |
| Manage | deny-all default, read-only mode, disabled memory, no mutation endpoint, staged deployment runbook | monitored executor, kill switch, rate limits, dual control, verified deletion, production incident exercises |

## Risk tolerances

- False authorization is less acceptable than unnecessary blocking.
- Unknown live state is reported as `UNKNOWN`, never inferred from documentation.
- Sensitive memory is out of scope for the default profile.
- Irreversible actions remain proposal-only without independent platform dual control.
- Model performance cannot compensate for missing identity, scope, or postcondition controls.

## Measurement claims

Deterministic tests can establish local invariants. They cannot establish model completeness, live connector safety, operational resilience, or societal impact. Those require target-specific TEVV, monitored pilots, and periodic reassessment.

## Review triggers

Rebuild this profile when the model, instructions, tool schemas, Skills, MCP server, host policy, identity provider, data stores, deployment audience, or external regulations materially change.
