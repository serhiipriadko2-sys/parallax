# OWASP Agentic Control Matrix

This matrix adapts OWASP LLM and agentic risks to PARALLAX Ω. It is a design crosswalk, not proof that all risks are eliminated.

| Risk | rc.2 control | Deterministic evidence | Live gate still required |
|---|---|---|---|
| Prompt / goal injection | instruction-data separation; external content is evidence only | instruction and package contracts | indirect injection red-team on each enabled connector |
| Sensitive information disclosure | candidate-only memory; redacted receipts; no secrets in artifacts | secret scan; privacy tests | trace/log inspection and data-loss tests |
| Supply-chain compromise | Skill/MCP/tool changes treated as reviewed artifacts | hashes, skill packaging, archive QC | dependency provenance, deployment diff, patch SLA |
| Data or memory poisoning | temporal evidence; dependency invalidation; candidate-bound consent | claim and memory tests | retrieval corpus and live memory red-team |
| Improper output handling | model output never directly grants authority; typed host adapter | schema and authority tests | downstream escaping and application-specific validation |
| Excessive agency / tool misuse | no mutation endpoint; deny-all host policy; R0-R4 governor | policy, API, MCP, and Agents SDK contracts | executor penetration test and false-allow measurement |
| Identity and privilege abuse | end-user identity preferred; service account only with narrow scopes | deployment contract | OAuth audience/scope tests and account review |
| System prompt leakage | no secrets in instructions; behavior is not treated as secret security boundary | secret scan | prompt extraction tests and impact review |
| Vector / retrieval weakness | evidence freshness, source identity, conflicts, and falsifiers | claim graph tests | retrieval poisoning and access-control evaluation |
| Misinformation / overreliance | confidence ceilings, alternatives, status precision, postcondition checks | claim and eval-contract tests | live factuality and calibration evals |
| Unbounded consumption | bounded branches; no autonomous loops in core | instruction contract | per-user quotas, max turns, concurrency, budget alarms |
| Memory/context poisoning | one-time candidate-bound consent and read-back | memory tests | backend ACL, deletion, and persistence isolation |
| Cascading failure | no default multi-agent committee; fail-closed adapters | degradation tests | chaos and dependency outage drills |
| Human-agent trust exploitation | explicit lifecycle and non-claims; advisory responses mark no execution | package and output contracts | user study for approval comprehension |

## Residual risk

A model can omit a relevant premise, misclassify risk, or phrase an unsafe recommendation persuasively. Deterministic controls reduce the blast radius but do not replace independent review for high-impact domains.
