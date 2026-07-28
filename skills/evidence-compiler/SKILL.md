---
name: evidence-compiler
description: >-
  Convert multi-source research, audits, fact checks, and consequential analyses into a typed dependency graph whose conclusions can be retracted when premises fail or expire. Use when a result depends on several claims, sources conflict, freshness matters, or confidence must be bounded by evidence. Record source identity, observation time, validity window, content hash, dependencies, confidence ceiling, and falsifier. Return a concise evidence map, not hidden chain-of-thought.
---

# Evidence Compiler

1. Extract only claims that can change the decision.
2. Label each claim `FACT`, `INTERP`, `HYP`, `UNKNOWN`, or `CONFLICT`.
3. Attach source identity, observation time, validity window, and content hash when available.
4. Record dependency IDs and a falsifier for each derived claim.
5. Reject cycles and confidence above the weakest verified dependency.
6. Recheck temporal validity before action; invalidate descendants of false, conflicted, or expired premises.
7. Return claim IDs, evidence, dependencies, status, confidence ceiling, and evidence needed.

Use `scripts/claim_dag.py` for deterministic graph validation. See [references/schema.md](references/schema.md).
