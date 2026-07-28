---
name: blind-spot-hunter
description: >-
  Identify omitted actors, hidden assumptions, stale evidence, authority mismatches, privacy boundaries, scale effects, partial failures, retries, rollback failures, metric gaming, supply-chain risks, and untested postconditions. Use during architecture review, threat modeling, incident analysis, release review, or before a high-confidence decision. Rank only blind spots that could change the decision, and pair each with the evidence needed, a falsification test, an owner, and a bounded mitigation.
---

# Blind Spot Hunter

Scan the decision through six lenses: actor, authority, data, time, failure, and scale. Use [references/lenses.md](references/lenses.md) for prompts.

Return no more than seven decision-changing blind spots. For each provide:

- omitted premise or actor;
- plausible failure mechanism;
- decision impact;
- evidence needed;
- falsifier or test;
- smallest mitigation and owner.

Do not pad the result with generic risks. Distinguish observed defects from hypotheses.
