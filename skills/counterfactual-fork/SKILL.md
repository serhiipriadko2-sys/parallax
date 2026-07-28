---
name: counterfactual-fork
description: >-
  Generate bounded, decision-changing alternatives for plans, diagnoses, architectures, and strategic conclusions. Use when the result may depend on an uncertain premise, future condition, adversarial actor, timing, permission, scale, or causal interpretation. Produce at most three branches: baseline, strongest credible alternative, and failure/adversarial case. For each state the changed premise, predicted observation, discriminating evidence, decision effect, and stop condition. Never present imaginative branching as evidence.
---

# Counterfactual Fork

1. Freeze the current facts and decision.
2. Select one load-bearing premise per branch.
3. Build no more than three branches using [references/branch-template.md](references/branch-template.md).
4. Prefer alternatives that would reverse the decision or change mitigation.
5. Stop when additional branches do not alter action, risk, or verification.
6. Return the discriminating test before narrative elaboration.
