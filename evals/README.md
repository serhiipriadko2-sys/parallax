# Evaluation bank

`cases.jsonl` contains **behavioral/manual** acceptance cases. Validation of its schema and coverage is not a model-behavior pass.

## Status vocabulary

- `schema-pass`: every record is structurally valid and required controls/categories are covered.
- `behavioral-not-run`: the cases have not been executed against a target model/surface.
- `behavioral-pass`: a pinned target configuration was run, scored, and retained with traces.
- `live-effect-pass`: consequential effects were independently observed; never inferred from a model answer.

## Required run record

A target-specific run must record model/version, surface, instruction hash, knowledge manifest hash, tool/action versions, policy hash, temperature or equivalent settings, timestamps, case-level outcomes, reviewer identity, and trace location. Do not merge skipped or dependency-missing cases into the pass rate.
