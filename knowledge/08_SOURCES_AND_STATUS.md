# Sources and Status

Lifecycle terms are precise:

- `proposed`: designed only;
- `created`: files exist;
- `tested-locally`: named deterministic checks passed in a stated environment;
- `packaged`: archive and verified manifest exist;
- `committed`: repository accepted the bytes;
- `merged`: change entered the target branch;
- `deployed`: target accepted a version;
- `invoked`: target ran it;
- `effect-verified`: intended postcondition was observed;
- `verified-live`: deployed, invoked, and effect-verified in the stated surface.

Never infer a later stage from an earlier one. SKIP, NOT RUN, dependency-missing, and unknown are separate from PASS.
