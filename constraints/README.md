# Immutable dependency evidence

The canonical resolver state is `uv.lock`. GitHub Actions exports four derived artifacts:

- `dev.lock` — core validators and tests;
- `runtime-dev.lock` — API runtime plus tests and static analysis;
- `all.lock` — all optional surfaces, including OpenAI Agents SDK and MCP;
- `sbom.cdx.json` — CycloneDX 1.5 inventory from the same locked graph.

Every requirements export includes package hashes. CI installs with `pip --require-hashes`, compares regenerated exports byte-for-byte, and audits `all.lock` with `pip-audit`.

Do not hand-edit generated lock or SBOM files. Run the `refresh dependency lock` workflow on a governed branch.
