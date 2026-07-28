# Dependency policy

The library keeps bounded compatibility ranges in `pyproject.toml`; `constraints/runtime-tested.txt` records the exact local runtime versions used for rc.2 verification. These are different artifacts:

- ranges express supported intent;
- tested constraints identify one observed environment;
- a production deployment must generate its own resolved lock and SBOM for its OS, Python, and target surface.

Before production promotion: resolve dependencies from an approved index, verify hashes where supported, scan direct and transitive dependencies, retain licenses, test upgrades in staging, and review MCP/Agents SDK schema changes as supply-chain changes. Optional OpenAI/MCP dependencies were not installed in the local rc.2 environment and therefore have no local runtime PASS.
