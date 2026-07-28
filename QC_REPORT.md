# QC Report — PARALLAX Ω 1.0.0-rc.2

Date: 2026-07-28  
Verdict: **PASS for local release-candidate packaging; behavioral and live gates remain open**

## Executed gates

| Gate | Result | Evidence |
|---|---|---|
| Clean-tree unit/contract suite | PASS | 64 tests; zero failures, errors, or skips |
| Runtime profile | PASS | same 64 tests with FastAPI/Pydantic/HTTPX present |
| Clean extraction | PASS | raw `python -m unittest discover -s tests -v` succeeds without prior install |
| Offline install/import smoke | PASS | PEP 517 wheel built with `--no-build-isolation`; `parallax_omega` imported as `1.0.0rc2` |
| Behavioral bank schema | SCHEMA_PASS | 72 cases, 16 categories, 20 control references |
| Behavioral model execution | NOT RUN | no target model/surface was invoked |
| Secret-shaped value scan | PASS | no OpenAI-key, JWT, private-key, or AWS-key patterns |
| Package structure | PASS | 10 knowledge files, 7 Skills, policy schemas, adapters, runbooks, assurance case |
| Skill validation | PASS | 7/7 official `quick_validate.py` |
| Skill packaging | PASS | 7/7 official `package_skill.py`; each output is `skill.zip` |
| Skill helper smoke | PASS | risk gate, archive QC, and claim DAG scripts executed with representative inputs |
| Policy boundary | PASS | host-owned exact allowlist, malformed-policy deny-all, model authority fields rejected |
| Archive/manifest logic | PASS | directory round-trip, tamper detection, and case-fold collision regression tests |
| Static Python parse/compile | PASS | all Python sources parse; compile pass performed |
| Ruff/mypy local run | NOT RUN | executables unavailable locally; CI installs dev extras and runs both |
| Agents SDK import/runtime | DEPENDENCY_MISSING | `agents` package unavailable locally |
| MCP import/runtime/OAuth | DEPENDENCY_MISSING | third-party `mcp` package unavailable locally; namespace collision was removed |

## Security repairs introduced in rc.2

1. Removed model/client-controlled policy and dual-control fields.
2. Added exact host policy rules with no wildcards and default deny.
3. Bound approval to action fingerprint and expiry.
4. Enforced evidence freshness, dependency confidence ceilings, and source diversity.
5. Bound memory consent to the exact candidate, issuer, expiry, and one-time use.
6. Made receipt payload hashes independently recomputable and documented their non-repudiation limit.
7. Moved the MCP adapter out of the `mcp` namespace to avoid shadowing the external SDK.
8. Separated executable PASS from behavioral `NOT_RUN` and dependency-missing results.
9. Added deterministic release manifests, case-collision rejection, rollback and incident runbooks.

## Live-system evidence and non-mutations

GitHub and Supabase were inspected read-only in the preceding architecture audit; no repository, database, function, policy, or deployment mutation was performed. Mintlify deployment `iskraspace` was discovered and an isolated editor branch was opened, but editor metadata was unavailable; the empty session was discarded and no documentation changes were saved.

## Open gates

- Workspace Agent or Custom GPT upload, Preview, publish, and invocation;
- target authentication, OAuth/MCP handshake, connector review, and tool-schema change control;
- behavioral execution of the 72-case bank on a pinned target configuration;
- external mutation adapter and independent postcondition observation;
- Supabase memory ACL/RLS/gateway/deletion/read-back remediation;
- production dependency lock, SBOM, vulnerability scan, load test, and incident drill.

## Decision

Release as `locally-verified / packaged / not-deployed / not-invoked / not-verified-live`. External writes and durable memory remain unexposed by default.
