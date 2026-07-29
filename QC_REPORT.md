# QC Report — PARALLAX Ω 1.0.0-rc.3

Date: 2026-07-28  
Verdict: **PASS for local release-candidate packaging; behavioral and live gates remain open**

Lifecycle discipline for every statement below:
`accepted != implemented != committed != merged != deployed != invoked != verified-live`.

## Executed gates

All results in this table were measured on this tree. Counts include the A-10 remediation
landed after rc.3 was packaged; each profile was measured in an environment matching its CI job
rather than in a single developer environment.

| Gate | Result | Evidence |
|---|---|---|
| Core profile | PASS | 107 tests; 0 failures, 0 errors. 6 skips: the API surface tests require the runtime extra, which the core profile deliberately does not install |
| Runtime profile | PASS | 107 tests with FastAPI/Pydantic/HTTPX present; 0 failures, 0 errors, 0 skips |
| Clean extraction | PASS | `unittest discover -s tests` succeeds without prior install |
| Offline install/import smoke | PASS | PEP 517 wheel built with `--no-build-isolation`; `parallax_omega` imported as `1.0.0rc3` |
| Behavioral bank schema | SCHEMA_PASS | 74 cases, 16 categories, 21 control references |
| Behavioral model execution | NOT RUN | no target model or surface was invoked |
| Secret-shaped value scan | PASS | no OpenAI-key, JWT, private-key, or AWS-key patterns |
| Package structure | PASS | 158 repository files; 156 ledger entries (`SHA256SUMS` and `MANIFEST.json` exclude themselves); 10 knowledge files, 7 Skills, policy schemas, adapters, runbooks, assurance case |
| Dependency lock resolution | PASS | `uv==0.10.0` (the version `[tool.uv] required-version` pins); 82 packages; `uv lock --check` clean |
| Hashed install | PASS | `pip install --require-hashes -r constraints/dev.lock` succeeds in a clean virtualenv; 1158 hashes across `all.lock` |
| Lock export reproducibility | PASS | re-export to a different path is byte-identical under `cmp`; 3.11 and 3.12 exports agree |
| Dependency vulnerability audit | PASS | `pip-audit -r constraints/all.lock --strict` reports no known vulnerabilities |
| SBOM drift comparison | PASS | CycloneDX 1.5 inventory of 81 components compared with volatile fields normalized |
| Bidirectional ledger equality | PASS | repository file set == `SHA256SUMS` == `MANIFEST.json`; unlisted-file and missing-entry injections both fail validation |
| Release ZIP | PASS | deterministic rebuild; CRC, traversal, duplicate, symlink, and case-fold checks clean |
| MCP tool integrity manifest | PASS | `scripts/tool_manifest.py verify` |
| Skill integrity manifest | PASS | `scripts/skill_manifest.py verify` |
| Skill validation | PASS | 7/7 official `quick_validate.py` |
| Skill packaging | PASS | 7/7 official `package_skill.py`; each output is `skill.zip` |
| Skill helper smoke | PASS | risk gate, archive QC, and claim DAG scripts executed with representative inputs |
| Policy boundary | PASS | host-owned risk floor, segment-aware scope grammar, malformed-policy deny-all, model authority fields rejected |
| Archive/manifest logic | PASS | directory round-trip, tamper detection, case-fold collision, and VCS-metadata exclusion regression tests |
| Static Python parse/compile | PASS | all Python sources parse; compile pass performed |
| Ruff lint | PASS | `ruff check runtime tests scripts agents_sdk adapters` clean under ruff 0.16.0 |
| Mypy strict | PASS | `mypy runtime/parallax_omega` clean across 12 source files |
| Agents SDK import/runtime | DEPENDENCY_MISSING | `agents` package unavailable locally |
| MCP import/runtime/OAuth | DEPENDENCY_MISSING | third-party `mcp` package unavailable locally; namespace collision was removed |

## Security repairs introduced in rc.3

rc.3 responds to the adversarial audit recorded in `threat-model/ADVERSARIAL_AUDIT_02.md`.
Each repair below was exercised against the audit's original reproduction:

1. **A-01 host-owned risk floor.** `PolicyRule` carries `risk_floor` and `irreversible`;
   the governor evaluates `higher_risk(request.risk, rule.risk_floor)`. A caller may raise
   strictness and can no longer lower it. A request declaring `R1` on an operation the host
   classifies `R4` is evaluated at `R4` and returns `proposal_only`.
2. **A-02 normalized scope grammar.** `Scope.parse` enforces a namespace/segment grammar and
   rejects traversal, percent encoding, backslashes, doubled separators, empty segments, and
   control characters. Containment is segment-aware, so `repo:acme/public` no longer covers
   `repo:acme/public-secrets`.
3. **A-06 policy provenance.** Policy is loaded once into an immutable startup snapshot with a
   SHA-256 pin, a signed reload path, and a policy-bound receipt.
4. **A-08 receipts on shipped surfaces.** The API, MCP, and Agents SDK preflight routes pass
   through `ParallaxKernel` and return a receipt with its chain hash.
5. **A-09 memory consent durability.** Durable unique consent registry, idempotent write, and
   quarantine on read-back mismatch, replacing the process-local set.
6. **A-12 bidirectional ledger.** Release validation asserts set equality in both directions
   for the repository tree and the release ZIP. A file added to disk but absent from the
   ledger fails; a ledger entry without a file fails.
7. **Retrieval boundary.** Retrieved content is typed as untrusted data and cannot mint
   authority; covered by dedicated boundary tests.
8. **Bounded state and rate limiting.** Per-session bounded state with a transport rate-limit
   backstop.
9. **Integrity manifests.** MCP tool and Skill manifests are verified as supply-chain inputs.
10. **Supabase gate artifacts.** Client deny policies, consent uniqueness, a reviewed
    `SECURITY DEFINER` allowlist, and a drift test are carried in-repository.

### Defects found and fixed during this packaging step

**1. Release file set included version-control metadata.** `scripts/release_policy.py` did not
exclude `.git/`. Because the builder and the validator share that function, running either from
a repository root — which the release procedure requires — pulled git internals into the
comparison and failed validation with `unlisted_file:.git/...`. The bare source snapshot used
for the preceding local verification contained no `.git` directory, so the condition could not
appear there. `VCS_PARTS` now excludes `.git`, `.hg`, and `.svn` on both sides, with a
regression test in `tests/test_release_manifest.py`.

**2. Dependency lock evidence was specified but never generated.** The rc.3 CI installs with
`pip --require-hashes` from `constraints/dev.lock`, `runtime-dev.lock`, and `all.lock`, and
`security-release.yml` attests `constraints/sbom.cdx.json`. None of those files existed, and
neither did the canonical `uv.lock`, so every CI job failed at its first install step. All five
artifacts are now generated with `uv==0.10.0` — the version `[tool.uv] required-version` pins
and the version both workflows install — and committed. Resolution covers 82 packages with
1158 hashes; a `--require-hashes` install was verified in a clean virtualenv.

**3. The lock verification step could never pass.** `uv export` writes a provenance header
recording its own command line, including `--output-file`. CI exported to `/tmp/…` and compared
against `constraints/…` with `cmp`, so line 2 differed for any possible committed content.
Independently, the CycloneDX export stamps a fresh random `serialNumber` and a generation
`timestamp` on every run, so a byte comparison of two exports of the same locked graph could
never succeed. Both workflows now export the requirements files with `--no-header`, which makes
`cmp` path-independent and meaningful, and the SBOM is compared by `scripts/compare_sbom.py`,
which normalizes only those two volatile fields and then requires strict equality — so genuine
component drift is still rejected. Covered by three tests in `tests/test_integrity_manifests.py`.

**4. Lint and type checking had never actually run.** `ruff` and `mypy` were previously recorded
as NOT RUN because the executables were unavailable locally, and CI never reached those steps —
it exited at the install step for the reason above. Once CI got that far, `ruff` reported 67
findings and `mypy --strict` reported 6. Both counts are identical on the untouched handoff
snapshot, so none of them were introduced here. Additionally, the `runtime` CI job ran its
release hygiene check *after* `pip install -e`, so the editable install's
`runtime/*.egg-info` was flagged as generated noise; that job now removes build metadata first,
exactly as the release procedure already does for `__pycache__`.

The findings are resolved as follows. 30 were auto-fixable and are applied; they are mechanical
and behaviour-preserving (`timezone.utc` to `UTC`, quoted annotations to real ones under
`from __future__ import annotations`, `.encode("utf-8")` to the identical default `.encode()`,
`typing.Callable` to `collections.abc.Callable`). The 31 `E402` findings come from the
deliberate `sys.path` bootstrap idiom in tests and two scripts and are declared as
`per-file-ignores` rather than restructured. The remaining nine — `E701`/`E702` formatting in
`secret_scan.py`, two `SIM102` nested conditionals, one `SIM103`, and one `B030` — are fixed
directly; the `B030` case was a conditional expression inside an `except` tuple, now hoisted
into a plain exception tuple built once at import. The 6 `mypy` findings were missing `dict`
type parameters in `kernel.py` and `receipts.py` and are annotation-only.

`UP042` is deliberately **not** applied and is instead ignored with a recorded reason. It would
migrate the `(str, Enum)` classes in `models.py` and `policy.py` to `StrEnum`, which changes
`str(RiskLevel.R0)` from `RiskLevel.R0` to `R0`. Those members are serialized into action
fingerprints, receipt payloads, and the receipt chain hash, so the migration is a deliberate,
separately tested change rather than a lint cleanup. The enums are unchanged in this branch and
`str(RiskLevel.R0)` still evaluates to `RiskLevel.R0`.

**5. The locked dependency set carried a known vulnerability.** With the lock generated,
`pip-audit --strict` reported `PYSEC-2026-1845` against `pytest 8.4.2`, fixed in `9.0.3`. The
`dev` extra pinned `pytest>=8,<9`, so the resolver could not reach the fix. The ceiling is
raised to `pytest>=9.0.3,<10` and the lock regenerated; `pytest` is a development extra that no
CI job or test runner invokes, so the change carries no runtime behaviour. `pip-audit --strict`
is now clean.

## Audit findings not addressed in rc.3

These remain open and are **not** claimed as repaired. They are recorded so the residual risk
stays visible:

- **A-07** receipt chains remain tail-truncatable; removing trailing receipts still verifies.
  Sequence numbers, length checkpoints, keyed hashing, and persistence are outstanding.
- **A-03, A-04, A-05, A-11, A-13 through A-20** are unchanged from the audit's P1–P3 plan
  except where a repair above happens to cover them.

**A-10 is now closed** — see the section below. It was open in rc.3 as packaged and was
remediated afterwards.

## A-10 remediation: memory sensitivity classification

`runtime/parallax_omega/sensitivity.py` replaces the single bypassable comparison with two
independent gates, because the finding had two independent causes.

*Label normalization.* The prohibited-label check was `sensitivity.lower() in PROHIBITED`,
which the audit defeated with `" secret"`, `"SECRET "`, a trailing zero-width space, and the
Cyrillic homoglyph `"ѕecret"`. Labels are now NFKC-normalized, stripped of Unicode `Cc`/`Cf`
characters — U+200B survives both NFKC and `str.strip`, so removing it needs to be explicit —
then stripped and case-folded. A label that is still non-ASCII after that is a confusable
spelling and is refused outright rather than compared, since NFKC does not fold Cyrillic to
Latin. An empty-after-normalization label is refused rather than treated as benign.

*Content detection.* Normalization alone cannot help, because the label is caller-declared: a
model under injection simply declares `"normal"`. `detect_credentials` therefore inspects the
payload regardless of the declared label, using the same credential shapes
`scripts/secret_scan.py` applies to release artifacts, so a value refused at the memory
boundary is also refused at packaging. This also reaches the MCP surface, which hardcodes
`sensitivity="normal"` and could not otherwise trigger the label check at all — a partial
mitigation of A-11, not a full one.

Detection is deliberately limited to credential shapes, which are precise and low
false-positive. It is **not** a general personal-data classifier; the `medical`, `intimate`,
and `private-third-party` labels still depend on an honest caller, and content-based detection
of those categories remains a deployment responsibility.

Covered by 13 tests in `tests/test_sensitivity.py`, including every spelling the audit used.
The credential fixtures are assembled at import time rather than written as literals, so
`secret_scan.py` stays strict instead of gaining an exemption for `tests/`.

## Live-system evidence and non-mutations

GitHub and Supabase were inspected read-only during the preceding architecture audit and the
adversarial audit; no repository, database, function, policy, or deployment mutation was
performed in either.

Supabase migrations were previously applied and read back **outside** this Git task. This
packaging step performs **no** Supabase mutation. The migration and test files under
`supabase/` are repository artifacts and are the traceable source representation of that work,
not evidence of live state. Any live claim requires a fresh read-back at the time of the claim.

## Open gates

- Workspace Agent or Custom GPT upload, Preview, publish, and invocation;
- target authentication, OAuth/MCP handshake, connector review, and tool-schema change control;
- behavioral execution of the 74-case bank on a pinned target configuration;
- external mutation adapter and independent postcondition observation;
- Supabase memory ACL/RLS/gateway/deletion/read-back verification against live state;
- production dependency lock, SBOM, vulnerability scan, load test, and incident drill;
- the audit findings listed as not addressed above.

## Decision

Release as `locally-verified / packaged / not-deployed / not-invoked / not-verified-live`.
External writes and durable memory remain unexposed by default.
