# PARALLAX Ω — Proof-Carrying Agent Stack

Version: `1.0.0-rc.3`  
Built: `2026-07-28`  
Status: **locally tested release candidate; packaged after final ledger build; not deployed; not verified live**

PARALLAX Ω is a portable control plane for ChatGPT Workspace Agents, Custom GPTs, the OpenAI Agents SDK, MCP, and an optional advisory HTTP Action. It is not a persona-first agent. Its differentiator is **proof-carrying agency**: important claims, permissions, actions, memory writes, and readiness statements carry enough structured evidence to be challenged and verified.

## rc.2 changes

The second pass changes the security model, not just the wording:

- authority is now supplied only by a trusted host adapter; model/request fields cannot mint permission;
- approval binds to the complete action fingerprint and expires;
- factual evidence is checked for temporal validity;
- derived confidence cannot exceed the weakest verified dependency;
- memory consent binds to the exact candidate fingerprint and is one-time use;
- receipt verification recomputes the stored payload hash;
- raw archive tests, CI profiles, risk crosswalks, and staging gates are expanded;
- generated build noise is excluded from release archives.

## Package surfaces

- Workspace Agent and Custom GPT instructions;
- ten curated Knowledge files, keeping behavior in Instructions rather than reference files;
- seven reusable Skills with progressive references and deterministic helper scripts;
- pure-Python claim graph, action governor, memory protocol, policy adapter, and receipt chain;
- FastAPI advisory Action API and OpenAPI 3.1 schema;
- advisory-only MCP surface;
- OpenAI Agents SDK composition with host-supplied context;
- NIST AI RMF profile, OWASP agentic control matrix, threat model, ADRs, privacy contract, and deployment gates;
- deterministic tests, acceptance-bank validation, secret scan, package validator, release manifest, and archive QC.

## Fast start

Core checks from a clean unpack:

```bash
python scripts/run_tests.py --profile core --verbose
python scripts/run_evals.py
python scripts/validate_package.py --skip-ledger
python scripts/secret_scan.py
```

Runtime checks:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[runtime,dev]'
python scripts/run_tests.py --profile runtime --verbose
```

Optional OpenAI/MCP imports:

```bash
python -m pip install -e '.[runtime,openai]'
python scripts/run_tests.py --profile openai --verbose
python scripts/verify_optional_surfaces.py --require all
```

Local API:

```bash
export PARALLAX_API_KEY='replace-in-secret-store'
export PARALLAX_POLICY_MODE='deny_all'
# Optional exact allowlist for local-only analysis:
# export PARALLAX_POLICY_FILE=policy/local-analysis.example.json
uvicorn parallax_omega.api:app --host 127.0.0.1 --port 8000
```

No mutation endpoint is exposed. Never commit credentials. Configure them only in the target secret store.

## Readiness language

- `tested-locally`: named deterministic tests passed in a stated environment;
- `packaged`: a clean archive and external manifest were rebuilt and verified;
- `deployment-ready candidate`: runbooks and target files exist, with live gates still open;
- `verified-live`: the exact deployed version was invoked and its intended effect observed.

This package is **not verified live**. A live pass requires target upload, Preview or staging invocation, behavioral evals, connector/OAuth tests, and an effect receipt.
## rc.3 security status

The rc.3 branch closes the confirmed P0 paths A-01, A-02, A-06, A-08, A-09, and A-12 in the local package. File-backed policies are immutable SHA-256-pinned startup snapshots; explicit reloads require a host HMAC. HTTP, MCP, and Agents SDK preflight responses now include policy-bound receipts. Durable memory remains disabled by default; the supplied Supabase migration and drift SQL are activation gates, not proof of a live adapter.

