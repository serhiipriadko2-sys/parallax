# MCP surface

The rc.2 MCP adapter lives at `adapters/mcp_server.py` so it cannot shadow the third-party `mcp` package. It exposes three advisory tools:

- `server_status`;
- `evaluate_action`;
- `propose_memory`.

It does not execute writes or persist memory. Model arguments cannot set policy. The host reads `PARALLAX_MCP_POLICY_FILE` or falls back to `PARALLAX_MCP_POLICY_MODE=deny_all`. A policy file must use exact tool, operation, risk, and scope rules; wildcards are unsupported.

## Deployment requirements

- OAuth with protected-resource metadata and audience-restricted tokens;
- no token passthrough to downstream services;
- exact scopes, short expiry, revocation, rate limits, and network allowlists;
- secure discovery and explicit server identity;
- review and hash tool definitions; treat schema changes as supply-chain changes;
- disable new or changed tools until a human reviews the diff;
- sandbox the server and restrict filesystem/network access;
- redact logs and preserve request IDs;
- test prompt injection, tool poisoning, identity confusion, replay, and resource exhaustion.

Run after installing optional dependencies:

```bash
python -m pip install -e '.[openai]'
export PARALLAX_MCP_POLICY_MODE=deny_all
# Or: export PARALLAX_MCP_POLICY_FILE=policy/local-analysis.example.json
python adapters/mcp_server.py
```
