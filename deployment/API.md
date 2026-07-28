# Advisory Actions API deployment

The rc.2 API exposes only:

- `GET /health`;
- `POST /v1/actions/preflight`;
- `POST /v1/memory/candidates`.

It exposes no external mutation or durable-memory endpoint.

## Required deployment controls

1. Deploy behind TLS and an identity-aware gateway.
2. Store `PARALLAX_API_KEY` only in the platform secret store.
3. Leave policy at deny-all unless an exact reviewed JSON policy is mounted through `PARALLAX_POLICY_FILE`.
4. Treat `policy/local-analysis.example.json` as a local demonstration, not a production policy.
5. Rate-limit by authenticated subject and network boundary.
6. Reject oversized bodies before application parsing.
7. Redact logs and propagate `x-request-id`.
8. Restrict network egress because the reference API needs none.
9. Pin the exact release archive, external manifest, policy hash, and container digest.
10. Verify health, authentication, malformed-policy fail-closed behavior, exact scope denials, and absence of mutation routes.

A future executor must be a separate adapter with its own ADR, identity model, action-bound approval, current-state read, idempotency, rollback, postcondition query, and live tests.
