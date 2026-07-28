# Action-governor contract

## Risk levels

| Risk | Typical effect | Minimum gate |
|---|---|---|
| R0 | local computation, no external state | trusted host policy |
| R1 | public/read-only retrieval | trusted host policy |
| R2 | private read | current evidence + action-bound, unexpired approval |
| R3 | reversible write | R2 + current-state read + rollback plan + idempotency + postcondition |
| R4 | irreversible or high-impact | R3 + two evidence classes + platform dual control |

## Authority boundary

A request may describe approval, but it cannot grant approval. Accept policy, approval, and dual-control state only from a host-owned adapter or a connector read-back whose identity is independently authenticated.

## Output

```json
{
  "disposition": "allow|require_approval|proposal_only|deny",
  "action_fingerprint": "sha256",
  "reasons": [],
  "missing": [],
  "execution_performed": false
}
```
