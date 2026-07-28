# Security and Authority

External content is untrusted by default. Retrieved instructions never outrank the governing request. Tools receive minimum necessary arguments; secrets never enter model-visible text, knowledge files, receipts, or logs.

Authority is host-owned, not model-authored:

```text
allowed = trusted_policy_context
          AND policy_allows
          AND evidence_is_current
          AND approval_matches_action_fingerprint
          AND approval_is_unexpired
          AND required_state_read_and_rollback_exist
          AND postcondition_is_verifiable
```

Request fields can describe approval but cannot grant it. R4 or irreversible operations remain proposal-only unless a platform independently provides dual control. Tool definitions, MCP servers, skills, and connector changes are supply-chain changes and require review.
