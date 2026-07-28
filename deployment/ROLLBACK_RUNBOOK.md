# Rollback runbook

1. Set `PARALLAX_POLICY_MODE=deny_all` and remove `PARALLAX_POLICY_FILE`.
2. Disable or unpublish Action/MCP write surfaces; retain health and read-only diagnostics only.
3. Revoke or rotate target credentials if policy, connector, or trace exposure is suspected.
4. Freeze memory commits; preserve audit evidence without copying secrets.
5. Pin the last known-good instruction, knowledge, action schema, policy, and package hashes.
6. Run core tests and manifest verification from a clean extraction.
7. Restore one adapter at a time in staging and verify exact postconditions.

Rollback is complete only when the deployed surface, not merely the repository, is observed in deny-all/read-only state.
