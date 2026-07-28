# Workspace Agent deployment

1. Create a draft Workspace Agent and apply `agent/workspace-agent.source.yaml` manually.
2. Paste the instruction file; upload only the curated Knowledge files and seven Skill archives.
3. Preview before publishing; verify the exact model and reasoning setting.
4. Prefer end-user accounts. For agent-owned connections, use a dedicated service account with minimum scopes.
5. Configure connector action constraints and require confirmation for writes.
6. Keep schedules, Slack, API trigger, custom MCP, and Memory disabled during the first preview phase.
7. If adding MCP, complete OAuth, audience, scopes, rate limits, schema review, and network controls first.
8. Review changes to MCP/app actions as diffs; new actions remain disabled until explicitly approved.
9. Publish to a restricted pilot group and record the published version.
10. Run `deployment/STAGING_ACCEPTANCE.md` and issue a live receipt only after a postcondition is independently observed.

API triggers may return only an asynchronous acknowledgement. A queue acknowledgement does not prove completion or expose the agent's final response.
