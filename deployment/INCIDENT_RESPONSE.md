# Incident response

## Trigger classes

- unauthorized or over-scoped action;
- secret, private-data, or trace exposure;
- memory write without valid consent/read-back;
- package or policy hash drift;
- prompt/tool injection that changes behavior;
- claimed effect that cannot be independently observed.

## Response

1. Contain: deny all policy, disable affected tools, revoke credentials, stop memory commits.
2. Preserve: request ID, action fingerprint, policy hash, receipt chain, adapter version, timestamps, and redacted trace.
3. Classify actual state: attempted, accepted, executed, observed, verified, or unknown.
4. Eradicate the boundary failure; do not patch only the prompt.
5. Recover in restricted staging with adversarial regression cases.
6. Record an incident receipt and update the threat model, tests, and policy.

Never place raw credentials or unnecessary personal data in the incident record.
