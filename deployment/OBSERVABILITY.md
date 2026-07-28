# Observability and Incident Boundaries

## Minimum telemetry

Record version, request ID, policy mode, action fingerprint, risk class, disposition, missing gates, tool name, latency, error class, postcondition status, and receipt hash. Do not log raw credentials, full private payloads, or memory content.

## Tracing

OpenAI Agents SDK tracing is useful for model turns, tools, guardrails, and handoffs. Keep sensitive model/tool data excluded unless a short-lived, approved debugging session requires it. Trace availability is not a prerequisite for the deterministic core, but production actions require a durable redacted audit path.

## Alerts

Alert on repeated denied high-risk proposals, approval mismatch, consent replay, unexpected policy-mode change, connector schema change, missing postcondition, receipt-chain failure, rate-limit exhaustion, and any attempt to invoke a non-existent mutation endpoint.

## Kill switches

Provide independent switches for model invocation, each connector, write adapters, schedules, API triggers, and memory. A kill switch must be testable without relying on the model.

## Incident receipt

Capture detection time, affected version, identity, scope, observed effect, containment, credential rotation, rollback, evidence preservation, user impact, remediation, and verification. Do not overwrite the original failed receipt.
