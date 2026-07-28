# OpenAI Agents SDK adapter

`agents_sdk/agent.py` registers one advisory `action_preflight` function tool. The `ParallaxRunContext` is created by the host and contains a `HostPolicyAdapter`; policy is not a function-tool argument and cannot be minted by the model.

Example host setup after installing optional dependencies:

```python
from pathlib import Path
from agents import Runner
from agents_sdk.agent import ParallaxRunContext, agent
from parallax_omega.policy import HostPolicyAdapter

context = ParallaxRunContext(
    policy=HostPolicyAdapter.from_file(Path("policy/local-analysis.example.json"))
)
result = Runner.run_sync(agent, "Preflight a local parse operation", context=context)
```

The reference agent has no write tool. Add a future executor only behind separate input/output guardrails, exact identity and scope, current-state read, idempotency, rollback, postcondition verification, and target-specific tests. Hosted tools and handoffs require their own coverage; do not assume function-tool guardrails automatically govern every surface.
