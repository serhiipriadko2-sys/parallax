from __future__ import annotations

import json
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .models import ActionRequest, AuthorizationContext, RiskLevel


class PolicyMode(str, Enum):
    DENY_ALL = "deny_all"
    READ_ONLY = "read_only"
    ALLOWLIST = "allowlist"


_RISK_ORDER = {
    RiskLevel.R0: 0,
    RiskLevel.R1: 1,
    RiskLevel.R2: 2,
    RiskLevel.R3: 3,
    RiskLevel.R4: 4,
}


@dataclass(frozen=True)
class PolicyRule:
    """Exact host-owned allowlist entry; wildcards are intentionally unsupported."""

    tool: str
    operation: str
    max_risk: RiskLevel
    scope_prefixes: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.tool.strip() or not self.operation.strip():
            raise ValueError("policy rule tool and operation are required")
        if not self.scope_prefixes or any(not prefix.strip() for prefix in self.scope_prefixes):
            raise ValueError("policy rule requires non-empty scope_prefixes")

    def matches(self, request: ActionRequest) -> bool:
        return (
            request.tool == self.tool
            and request.operation == self.operation
            and _RISK_ORDER[request.risk] <= _RISK_ORDER[self.max_risk]
            and any(request.scope.startswith(prefix) for prefix in self.scope_prefixes)
        )


@dataclass(frozen=True)
class HostPolicyAdapter:
    """Server-owned policy adapter. Model/user input cannot set authorization fields."""

    mode: PolicyMode = PolicyMode.DENY_ALL
    source: str = "host-policy"
    rules: tuple[PolicyRule, ...] = ()

    @classmethod
    def from_env(
        cls,
        mode_variable: str = "PARALLAX_POLICY_MODE",
        file_variable: str = "PARALLAX_POLICY_FILE",
    ) -> "HostPolicyAdapter":
        policy_file = os.getenv(file_variable)
        if policy_file:
            try:
                return cls.from_file(Path(policy_file))
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                return cls(mode=PolicyMode.DENY_ALL, source="invalid-policy-file")

        raw = os.getenv(mode_variable, PolicyMode.DENY_ALL.value)
        try:
            mode = PolicyMode(raw)
        except ValueError:
            return cls(mode=PolicyMode.DENY_ALL, source="invalid-policy-mode")

        if mode is PolicyMode.READ_ONLY:
            # Narrow built-in profile for local parsing only. Real deployments should use a file.
            return cls(
                mode=mode,
                source="builtin:read_only",
                rules=(PolicyRule("local", "parse", RiskLevel.R0, ("input",)),),
            )
        return cls(mode=mode, source="builtin:deny_all")

    @classmethod
    def from_file(cls, path: Path) -> "HostPolicyAdapter":
        raw = json.loads(path.read_text(encoding="utf-8"))
        if raw.get("schema_version") != "1.0":
            raise ValueError("unsupported policy schema_version")
        if raw.get("default") != "deny":
            raise ValueError("policy default must be deny")
        rules: list[PolicyRule] = []
        for item in raw.get("rules", []):
            if set(item) != {"tool", "operation", "max_risk", "scope_prefixes"}:
                raise ValueError("policy rule has unknown or missing fields")
            rules.append(
                PolicyRule(
                    tool=str(item["tool"]),
                    operation=str(item["operation"]),
                    max_risk=RiskLevel(str(item["max_risk"])),
                    scope_prefixes=tuple(str(value) for value in item["scope_prefixes"]),
                )
            )
        return cls(
            mode=PolicyMode.ALLOWLIST if rules else PolicyMode.DENY_ALL,
            source=f"file:{path.resolve()}",
            rules=tuple(rules),
        )

    def context_for(self, request: ActionRequest) -> AuthorizationContext:
        allowed = self.mode is not PolicyMode.DENY_ALL and any(
            rule.matches(request) for rule in self.rules
        )
        return AuthorizationContext(
            policy_allows=allowed,
            trusted_source=True,
            policy_source=self.source,
        )
