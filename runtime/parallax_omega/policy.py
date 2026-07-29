from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path

from .models import ActionRequest, AuthorizationContext, RiskLevel, canonical_hash


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
_SCOPE_NAMESPACE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_SCOPE_SEGMENT = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
POLICY_SCHEMA_VERSION = "1.1"
POLICY_RELOAD_DOMAIN = b"parallax.policy.reload.v1:"


def higher_risk(left: RiskLevel, right: RiskLevel) -> RiskLevel:
    return left if _RISK_ORDER[left] >= _RISK_ORDER[right] else right


def lower_risk(left: RiskLevel, right: RiskLevel) -> RiskLevel:
    return left if _RISK_ORDER[left] <= _RISK_ORDER[right] else right


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_digest(value: str) -> str:
    normalized = value.strip().lower()
    if not _SHA256_RE.fullmatch(normalized):
        raise ValueError("policy hash pin must be a SHA-256 hex digest")
    return normalized


@dataclass(frozen=True)
class Scope:
    """Normalized hierarchical scope.

    Accepted forms are ``namespace`` and ``namespace:path/to/resource``. For
    compatibility with rc.2, ``namespace/path`` is normalized to the same
    representation. Traversal, percent encoding, empty segments, control
    characters, and backslashes are rejected.
    """

    namespace: str
    segments: tuple[str, ...] = ()

    @classmethod
    def parse(cls, value: str, *, prefix: bool = False) -> Scope:
        if value != value.strip() or not value:
            raise ValueError("scope must be non-empty and trimmed")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
            raise ValueError("scope contains control characters")
        if "\\" in value or "%" in value or "//" in value:
            raise ValueError("scope contains ambiguous encoding or separators")

        normalized = value[:-1] if prefix and value.endswith("/") else value
        if not normalized:
            raise ValueError("scope prefix cannot be empty")

        if ":" in normalized:
            namespace, raw_path = normalized.split(":", 1)
        elif "/" in normalized:
            namespace, raw_path = normalized.split("/", 1)
        else:
            namespace, raw_path = normalized, ""

        if not _SCOPE_NAMESPACE.fullmatch(namespace):
            raise ValueError("invalid scope namespace")

        segments: list[str] = []
        if raw_path:
            for segment in raw_path.split("/"):
                if segment in {"", ".", ".."} or not _SCOPE_SEGMENT.fullmatch(segment):
                    raise ValueError("invalid scope path segment")
                segments.append(segment)
        return cls(namespace=namespace, segments=tuple(segments))

    def contains(self, other: Scope) -> bool:
        return (
            self.namespace == other.namespace
            and len(self.segments) <= len(other.segments)
            and other.segments[: len(self.segments)] == self.segments
        )

    def canonical(self) -> str:
        if not self.segments:
            return self.namespace
        return f"{self.namespace}:{'/'.join(self.segments)}"


@dataclass(frozen=True)
class PolicyRule:
    """Host-owned operation classification and exact scope allowlist."""

    tool: str
    operation: str
    risk_floor: RiskLevel
    max_risk: RiskLevel
    irreversible: bool
    scope_prefixes: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.tool.strip() or not self.operation.strip():
            raise ValueError("policy rule tool and operation are required")
        if _RISK_ORDER[self.risk_floor] > _RISK_ORDER[self.max_risk]:
            raise ValueError("risk_floor cannot exceed max_risk")
        if not self.scope_prefixes or any(not prefix.strip() for prefix in self.scope_prefixes):
            raise ValueError("policy rule requires non-empty scope_prefixes")
        for prefix in self.scope_prefixes:
            Scope.parse(prefix, prefix=True)

    def matches_target(self, request: ActionRequest) -> bool:
        try:
            requested_scope = Scope.parse(request.scope)
        except ValueError:
            return False
        prefixes = (Scope.parse(prefix, prefix=True) for prefix in self.scope_prefixes)
        return (
            request.tool == self.tool
            and request.operation == self.operation
            and any(prefix.contains(requested_scope) for prefix in prefixes)
        )

    def effective_risk(self, request: ActionRequest) -> RiskLevel:
        return higher_risk(request.risk, self.risk_floor)

    def allows(self, request: ActionRequest) -> bool:
        return (
            self.matches_target(request)
            and _RISK_ORDER[self.effective_risk(request)] <= _RISK_ORDER[self.max_risk]
        )


@dataclass(frozen=True)
class HostPolicyAdapter:
    """Immutable server-owned policy snapshot.

    File-backed policies require an out-of-band SHA-256 pin. Entry points load
    this object once at process startup. Reloads are explicit and HMAC signed.
    """

    mode: PolicyMode = PolicyMode.DENY_ALL
    source: str = "host-policy"
    rules: tuple[PolicyRule, ...] = ()
    policy_hash: str = ""

    def __post_init__(self) -> None:
        if self.policy_hash:
            object.__setattr__(self, "policy_hash", _validate_digest(self.policy_hash))
            return
        payload = {
            "mode": self.mode.value,
            "source": self.source,
            "rules": [asdict(rule) for rule in self.rules],
        }
        object.__setattr__(self, "policy_hash", canonical_hash(payload))

    @classmethod
    def from_env(
        cls,
        mode_variable: str = "PARALLAX_POLICY_MODE",
        file_variable: str = "PARALLAX_POLICY_FILE",
        root_variable: str = "PARALLAX_POLICY_ROOT",
        hash_variable: str = "PARALLAX_POLICY_SHA256",
    ) -> HostPolicyAdapter:
        policy_file = os.getenv(file_variable)
        if policy_file:
            expected_hash = os.getenv(hash_variable)
            if not expected_hash:
                return cls(mode=PolicyMode.DENY_ALL, source="missing-policy-hash-pin")
            try:
                root_raw = os.getenv(root_variable)
                root = Path(root_raw).resolve() if root_raw else None
                return cls.from_file(
                    Path(policy_file),
                    allowed_root=root,
                    expected_sha256=expected_hash,
                )
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                return cls(mode=PolicyMode.DENY_ALL, source="invalid-policy-file")

        raw = os.getenv(mode_variable, PolicyMode.DENY_ALL.value)
        try:
            mode = PolicyMode(raw)
        except ValueError:
            return cls(mode=PolicyMode.DENY_ALL, source="invalid-policy-mode")

        if mode is PolicyMode.READ_ONLY:
            return cls(
                mode=mode,
                source="builtin:read_only",
                rules=(
                    PolicyRule(
                        tool="local",
                        operation="parse",
                        risk_floor=RiskLevel.R0,
                        max_risk=RiskLevel.R0,
                        irreversible=False,
                        scope_prefixes=("input",),
                    ),
                ),
            )
        return cls(mode=PolicyMode.DENY_ALL, source="builtin:deny_all")

    @classmethod
    def from_file(
        cls,
        path: Path,
        *,
        expected_sha256: str,
        allowed_root: Path | None = None,
    ) -> HostPolicyAdapter:
        resolved = path.expanduser().resolve(strict=True)
        if allowed_root is not None:
            root = allowed_root.expanduser().resolve(strict=True)
            if resolved != root and root not in resolved.parents:
                raise ValueError("policy file is outside PARALLAX_POLICY_ROOT")
        if not resolved.is_file() or resolved.is_symlink():
            raise ValueError("policy path must be a regular non-symlink file")
        stat_result = resolved.stat()
        if stat_result.st_size > 1_000_000:
            raise ValueError("policy file exceeds size limit")
        if stat_result.st_mode & 0o002:
            raise ValueError("policy file must not be world-writable")

        data = resolved.read_bytes()
        digest = _sha256(data)
        if not hmac.compare_digest(digest, _validate_digest(expected_sha256)):
            raise ValueError("policy hash pin mismatch")

        raw = json.loads(data.decode("utf-8"))
        if raw.get("schema_version") != POLICY_SCHEMA_VERSION:
            raise ValueError("unsupported policy schema_version")
        if raw.get("default") != "deny":
            raise ValueError("policy default must be deny")
        rules: list[PolicyRule] = []
        expected_fields = {
            "tool",
            "operation",
            "risk_floor",
            "max_risk",
            "irreversible",
            "scope_prefixes",
        }
        for item in raw.get("rules", []):
            if set(item) != expected_fields:
                raise ValueError("policy rule has unknown or missing fields")
            rules.append(
                PolicyRule(
                    tool=str(item["tool"]),
                    operation=str(item["operation"]),
                    risk_floor=RiskLevel(str(item["risk_floor"])),
                    max_risk=RiskLevel(str(item["max_risk"])),
                    irreversible=bool(item["irreversible"]),
                    scope_prefixes=tuple(str(value) for value in item["scope_prefixes"]),
                )
            )
        return cls(
            mode=PolicyMode.ALLOWLIST if rules else PolicyMode.DENY_ALL,
            source=f"file:{resolved}",
            rules=tuple(rules),
            policy_hash=digest,
        )

    @classmethod
    def reload_signed(
        cls,
        path: Path,
        *,
        expected_sha256: str,
        signature_hex: str,
        hmac_key: bytes,
        allowed_root: Path | None = None,
    ) -> HostPolicyAdapter:
        if not hmac_key:
            raise ValueError("policy reload HMAC key is required")
        digest = _validate_digest(expected_sha256)
        expected_signature = hmac.new(
            hmac_key,
            POLICY_RELOAD_DOMAIN + digest.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        try:
            supplied = bytes.fromhex(signature_hex)
            expected = bytes.fromhex(expected_signature)
        except ValueError as exc:
            raise ValueError("invalid policy reload signature") from exc
        if not hmac.compare_digest(supplied, expected):
            raise ValueError("invalid policy reload signature")
        return cls.from_file(
            path,
            expected_sha256=digest,
            allowed_root=allowed_root,
        )

    def context_for(self, request: ActionRequest) -> AuthorizationContext:
        matching = tuple(rule for rule in self.rules if rule.matches_target(request))
        if self.mode is PolicyMode.DENY_ALL or not matching:
            return AuthorizationContext(
                policy_allows=False,
                trusted_source=True,
                policy_source=self.source,
                policy_hash=self.policy_hash,
            )

        risk_floor = matching[0].risk_floor
        max_risk = matching[0].max_risk
        operation_irreversible = False
        for rule in matching:
            risk_floor = higher_risk(risk_floor, rule.risk_floor)
            max_risk = lower_risk(max_risk, rule.max_risk)
            operation_irreversible = operation_irreversible or rule.irreversible

        effective_risk = higher_risk(request.risk, risk_floor)
        allowed = _RISK_ORDER[effective_risk] <= _RISK_ORDER[max_risk]
        return AuthorizationContext(
            policy_allows=allowed,
            trusted_source=True,
            policy_source=self.source,
            policy_hash=self.policy_hash,
            risk_floor=risk_floor,
            operation_irreversible=operation_irreversible,
        )
