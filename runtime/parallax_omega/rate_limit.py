from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from time import monotonic


class RateLimitExceeded(RuntimeError):
    pass


@dataclass(frozen=True)
class RateLimitPolicy:
    limit: int = 60
    window_seconds: float = 60.0
    max_keys: int = 128

    def __post_init__(self) -> None:
        if self.limit < 1 or self.window_seconds <= 0 or self.max_keys < 1:
            raise ValueError("rate limit values must be positive")


class SlidingWindowRateLimiter:
    """Thread-safe bounded process-level limiter.

    This is a deployment backstop, not an identity-aware quota system. Public
    deployments must still place the MCP server behind an authenticated gateway.
    """

    def __init__(
        self,
        policy: RateLimitPolicy | None = None,
        *,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self.policy = policy or RateLimitPolicy()
        self._clock = clock
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(self, key: str) -> None:
        if not key:
            raise ValueError("rate limit key is required")
        now = self._clock()
        cutoff = now - self.policy.window_seconds
        with self._lock:
            if key not in self._events and len(self._events) >= self.policy.max_keys:
                oldest_key = min(
                    self._events,
                    key=lambda candidate: self._events[candidate][0]
                    if self._events[candidate]
                    else float("-inf"),
                )
                self._events.pop(oldest_key, None)
            bucket = self._events[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self.policy.limit:
                raise RateLimitExceeded("rate_limit_exceeded")
            bucket.append(now)
