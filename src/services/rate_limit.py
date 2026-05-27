from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


class RateLimitExceeded(RuntimeError):
    """Raised when a future sending operation exceeds the configured limit."""


@dataclass(frozen=True)
class RateLimitConfig:
    max_sends_per_hour: int = 5


class RateLimitService:
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self._events: dict[str, deque[datetime]] = defaultdict(deque)

    def _prune(self, account_key: str, now: datetime) -> None:
        cutoff = now - timedelta(hours=1)
        events = self._events[account_key]
        while events and events[0] <= cutoff:
            events.popleft()

    def remaining(self, account_key: str, now: datetime | None = None) -> int:
        now = now or datetime.now(UTC)
        self._prune(account_key, now)
        return max(self.config.max_sends_per_hour - len(self._events[account_key]), 0)

    def assert_send_allowed(self, account_key: str, now: datetime | None = None) -> None:
        if self.remaining(account_key, now) <= 0:
            raise RateLimitExceeded("Future send rate limit exceeded")

    def record_send(self, account_key: str, now: datetime | None = None) -> None:
        now = now or datetime.now(UTC)
        self.assert_send_allowed(account_key, now)
        self._events[account_key].append(now)
