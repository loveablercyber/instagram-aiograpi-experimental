from __future__ import annotations

import pytest

from src.services.rate_limit import RateLimitConfig, RateLimitExceeded, RateLimitService


def test_default_future_send_limit_is_five_per_hour():
    service = RateLimitService(RateLimitConfig())

    assert service.config.max_sends_per_hour == 5


def test_future_sends_above_limit_are_blocked():
    service = RateLimitService(RateLimitConfig(max_sends_per_hour=5))

    for _ in range(5):
        service.record_send("test_account_only")

    with pytest.raises(RateLimitExceeded):
        service.record_send("test_account_only")
