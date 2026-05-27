from __future__ import annotations

import pytest

from src.instagram_client import RealConnectionDisabledError
from src.services.polling import PollingService


@pytest.mark.asyncio
async def test_real_login_is_blocked_when_flag_false(app_components):
    _settings, _store, _audit, instagram = app_components

    with pytest.raises(RealConnectionDisabledError):
        await instagram.login_future("user", "password", {})


@pytest.mark.asyncio
async def test_real_read_is_blocked_when_flag_false(app_components):
    _settings, _store, _audit, instagram = app_components

    with pytest.raises(RealConnectionDisabledError):
        await instagram.list_threads_future(20)

    with pytest.raises(RealConnectionDisabledError):
        await instagram.list_messages_future("thread-id", 20)


@pytest.mark.asyncio
async def test_real_send_is_blocked_when_flag_false(app_components):
    _settings, _store, _audit, instagram = app_components

    with pytest.raises(RealConnectionDisabledError):
        await instagram.send_text_future("thread-id", "hello")


@pytest.mark.asyncio
async def test_polling_does_not_start_when_flag_false(app_components):
    settings, _store, audit, _instagram = app_components
    polling = PollingService(settings, audit)

    started = await polling.start()

    assert started is False
    assert polling.started is False
    assert any(event["event"] == "POLLING_BLOCKED" for event in audit.memory_events)
