from __future__ import annotations

import pytest

from src.instagram_client import RealConnectionDisabledError
from src.services.polling import PollingService
from src.security.encryption import EncryptionService
from src.session_store import MemorySessionStore
from src.services.audit import AuditService
from conftest import make_settings


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


@pytest.mark.asyncio
async def test_polling_does_not_start_without_valid_session():
    settings = make_settings(instagram_real_connection_enabled=True, instagram_polling_enabled=True)
    store = MemorySessionStore(settings, EncryptionService(settings.session_encryption_key))
    audit = AuditService()
    polling = PollingService(settings, audit, session_store=store)

    started = await polling.start()

    assert started is False
    assert polling.started is False
    event = next(event for event in audit.memory_events if event["event"] == "POLLING_BLOCKED")
    assert event["metadata"]["reason"] == "no_valid_stored_session"


def test_phase2_internal_routes_are_blocked_when_flag_false(client, auth_headers):
    login = client.post(
        "/internal/instagram/login",
        headers=auth_headers,
        json={"username": "test-user", "password": "test-password"},
    )
    validate = client.post("/internal/instagram/session/validate", headers=auth_headers)
    threads = client.get("/internal/instagram/threads", headers=auth_headers)
    messages = client.get("/internal/instagram/threads/123/messages", headers=auth_headers)
    send = client.post(
        "/internal/instagram/threads/123/send-text",
        headers=auth_headers,
        json={"text": "test only"},
    )
    logout = client.post(
        "/internal/instagram/logout",
        headers=auth_headers,
        json={"confirm": "LOGOUT_INSTAGRAM_TEST_ACCOUNT"},
    )

    assert login.status_code == 403
    assert validate.status_code == 403
    assert threads.status_code == 403
    assert messages.status_code == 403
    assert send.status_code == 403
    assert logout.status_code == 403
