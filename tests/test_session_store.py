from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_store_restore_and_remove_encrypted_session(app_components):
    settings, store, _audit, _instagram = app_components
    fake_settings = {
        "cookies": {"sessionid": "fake-sessionid-plain-value"},
        "device_settings": {"uuid": "fake-uuid"},
    }

    await store.save_settings(settings.instagram_test_account_key, fake_settings)
    restored = await store.restore_settings(settings.instagram_test_account_key)
    raw = await store.raw_document_for_tests(settings.instagram_test_account_key)

    assert restored == fake_settings
    assert raw is not None
    assert "encryptedSettings" in raw
    assert "fake-sessionid-plain-value" not in str(raw)
    assert "cookies" not in str(raw)

    removed = await store.delete_session(settings.instagram_test_account_key)

    assert removed is True
    assert await store.session_exists(settings.instagram_test_account_key) is False


def test_session_routes_store_restore_and_delete(client, auth_headers):
    store_response = client.post("/internal/session/test-store", headers=auth_headers)
    restore_response = client.post("/internal/session/test-restore", headers=auth_headers)
    delete_response = client.request(
        "DELETE",
        "/internal/session",
        headers=auth_headers,
        json={"confirm": "REMOVE_EXPERIMENTAL_SESSION"},
    )

    assert store_response.status_code == 200
    assert restore_response.status_code == 200
    assert delete_response.status_code == 200
    assert delete_response.json()["ok"] is True


def test_delete_requires_exact_confirmation(client, auth_headers):
    response = client.request(
        "DELETE",
        "/internal/session",
        headers=auth_headers,
        json={"confirm": "wrong"},
    )

    assert response.status_code == 400
