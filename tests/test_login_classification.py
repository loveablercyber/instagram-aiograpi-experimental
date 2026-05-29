from __future__ import annotations

import asyncio

from aiograpi.exceptions import (
    BadPassword,
    ChallengeRequired,
    CheckpointRequired,
    ClientForbiddenError,
    TwoFactorRequired,
    UnknownError,
)
from fastapi.testclient import TestClient

from src.app import create_app
from src.auth_diagnostics import sanitize_instagram_auth_payload
from src.config import Settings
from src.instagram_client import InstagramClientService
from src.security.encryption import EncryptionService
from src.services.audit import AuditService
from src.session_store import MemorySessionStore
from conftest import TEST_TOKEN, make_settings

MANUAL_CONFIRMATION = "RUN_ONE_MANUAL_LOGIN_ATTEMPT"


class RaisingClient:
    exception_class = Exception
    exception_kwargs = {}
    public_profile_exists = True
    login_calls = 0

    def __init__(self, settings=None, proxy=None, logger=None):
        self.settings_payload = settings or {}
        self.challenge_code_handler = None
        self.last_json = {}
        self.last_response = None

    async def login(self, username=None, password=None, verification_code=""):
        self.__class__.login_calls += 1
        raise self.exception_class("sanitized test exception", **self.exception_kwargs)

    async def user_info_by_username_gql(self, username):
        if not self.public_profile_exists:
            from aiograpi.exceptions import UserNotFound

            raise UserNotFound("User not found")
        return {"pk": "123", "username": username}

    def get_settings(self):
        return {
            "cookies": {"sessionid": "fake-sessionid-sensitive"},
            "authorization_data": {"ds_user_id": "123"},
            "device_settings": {"uuid": "fake-device"},
        }


def _client_for_exception(exception_class):
    class SpecificRaisingClient(RaisingClient):
        pass

    SpecificRaisingClient.exception_class = exception_class
    SpecificRaisingClient.login_calls = 0
    settings: Settings = make_settings(
        instagram_real_connection_enabled=True,
        instagram_username="secondary_test",
        instagram_password="temporary-password",
    )
    encryption = EncryptionService(settings.session_encryption_key)
    store = MemorySessionStore(settings, encryption)
    audit = AuditService()
    instagram = InstagramClientService(settings, store, audit, client_factory=SpecificRaisingClient)
    app = create_app(settings=settings, session_store=store, audit=audit, instagram=instagram)
    return TestClient(app), audit, store


def _client_for_exception_kwargs(exception_class, exception_kwargs):
    class SpecificRaisingClient(RaisingClient):
        pass

    SpecificRaisingClient.exception_class = exception_class
    SpecificRaisingClient.exception_kwargs = exception_kwargs
    SpecificRaisingClient.login_calls = 0
    settings: Settings = make_settings(
        instagram_real_connection_enabled=True,
        instagram_username="secondary_test",
        instagram_password="temporary-password",
    )
    encryption = EncryptionService(settings.session_encryption_key)
    store = MemorySessionStore(settings, encryption)
    audit = AuditService()
    instagram = InstagramClientService(settings, store, audit, client_factory=SpecificRaisingClient)
    app = create_app(settings=settings, session_store=store, audit=audit, instagram=instagram)
    return TestClient(app), audit, store


def _login_response(exception_class):
    client, audit, store = _client_for_exception(exception_class)
    with client:
        response = client.post(
            "/internal/instagram/login",
            headers={"X-Internal-Token": TEST_TOKEN},
            json={"confirmManualAttempt": MANUAL_CONFIRMATION},
        )
    return response, audit, store


def test_two_factor_required_returns_sanitized_verification_status():
    response, audit, store = _login_response(TwoFactorRequired)

    assert response.status_code == 409
    assert response.json()["status"] == "two_factor_required"
    assert response.json()["requires_manual_action"] is True
    assert response.json()["retry_allowed"] is False
    assert any(event["event"] == "LOGIN_TWO_FACTOR_REQUIRED" for event in audit.memory_events)
    assert "fake-sessionid-sensitive" not in str(store.documents)


def test_challenge_required_returns_sanitized_challenge_status():
    response, audit, _store = _login_response(ChallengeRequired)

    assert response.status_code == 409
    assert response.json()["status"] == "challenge_required"
    assert response.json()["requires_manual_action"] is True
    assert any(event["event"] == "LOGIN_CHALLENGE_REQUIRED" for event in audit.memory_events)


def test_checkpoint_required_returns_manual_action_required():
    response, audit, _store = _login_response(CheckpointRequired)

    assert response.status_code == 409
    assert response.json()["status"] == "checkpoint_required"
    assert response.json()["safe_message"] == "Instagram requires manual account action before another login attempt."
    assert any(event["event"] == "LOGIN_CHECKPOINT_REQUIRED" for event in audit.memory_events)


def test_bad_password_returns_context_rejected_without_sensitive_detail():
    response, audit, _store = _login_response(BadPassword)
    body = str(response.json())

    assert response.status_code == 401
    assert response.json()["status"] == "invalid_credentials"
    assert response.json()["safe_message"] == "Instagram rejected the credentials or private login context."
    assert "temporary-password" not in body
    assert "fake-sessionid-sensitive" not in body
    assert any(event["event"] == "LOGIN_BAD_PASSWORD_OR_CONTEXT_REJECTED" for event in audit.memory_events)


def test_unknown_error_returns_unclassified_sanitized_status():
    response, audit, _store = _login_response(UnknownError)

    assert response.status_code == 409
    assert response.json()["status"] == "unknown_error"
    assert response.json()["safe_message"].startswith("Instagram returned an unclassified")
    event = next(event for event in audit.memory_events if event["event"] == "LOGIN_UNCLASSIFIED_FAILURE")
    assert event["metadata"]["exceptionClass"] == "UnknownError"
    assert "challengeType" not in event["metadata"]


def test_client_forbidden_returns_blocked_diagnostic():
    response, audit, _store = _login_response(ClientForbiddenError)

    assert response.status_code == 409
    assert response.json()["status"] == "blocked"
    assert response.json()["requires_manual_action"] is True
    assert any(event["event"] == "LOGIN_FEEDBACK_REQUIRED" for event in audit.memory_events)


def test_verification_endpoint_rejects_missing_token(client):
    response = client.post("/internal/instagram/verification/two-factor", json={"code": "123456"})

    assert response.status_code == 401


def test_verification_endpoint_blocks_more_than_two_attempts(auth_headers):
    client, _audit, store = _client_for_exception(TwoFactorRequired)
    with client:
        login_response = client.post(
            "/internal/instagram/login",
            headers=auth_headers,
            json={"confirmManualAttempt": MANUAL_CONFIRMATION},
        )
        first = client.post("/internal/instagram/verification/two-factor", headers=auth_headers, json={"code": "111111"})
        second = client.post("/internal/instagram/verification/two-factor", headers=auth_headers, json={"code": "222222"})
        third = client.post("/internal/instagram/verification/two-factor", headers=auth_headers, json={"code": "333333"})

    assert login_response.json()["status"] == "two_factor_required"
    assert first.json()["status"] == "verification_failed"
    assert second.json()["status"] == "verification_failed"
    assert third.json()["status"] == "verification_failed"
    assert third.json()["reason"] == "verification_attempt_limit_exceeded_or_context_missing"
    assert "111111" not in str(store.documents)
    assert "222222" not in str(store.documents)


def test_direct_endpoints_are_blocked_without_valid_session(auth_headers):
    settings: Settings = make_settings(instagram_real_connection_enabled=True)
    encryption = EncryptionService(settings.session_encryption_key)
    store = MemorySessionStore(settings, encryption)
    audit = AuditService()
    instagram = InstagramClientService(settings, store, audit)
    app = create_app(settings=settings, session_store=store, audit=audit, instagram=instagram)

    with TestClient(app) as client:
        threads = client.get("/internal/instagram/threads", headers=auth_headers)
        messages = client.get("/internal/instagram/threads/123/messages", headers=auth_headers)
        send = client.post(
            "/internal/instagram/threads/123/send-text",
            headers=auth_headers,
            json={"text": "manual test"},
        )

    assert threads.status_code == 401
    assert messages.status_code == 401
    assert send.status_code == 401


def test_login_requires_manual_confirmation(auth_headers):
    client, audit, _store = _client_for_exception(UnknownError)
    with client:
        response = client.post("/internal/instagram/login", headers=auth_headers, json={})

    assert response.status_code == 409
    assert response.json()["status"] == "blocked"
    assert response.json()["retry_allowed"] is False
    assert any(event["event"] == "LOGIN_BLOCKED_BY_AUTH_GUARD" for event in audit.memory_events)


def test_latest_auth_attempt_endpoint_returns_sanitized_diagnostic(auth_headers):
    client, _audit, _store = _client_for_exception(UnknownError)
    with client:
        client.post(
            "/internal/instagram/login",
            headers=auth_headers,
            json={"confirmManualAttempt": MANUAL_CONFIRMATION},
        )
        latest = client.get("/internal/instagram/auth-attempts/latest", headers=auth_headers)

    assert latest.status_code == 200
    assert latest.json()["found"] is True
    assert latest.json()["diagnostic"]["status"] == "unknown_error"
    assert "fake-sessionid-sensitive" not in str(latest.json())


def test_latest_auth_attempt_redacts_configured_username(auth_headers):
    client, _audit, _store = _client_for_exception_kwargs(
        UnknownError,
        {
            "message": "We can't find an account with secondary_test.",
            "error_type": "invalid_user",
            "status": "fail",
        },
    )
    with client:
        login = client.post(
            "/internal/instagram/login",
            headers=auth_headers,
            json={"confirmManualAttempt": MANUAL_CONFIRMATION},
        )
        latest = client.get("/internal/instagram/auth-attempts/latest", headers=auth_headers)

    assert login.status_code == 409
    assert "secondary_test" not in str(login.json())
    assert latest.status_code == 200
    assert "secondary_test" not in str(latest.json())
    assert "ACCOUNT_IDENTIFIER_REDACTED" in str(latest.json())


def test_account_preflight_uses_public_profile_without_login(auth_headers):
    client, _audit, _store = _client_for_exception(UnknownError)
    client.app.state.instagram._client_factory.login_calls = 0

    with client:
        response = client.get("/internal/instagram/account/preflight", headers=auth_headers)

    assert response.status_code == 200
    assert response.json()["public_profile_exists"] is True
    assert response.json()["profile_identifier_present"] is True
    assert response.json()["login_attempt_performed"] is False
    assert response.json()["username_redacted"] == "se***st"
    assert client.app.state.instagram._client_factory.login_calls == 0


def test_latest_auth_attempt_correlates_public_preflight_and_private_invalid_user(auth_headers):
    client, _audit, _store = _client_for_exception_kwargs(
        UnknownError,
        {
            "message": "We can't find an account with secondary_test.",
            "error_type": "invalid_user",
            "status": "fail",
        },
    )
    with client:
        preflight = client.get("/internal/instagram/account/preflight", headers=auth_headers)
        client.post(
            "/internal/instagram/login",
            headers=auth_headers,
            json={"confirmManualAttempt": MANUAL_CONFIRMATION},
        )
        latest = client.get("/internal/instagram/auth-attempts/latest", headers=auth_headers)

    assert preflight.json()["public_profile_exists"] is True
    assert latest.json()["correlation"]["public_profile_exists"] is True
    assert latest.json()["correlation"]["private_login_error_type"] == "invalid_user"
    assert latest.json()["correlation"]["safe_interpretation"].startswith("Public profile exists")


def test_failed_login_does_not_overwrite_existing_session(auth_headers):
    client, _audit, store = _client_for_exception(UnknownError)
    existing = {"cookies": {"sessionid": "existing-valid-session"}, "device_settings": {"uuid": "existing-device"}}
    with client:
        asyncio.run(store.save_settings("test_account_only", existing))
        before = dict(store.documents["test_account_only"])
        response = client.post(
            "/internal/instagram/login",
            headers=auth_headers,
            json={"confirmManualAttempt": MANUAL_CONFIRMATION},
        )

    assert response.json()["status"] == "unknown_error"
    assert store.documents["test_account_only"]["encryptedSettings"] == before["encryptedSettings"]


def test_sanitize_instagram_auth_payload_removes_secrets():
    payload = {
        "message": "challenge_required for user@example.com",
        "error_type": "unknown",
        "password": "secret-password",
        "cookies": {"sessionid": "full-session-id", "csrftoken": "csrf-token"},
        "authorization": "Bearer secret",
        "challenge": {
            "challenge_context": "opaque-context",
            "phone": "+5511999999999",
            "email": "user@example.com",
        },
        "two_factor_info": {"two_factor_identifier": "identifier-secret"},
        "device_id": "android-secret-device",
        "uuid": "uuid-secret",
    }

    sanitized = sanitize_instagram_auth_payload(payload)
    body = str(sanitized)

    assert "secret-password" not in body
    assert "full-session-id" not in body
    assert "csrf-token" not in body
    assert "identifier-secret" not in body
    assert "android-secret-device" not in body
    assert "uuid-secret" not in body
    assert "[EMAIL_REDACTED]" in body
    assert sanitized["challenge"]["challenge_context"] == "[PRESENT]"
