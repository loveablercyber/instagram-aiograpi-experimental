from __future__ import annotations

from aiograpi.exceptions import (
    BadPassword,
    ChallengeRequired,
    CheckpointRequired,
    TwoFactorRequired,
    UnknownError,
)
from fastapi.testclient import TestClient

from src.app import create_app
from src.config import Settings
from src.instagram_client import InstagramClientService
from src.security.encryption import EncryptionService
from src.services.audit import AuditService
from src.session_store import MemorySessionStore
from conftest import TEST_TOKEN, make_settings


class RaisingClient:
    exception_class = Exception

    def __init__(self, settings=None, proxy=None, logger=None):
        self.settings_payload = settings or {}
        self.challenge_code_handler = None

    async def login(self, username=None, password=None, verification_code=""):
        raise self.exception_class("sanitized test exception")

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
        response = client.post("/internal/instagram/login", headers={"X-Internal-Token": TEST_TOKEN}, json={})
    return response, audit, store


def test_two_factor_required_returns_sanitized_verification_status():
    response, audit, store = _login_response(TwoFactorRequired)

    assert response.status_code == 200
    assert response.json() == {
        "status": "verification_required",
        "nextAction": "submit_verification_code",
        "sessionStored": None,
        "verificationType": "two_factor",
        "challengeMethod": None,
        "reason": None,
    }
    assert any(event["event"] == "LOGIN_TWO_FACTOR_REQUIRED" for event in audit.memory_events)
    assert "fake-sessionid-sensitive" not in str(store.documents)


def test_challenge_required_returns_sanitized_challenge_status():
    response, audit, _store = _login_response(ChallengeRequired)

    assert response.status_code == 200
    assert response.json()["status"] == "verification_required"
    assert response.json()["verificationType"] == "challenge"
    assert response.json()["challengeMethod"] == "email_or_sms_or_unknown"
    assert any(event["event"] == "LOGIN_CHALLENGE_REQUIRED" for event in audit.memory_events)


def test_checkpoint_required_returns_manual_action_required():
    response, audit, _store = _login_response(CheckpointRequired)

    assert response.status_code == 200
    assert response.json()["status"] == "manual_action_required"
    assert response.json()["reason"] == "checkpoint_or_login_confirmation"
    assert any(event["event"] == "LOGIN_CHECKPOINT_REQUIRED" for event in audit.memory_events)


def test_bad_password_returns_context_rejected_without_sensitive_detail():
    response, audit, _store = _login_response(BadPassword)
    body = str(response.json())

    assert response.status_code == 200
    assert response.json()["status"] == "authentication_rejected"
    assert response.json()["reason"] == "credentials_or_login_context_rejected"
    assert "temporary-password" not in body
    assert "fake-sessionid-sensitive" not in body
    assert any(event["event"] == "LOGIN_BAD_PASSWORD_OR_CONTEXT_REJECTED" for event in audit.memory_events)


def test_unknown_error_returns_unclassified_sanitized_status():
    response, audit, _store = _login_response(UnknownError)

    assert response.status_code == 200
    assert response.json()["status"] == "authentication_failed_unclassified"
    assert response.json()["reason"] == "sanitized_unclassified_instagram_response"
    assert any(event["event"] == "LOGIN_UNCLASSIFIED_FAILURE" for event in audit.memory_events)


def test_verification_endpoint_rejects_missing_token(client):
    response = client.post("/internal/instagram/verification/two-factor", json={"code": "123456"})

    assert response.status_code == 401


def test_verification_endpoint_blocks_more_than_two_attempts(auth_headers):
    client, _audit, store = _client_for_exception(TwoFactorRequired)
    with client:
        login_response = client.post("/internal/instagram/login", headers=auth_headers, json={})
        first = client.post("/internal/instagram/verification/two-factor", headers=auth_headers, json={"code": "111111"})
        second = client.post("/internal/instagram/verification/two-factor", headers=auth_headers, json={"code": "222222"})
        third = client.post("/internal/instagram/verification/two-factor", headers=auth_headers, json={"code": "333333"})

    assert login_response.json()["status"] == "verification_required"
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
