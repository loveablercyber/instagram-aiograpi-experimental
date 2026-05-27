from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from src.app import create_app
from src.config import Settings
from src.instagram_client import InstagramClientService
from src.security.encryption import EncryptionService
from src.services.audit import AuditService
from src.session_store import MemorySessionStore
from conftest import TEST_TOKEN, make_settings


@dataclass
class FakeUser:
    pk: str
    username: str
    full_name: str


@dataclass
class FakeMessage:
    id: str
    thread_id: str
    user_id: str
    timestamp: datetime
    item_type: str
    is_sent_by_viewer: bool
    text: str


@dataclass
class FakeThread:
    id: str
    thread_title: str
    is_group: bool
    last_activity_at: datetime
    users: list[FakeUser]
    messages: list[FakeMessage]


class FakeAioClient:
    def __init__(self, settings=None, proxy=None, logger=None):
        self.settings_payload = settings or {}
        self.proxy = proxy
        self.logger = logger
        self.challenge_code_handler = None

    async def login(self, username=None, password=None, verification_code=""):
        assert username
        assert password
        return True

    def get_settings(self):
        return {
            "cookies": {"sessionid": "fake-real-sessionid-never-plaintext"},
            "authorization_data": {"ds_user_id": "123"},
            "device_settings": {"uuid": "fake-real-device"},
        }

    async def account_info(self):
        return {"pk": "123"}

    async def direct_threads(self, amount=5, thread_message_limit=1):
        message = FakeMessage(
            id="msg-1",
            thread_id="thread-1",
            user_id="user-2",
            timestamp=datetime.now(UTC),
            item_type="text",
            is_sent_by_viewer=False,
            text="hello",
        )
        return [
            FakeThread(
                id="thread-1",
                thread_title="Test Thread",
                is_group=False,
                last_activity_at=datetime.now(UTC),
                users=[FakeUser(pk="user-2", username="test_receiver", full_name="Test Receiver")],
                messages=[message],
            )
        ][:amount]

    async def direct_messages(self, thread_id, amount=10):
        return [
            FakeMessage(
                id="msg-1",
                thread_id=str(thread_id),
                user_id="user-2",
                timestamp=datetime.now(UTC),
                item_type="text",
                is_sent_by_viewer=False,
                text="hello",
            )
        ][:amount]

    async def direct_send(self, text, user_ids=None, thread_ids=None):
        return FakeMessage(
            id="msg-send-1",
            thread_id=str((thread_ids or [""])[0]),
            user_id="me",
            timestamp=datetime.now(UTC),
            item_type="text",
            is_sent_by_viewer=True,
            text=text,
        )

    async def logout(self):
        return True


def _client_with_real_connection_enabled() -> tuple[TestClient, MemorySessionStore]:
    settings: Settings = make_settings(instagram_real_connection_enabled=True, instagram_max_sends_per_hour=2)
    encryption = EncryptionService(settings.session_encryption_key)
    store = MemorySessionStore(settings, encryption)
    audit = AuditService()
    instagram = InstagramClientService(settings, store, audit, client_factory=FakeAioClient)
    app = create_app(settings=settings, session_store=store, audit=audit, instagram=instagram)
    return TestClient(app), store


def test_login_saves_real_settings_encrypted_and_validate_restores():
    client, store = _client_with_real_connection_enabled()
    with client:
        response = client.post(
            "/internal/instagram/login",
            headers={"X-Internal-Token": TEST_TOKEN},
            json={"username": "secondary_test", "password": "temporary-password"},
        )
        validate = client.post("/internal/instagram/session/validate", headers={"X-Internal-Token": TEST_TOKEN})

    assert response.status_code == 200
    assert validate.status_code == 200
    assert validate.json()["authenticated"] is True
    raw = store.documents["test_account_only"]
    assert raw["encryptedSettings"].startswith("v1:gAAAA")
    assert "fake-real-sessionid-never-plaintext" not in str(raw)


def test_login_can_use_render_configured_credentials_without_request_body_password():
    settings: Settings = make_settings(
        instagram_real_connection_enabled=True,
        instagram_username="secondary_test",
        instagram_password="temporary-password",
    )
    encryption = EncryptionService(settings.session_encryption_key)
    store = MemorySessionStore(settings, encryption)
    audit = AuditService()
    instagram = InstagramClientService(settings, store, audit, client_factory=FakeAioClient)
    app = create_app(settings=settings, session_store=store, audit=audit, instagram=instagram)

    with TestClient(app) as client:
        response = client.post("/internal/instagram/login", headers={"X-Internal-Token": TEST_TOKEN}, json={})

    assert response.status_code == 200
    assert "fake-real-sessionid-never-plaintext" not in str(store.documents["test_account_only"])


def test_threads_messages_send_and_send_rate_limit_are_controlled():
    client, _store = _client_with_real_connection_enabled()
    headers = {"X-Internal-Token": TEST_TOKEN}
    with client:
        client.post(
            "/internal/instagram/login",
            headers=headers,
            json={"username": "secondary_test", "password": "temporary-password"},
        )
        threads = client.get("/internal/instagram/threads?amount=5", headers=headers)
        messages = client.get("/internal/instagram/threads/thread-1/messages?amount=10", headers=headers)
        first_send = client.post(
            "/internal/instagram/threads/thread-1/send-text",
            headers=headers,
            json={"text": "manual test"},
        )
        second_send = client.post(
            "/internal/instagram/threads/thread-1/send-text",
            headers=headers,
            json={"text": "manual test 2"},
        )
        third_send = client.post(
            "/internal/instagram/threads/thread-1/send-text",
            headers=headers,
            json={"text": "blocked"},
        )

    assert threads.status_code == 200
    assert len(threads.json()["threads"]) == 1
    assert messages.status_code == 200
    assert len(messages.json()["messages"]) == 1
    assert first_send.status_code == 200
    assert second_send.status_code == 200
    assert third_send.status_code == 429
