from __future__ import annotations

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
import pytest

from src.app import create_app
from src.config import Settings
from src.instagram_client import InstagramClientService
from src.security.encryption import EncryptionService
from src.services.audit import AuditService
from src.session_store import MemorySessionStore


TEST_TOKEN = "test-internal-token"


def make_settings(**overrides) -> Settings:
    values = {
        "app_env": "test",
        "port": 8000,
        "internal_api_token": TEST_TOKEN,
        "health_token": "",
        "mongodb_uri": "mongodb+srv://example.invalid/",
        "mongodb_database": "instagram_aiograpi_experimental",
        "mongodb_session_collection": "instagram_experimental_sessions",
        "mongodb_audit_collection": "instagram_experimental_audit",
        "mongodb_message_cache_collection": "instagram_experimental_messages",
        "session_encryption_key": Fernet.generate_key().decode("utf-8"),
        "instagram_real_connection_enabled": False,
        "instagram_test_account_key": "test_account_only",
        "instagram_username": "",
        "instagram_password": "",
        "instagram_polling_enabled": False,
        "instagram_polling_interval_seconds": 60,
        "instagram_max_messages_per_fetch": 20,
        "instagram_max_sends_per_hour": 5,
        "instagram_proxy_url": "",
    }
    values.update(overrides)
    settings = Settings(**values)
    settings.validate()
    return settings


def make_components(settings: Settings | None = None):
    settings = settings or make_settings()
    encryption = EncryptionService(settings.session_encryption_key)
    store = MemorySessionStore(settings, encryption)
    audit = AuditService()
    instagram = InstagramClientService(settings, store, audit)
    return settings, store, audit, instagram


@pytest.fixture()
def app_components():
    return make_components()


@pytest.fixture()
def client(app_components):
    settings, store, audit, instagram = app_components
    app = create_app(settings=settings, session_store=store, audit=audit, instagram=instagram)
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def auth_headers():
    return {"X-Internal-Token": TEST_TOKEN}
