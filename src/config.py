from __future__ import annotations

import os
from dataclasses import dataclass


APP_VERSION = "0.1.0"
EXPECTED_MONGODB_DATABASE = "instagram_aiograpi_experimental"
EXPECTED_SESSION_COLLECTION = "instagram_experimental_sessions"
EXPECTED_AUDIT_COLLECTION = "instagram_experimental_audit"
EXPECTED_MESSAGE_COLLECTION = "instagram_experimental_messages"
FORBIDDEN_ENV_TERMS = ("baileys", "whatsapp")


class ConfigError(RuntimeError):
    """Raised when startup configuration is unsafe for this experiment."""


def _get_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value == "":
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc


def _looks_like_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return lowered.startswith("replace_") or "replace_" in lowered or lowered in {"changeme", "example"}


@dataclass(frozen=True)
class Settings:
    app_env: str
    port: int
    internal_api_token: str
    health_token: str
    mongodb_uri: str
    mongodb_database: str
    mongodb_session_collection: str
    mongodb_audit_collection: str
    mongodb_message_cache_collection: str
    session_encryption_key: str
    instagram_real_connection_enabled: bool
    instagram_test_account_key: str
    instagram_username: str
    instagram_password: str
    instagram_polling_enabled: bool
    instagram_polling_interval_seconds: int
    instagram_max_messages_per_fetch: int
    instagram_max_sends_per_hour: int
    instagram_proxy_url: str
    app_version: str = APP_VERSION

    @classmethod
    def from_env(cls) -> "Settings":
        settings = cls(
            app_env=os.getenv("APP_ENV", "experimental").strip().lower(),
            port=_get_int("PORT", 8000),
            internal_api_token=os.getenv("INTERNAL_API_TOKEN", ""),
            health_token=os.getenv("HEALTH_TOKEN", ""),
            mongodb_uri=os.getenv("MONGODB_URI", ""),
            mongodb_database=os.getenv("MONGODB_DATABASE", EXPECTED_MONGODB_DATABASE),
            mongodb_session_collection=os.getenv("MONGODB_SESSION_COLLECTION", EXPECTED_SESSION_COLLECTION),
            mongodb_audit_collection=os.getenv("MONGODB_AUDIT_COLLECTION", EXPECTED_AUDIT_COLLECTION),
            mongodb_message_cache_collection=os.getenv(
                "MONGODB_MESSAGE_CACHE_COLLECTION",
                EXPECTED_MESSAGE_COLLECTION,
            ),
            session_encryption_key=os.getenv("SESSION_ENCRYPTION_KEY", ""),
            instagram_real_connection_enabled=_get_bool("INSTAGRAM_REAL_CONNECTION_ENABLED", False),
            instagram_test_account_key=os.getenv("INSTAGRAM_TEST_ACCOUNT_KEY", "test_account_only"),
            instagram_username=os.getenv("INSTAGRAM_USERNAME", ""),
            instagram_password=os.getenv("INSTAGRAM_PASSWORD", ""),
            instagram_polling_enabled=_get_bool("INSTAGRAM_POLLING_ENABLED", False),
            instagram_polling_interval_seconds=_get_int("INSTAGRAM_POLLING_INTERVAL_SECONDS", 60),
            instagram_max_messages_per_fetch=_get_int("INSTAGRAM_MAX_MESSAGES_PER_FETCH", 10),
            instagram_max_sends_per_hour=_get_int("INSTAGRAM_MAX_SENDS_PER_HOUR", 2),
            instagram_proxy_url=os.getenv("INSTAGRAM_PROXY_URL", ""),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if self.app_env not in {"development", "experimental", "test", "production"}:
            raise ConfigError("APP_ENV must be development, experimental, test, or production")
        if self.mongodb_database != EXPECTED_MONGODB_DATABASE:
            raise ConfigError("MONGODB_DATABASE must be the dedicated Instagram experimental database")
        if self.mongodb_session_collection != EXPECTED_SESSION_COLLECTION:
            raise ConfigError("MONGODB_SESSION_COLLECTION must be the dedicated Instagram session collection")
        if self.mongodb_audit_collection != EXPECTED_AUDIT_COLLECTION:
            raise ConfigError("MONGODB_AUDIT_COLLECTION must be the dedicated Instagram audit collection")
        if self.mongodb_message_cache_collection != EXPECTED_MESSAGE_COLLECTION:
            raise ConfigError("MONGODB_MESSAGE_CACHE_COLLECTION must be the dedicated Instagram message collection")
        combined = " ".join(
            [
                self.mongodb_database,
                self.mongodb_session_collection,
                self.mongodb_audit_collection,
                self.mongodb_message_cache_collection,
                self.instagram_test_account_key,
            ]
        ).lower()
        if any(term in combined for term in FORBIDDEN_ENV_TERMS):
            raise ConfigError("Configuration must not reference Baileys or WhatsApp resources")
        if self.app_env != "test":
            if not self.internal_api_token or _looks_like_placeholder(self.internal_api_token):
                raise ConfigError("INTERNAL_API_TOKEN must be configured with a non-placeholder secret")
            if not self.session_encryption_key or _looks_like_placeholder(self.session_encryption_key):
                raise ConfigError("SESSION_ENCRYPTION_KEY must be configured with a non-placeholder Fernet key")
        if self.instagram_polling_enabled and not self.instagram_real_connection_enabled:
            raise ConfigError("Polling cannot be enabled while real Instagram connections are disabled")
