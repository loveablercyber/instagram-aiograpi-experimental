from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from src.config import Settings
from src.security.encryption import EncryptionService

try:
    from pymongo import ASCENDING, AsyncMongoClient, ReturnDocument
except Exception:  # pragma: no cover - dependency is required in runtime image.
    ASCENDING = 1
    AsyncMongoClient = None
    ReturnDocument = None


class SessionStoreError(RuntimeError):
    """Raised when session persistence cannot complete safely."""


def _verification_context_key(account_key: str) -> str:
    return f"{account_key}:verification"


class MongoSessionStore:
    def __init__(self, settings: Settings, encryption: EncryptionService, client: Any | None = None):
        self.settings = settings
        self.encryption = encryption
        self._client = client

    def _ensure_client(self) -> Any:
        if self._client is not None:
            return self._client
        if not self.settings.mongodb_uri:
            raise SessionStoreError("MongoDB URI is not configured")
        if AsyncMongoClient is None:
            raise SessionStoreError("PyMongo async client is unavailable")
        self._client = AsyncMongoClient(
            self.settings.mongodb_uri,
            serverSelectionTimeoutMS=5000,
            uuidRepresentation="standard",
        )
        return self._client

    def session_collection(self) -> Any:
        client = self._ensure_client()
        return client[self.settings.mongodb_database][self.settings.mongodb_session_collection]

    def audit_collection(self) -> Any:
        client = self._ensure_client()
        return client[self.settings.mongodb_database][self.settings.mongodb_audit_collection]

    def message_collection(self) -> Any:
        client = self._ensure_client()
        return client[self.settings.mongodb_database][self.settings.mongodb_message_cache_collection]

    async def ping(self) -> bool:
        try:
            client = self._ensure_client()
            await client.admin.command("ping")
            return True
        except Exception:
            return False

    async def ensure_indexes(self) -> None:
        collection = self.session_collection()
        await collection.create_index([("accountKey", ASCENDING)], unique=True, name="unique_account_key")
        await collection.create_index([("expiresAt", ASCENDING)], expireAfterSeconds=0, name="verification_expires_at")
        await self.audit_collection().create_index([("createdAt", ASCENDING)], name="audit_created_at")
        await self.audit_collection().create_index(
            [("event", ASCENDING), ("accountKey", ASCENDING), ("createdAt", ASCENDING)],
            name="audit_event_account_created_at",
        )
        await self.message_collection().create_index(
            [("accountKey", ASCENDING), ("messageId", ASCENDING)],
            unique=True,
            name="unique_account_message",
        )

    async def save_settings(
        self,
        account_key: str,
        settings_payload: dict[str, Any],
        *,
        status: str = "stored",
    ) -> None:
        encrypted = self.encryption.encrypt_json(settings_payload)
        now = datetime.now(UTC)
        document = {
            "accountKey": account_key,
            "encryptedSettings": encrypted,
            "encryptionVersion": "v1",
            "library": "aiograpi",
            "libraryVersion": "1.0.9",
            "status": status,
            "updatedAt": now,
            "lastValidationAt": None,
            "lastChallengeType": None,
            "lastErrorCode": None,
        }
        await self.session_collection().update_one(
            {"accountKey": account_key},
            {"$set": document, "$setOnInsert": {"createdAt": now}},
            upsert=True,
        )

    async def restore_settings(self, account_key: str) -> dict[str, Any] | None:
        document = await self.session_collection().find_one({"accountKey": account_key})
        if not document:
            return None
        encrypted = document.get("encryptedSettings")
        if not encrypted:
            return None
        return self.encryption.decrypt_json(encrypted)

    async def session_exists(self, account_key: str) -> bool:
        document = await self.session_collection().find_one({"accountKey": account_key}, {"_id": 1})
        return document is not None

    async def delete_session(self, account_key: str) -> bool:
        result = await self.session_collection().delete_one({"accountKey": account_key})
        return result.deleted_count > 0

    async def save_verification_context(
        self,
        account_key: str,
        context_payload: dict[str, Any],
        *,
        challenge_type: str,
        expires_at: datetime,
    ) -> None:
        encrypted = self.encryption.encrypt_json(context_payload)
        now = datetime.now(UTC)
        await self.session_collection().update_one(
            {"accountKey": _verification_context_key(account_key)},
            {
                "$set": {
                    "accountKey": _verification_context_key(account_key),
                    "encryptedSettings": encrypted,
                    "encryptionVersion": "v1",
                    "library": "aiograpi",
                    "libraryVersion": "1.0.9",
                    "status": "pending_verification",
                    "challengeType": challenge_type,
                    "attempts": 0,
                    "updatedAt": now,
                    "expiresAt": expires_at,
                    "lastValidationAt": None,
                    "lastChallengeType": challenge_type,
                    "lastErrorCode": None,
                },
                "$setOnInsert": {"createdAt": now},
            },
            upsert=True,
        )

    async def restore_verification_context(self, account_key: str) -> dict[str, Any] | None:
        document = await self.session_collection().find_one({"accountKey": _verification_context_key(account_key)})
        if not document:
            return None
        expires_at = document.get("expiresAt")
        if isinstance(expires_at, datetime) and expires_at.replace(tzinfo=UTC) <= datetime.now(UTC):
            await self.delete_verification_context(account_key)
            return None
        encrypted = document.get("encryptedSettings")
        if not encrypted:
            return None
        payload = self.encryption.decrypt_json(encrypted)
        payload["challengeType"] = document.get("challengeType")
        return payload

    async def record_verification_attempt(self, account_key: str, *, max_attempts: int = 2) -> int:
        document = await self.session_collection().find_one_and_update(
            {"accountKey": _verification_context_key(account_key), "attempts": {"$lt": max_attempts}},
            {"$inc": {"attempts": 1}, "$set": {"updatedAt": datetime.now(UTC)}},
            return_document=ReturnDocument.AFTER,
        )
        if not document:
            raise SessionStoreError("Verification attempt limit exceeded or context unavailable")
        return int(document.get("attempts", 0))

    async def delete_verification_context(self, account_key: str) -> bool:
        result = await self.session_collection().delete_one({"accountKey": _verification_context_key(account_key)})
        return result.deleted_count > 0

    async def save_auth_attempt(self, account_key: str, diagnostic: dict[str, Any]) -> None:
        now = datetime.now(UTC)
        await self.audit_collection().insert_one(
            {
                "event": "AUTH_ATTEMPT_DIAGNOSTIC",
                "accountKey": account_key,
                "diagnostic": diagnostic,
                "createdAt": now,
            }
        )

    async def latest_auth_attempt(self, account_key: str) -> dict[str, Any] | None:
        document = await self.audit_collection().find_one(
            {
                "event": "AUTH_ATTEMPT_DIAGNOSTIC",
                "accountKey": account_key,
                "diagnostic": {"$exists": True},
            },
            sort=[("createdAt", -1)],
            projection={"_id": 0},
        )
        if not document:
            return None
        diagnostic = document.get("diagnostic")
        return diagnostic if isinstance(diagnostic, dict) else None

    async def save_account_preflight(self, account_key: str, preflight: dict[str, Any]) -> None:
        await self.audit_collection().insert_one(
            {
                "event": "ACCOUNT_PREFLIGHT_CHECKED",
                "accountKey": account_key,
                "preflight": preflight,
                "createdAt": datetime.now(UTC),
            }
        )

    async def latest_account_preflight(self, account_key: str) -> dict[str, Any] | None:
        document = await self.audit_collection().find_one(
            {
                "event": "ACCOUNT_PREFLIGHT_CHECKED",
                "accountKey": account_key,
                "preflight": {"$exists": True},
            },
            sort=[("createdAt", -1)],
            projection={"_id": 0},
        )
        if not document:
            return None
        preflight = document.get("preflight")
        return preflight if isinstance(preflight, dict) else None

    async def raw_document_for_tests(self, account_key: str) -> dict[str, Any] | None:
        return await self.session_collection().find_one({"accountKey": account_key})

    async def close(self) -> None:
        if self._client is not None and hasattr(self._client, "close"):
            maybe_awaitable = self._client.close()
            if hasattr(maybe_awaitable, "__await__"):
                await maybe_awaitable
            self._client = None


class MemorySessionStore:
    def __init__(self, settings: Settings, encryption: EncryptionService):
        self.settings = settings
        self.encryption = encryption
        self.documents: dict[str, dict[str, Any]] = {}
        self.audit_documents: list[dict[str, Any]] = []
        self.message_documents: list[dict[str, Any]] = []
        self.auth_attempt_documents: list[dict[str, Any]] = []
        self.account_preflight_documents: list[dict[str, Any]] = []
        self.connected = True

    async def ping(self) -> bool:
        return self.connected

    async def ensure_indexes(self) -> None:
        return None

    async def save_settings(
        self,
        account_key: str,
        settings_payload: dict[str, Any],
        *,
        status: str = "stored",
    ) -> None:
        encrypted = self.encryption.encrypt_json(settings_payload)
        now = datetime.now(UTC)
        existing = self.documents.get(account_key, {})
        self.documents[account_key] = {
            "accountKey": account_key,
            "encryptedSettings": encrypted,
            "encryptionVersion": "v1",
            "library": "aiograpi",
            "libraryVersion": "1.0.9",
            "status": status,
            "createdAt": existing.get("createdAt", now),
            "updatedAt": now,
            "lastValidationAt": None,
            "lastChallengeType": None,
            "lastErrorCode": None,
        }

    async def restore_settings(self, account_key: str) -> dict[str, Any] | None:
        document = self.documents.get(account_key)
        if not document:
            return None
        return self.encryption.decrypt_json(document["encryptedSettings"])

    async def session_exists(self, account_key: str) -> bool:
        return account_key in self.documents

    async def delete_session(self, account_key: str) -> bool:
        return self.documents.pop(account_key, None) is not None

    async def save_verification_context(
        self,
        account_key: str,
        context_payload: dict[str, Any],
        *,
        challenge_type: str,
        expires_at: datetime,
    ) -> None:
        encrypted = self.encryption.encrypt_json(context_payload)
        now = datetime.now(UTC)
        existing = self.documents.get(_verification_context_key(account_key), {})
        self.documents[_verification_context_key(account_key)] = {
            "accountKey": _verification_context_key(account_key),
            "encryptedSettings": encrypted,
            "encryptionVersion": "v1",
            "library": "aiograpi",
            "libraryVersion": "1.0.9",
            "status": "pending_verification",
            "challengeType": challenge_type,
            "attempts": 0,
            "createdAt": existing.get("createdAt", now),
            "updatedAt": now,
            "expiresAt": expires_at,
            "lastValidationAt": None,
            "lastChallengeType": challenge_type,
            "lastErrorCode": None,
        }

    async def restore_verification_context(self, account_key: str) -> dict[str, Any] | None:
        document = self.documents.get(_verification_context_key(account_key))
        if not document:
            return None
        expires_at = document.get("expiresAt")
        if isinstance(expires_at, datetime) and expires_at <= datetime.now(UTC):
            await self.delete_verification_context(account_key)
            return None
        payload = self.encryption.decrypt_json(document["encryptedSettings"])
        payload["challengeType"] = document.get("challengeType")
        return payload

    async def record_verification_attempt(self, account_key: str, *, max_attempts: int = 2) -> int:
        key = _verification_context_key(account_key)
        document = self.documents.get(key)
        if not document or document.get("attempts", 0) >= max_attempts:
            raise SessionStoreError("Verification attempt limit exceeded or context unavailable")
        document["attempts"] = int(document.get("attempts", 0)) + 1
        document["updatedAt"] = datetime.now(UTC)
        return document["attempts"]

    async def delete_verification_context(self, account_key: str) -> bool:
        return self.documents.pop(_verification_context_key(account_key), None) is not None

    async def save_auth_attempt(self, account_key: str, diagnostic: dict[str, Any]) -> None:
        self.auth_attempt_documents.append(
            {
                "event": "AUTH_ATTEMPT_DIAGNOSTIC",
                "accountKey": account_key,
                "diagnostic": diagnostic,
                "createdAt": datetime.now(UTC),
            }
        )

    async def latest_auth_attempt(self, account_key: str) -> dict[str, Any] | None:
        for document in reversed(self.auth_attempt_documents):
            if document.get("accountKey") == account_key:
                diagnostic = document.get("diagnostic")
                return diagnostic if isinstance(diagnostic, dict) else None
        return None

    async def save_account_preflight(self, account_key: str, preflight: dict[str, Any]) -> None:
        self.account_preflight_documents.append(
            {
                "event": "ACCOUNT_PREFLIGHT_CHECKED",
                "accountKey": account_key,
                "preflight": preflight,
                "createdAt": datetime.now(UTC),
            }
        )

    async def latest_account_preflight(self, account_key: str) -> dict[str, Any] | None:
        for document in reversed(self.account_preflight_documents):
            if document.get("accountKey") == account_key:
                preflight = document.get("preflight")
                return preflight if isinstance(preflight, dict) else None
        return None

    async def raw_document_for_tests(self, account_key: str) -> dict[str, Any] | None:
        return self.documents.get(account_key)

    async def close(self) -> None:
        return None
