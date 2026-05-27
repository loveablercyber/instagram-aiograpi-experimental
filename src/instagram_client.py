from __future__ import annotations

from typing import Any

from src.config import Settings
from src.services.audit import AuditService
from src.session_store import MemorySessionStore, MongoSessionStore


class RealConnectionDisabledError(RuntimeError):
    """Raised whenever Phase 1 code attempts to touch real Instagram APIs."""


class InstagramClientService:
    def __init__(
        self,
        settings: Settings,
        session_store: MongoSessionStore | MemorySessionStore,
        audit: AuditService,
    ):
        self.settings = settings
        self.session_store = session_store
        self.audit = audit

    async def load_session_from_store(self, account_key: str) -> dict[str, Any] | None:
        return await self.session_store.restore_settings(account_key)

    async def save_session_to_store(self, account_key: str, settings_payload: dict[str, Any]) -> None:
        await self.session_store.save_settings(account_key, settings_payload)

    async def delete_session_from_store(self, account_key: str) -> bool:
        return await self.session_store.delete_session(account_key)

    async def _block_real_connection(self, operation: str) -> None:
        if not self.settings.instagram_real_connection_enabled:
            await self.audit.record(
                "REAL_CONNECTION_BLOCKED",
                account_key=self.settings.instagram_test_account_key,
                metadata={"operation": operation},
            )
            raise RealConnectionDisabledError("Real Instagram connection is disabled for Phase 1")

    async def validate_session_future(self, account_key: str) -> bool:
        await self._block_real_connection("validate_session")
        raise NotImplementedError("Real Instagram validation is not implemented in Phase 1")

    async def login_future(self, username: str, password: str, challenge_data: dict[str, Any] | None = None) -> bool:
        await self._block_real_connection("login")
        raise NotImplementedError("Real Instagram login is not implemented in Phase 1")

    async def list_threads_future(self, amount: int = 20) -> list[dict[str, Any]]:
        await self._block_real_connection("list_threads")
        raise NotImplementedError("Real Direct reads are not implemented in Phase 1")

    async def list_messages_future(self, thread_id: str, amount: int = 20) -> list[dict[str, Any]]:
        await self._block_real_connection("list_messages")
        raise NotImplementedError("Real Direct reads are not implemented in Phase 1")

    async def send_text_future(self, thread_id: str, text: str) -> dict[str, Any]:
        await self._block_real_connection("send_text")
        raise NotImplementedError("Real Direct sends are not implemented in Phase 1")

    async def logout_future(self, account_key: str) -> bool:
        await self._block_real_connection("logout")
        raise NotImplementedError("Real Instagram logout is not implemented in Phase 1")
