from __future__ import annotations

from src.config import Settings
from src.services.audit import AuditService


class PollingService:
    def __init__(self, settings: Settings, audit: AuditService, session_store=None):
        self.settings = settings
        self.audit = audit
        self.session_store = session_store
        self.started = False

    async def start(self) -> bool:
        if not self.settings.instagram_polling_enabled:
            await self.audit.record(
                "POLLING_BLOCKED",
                account_key=self.settings.instagram_test_account_key,
                metadata={"reason": "disabled_by_configuration"},
            )
            self.started = False
            return False
        if not self.settings.instagram_real_connection_enabled:
            await self.audit.record(
                "POLLING_BLOCKED",
                account_key=self.settings.instagram_test_account_key,
                metadata={"reason": "real_connection_disabled"},
            )
            self.started = False
            return False
        if self.session_store is None or not await self.session_store.session_exists(
            self.settings.instagram_test_account_key
        ):
            await self.audit.record(
                "POLLING_BLOCKED",
                account_key=self.settings.instagram_test_account_key,
                metadata={"reason": "no_valid_stored_session"},
            )
            self.started = False
            return False
        self.started = False
        await self.audit.record(
            "POLLING_BLOCKED",
            account_key=self.settings.instagram_test_account_key,
            metadata={"reason": "requires_explicit_session_validation_before_start"},
        )
        return False
