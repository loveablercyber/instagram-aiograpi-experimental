from __future__ import annotations

from src.config import Settings
from src.services.audit import AuditService


class PollingService:
    def __init__(self, settings: Settings, audit: AuditService):
        self.settings = settings
        self.audit = audit
        self.started = False

    async def start(self) -> bool:
        if not self.settings.instagram_polling_enabled or not self.settings.instagram_real_connection_enabled:
            await self.audit.record(
                "POLLING_BLOCKED",
                account_key=self.settings.instagram_test_account_key,
                metadata={"reason": "disabled_by_configuration"},
            )
            self.started = False
            return False
        self.started = False
        await self.audit.record(
            "POLLING_BLOCKED",
            account_key=self.settings.instagram_test_account_key,
            metadata={"reason": "not_implemented_in_phase_1"},
        )
        return False
