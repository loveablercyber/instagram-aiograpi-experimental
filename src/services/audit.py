from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Callable


SAFE_EVENTS = {
    "SERVICE_STARTED",
    "MONGODB_CONNECTED",
    "MONGODB_CONNECTION_FAILED",
    "SESSION_TEST_STORED",
    "SESSION_TEST_RESTORED",
    "SESSION_REMOVED",
    "UNAUTHORIZED_REQUEST_BLOCKED",
    "REAL_CONNECTION_BLOCKED",
    "POLLING_BLOCKED",
    "INSTAGRAM_LOGIN_SUCCEEDED",
    "INSTAGRAM_LOGIN_CHALLENGE_REQUIRED",
    "INSTAGRAM_LOGIN_FAILED",
    "INSTAGRAM_SESSION_VALIDATED",
    "INSTAGRAM_SESSION_INVALID",
    "INSTAGRAM_THREADS_LISTED",
    "INSTAGRAM_MESSAGES_LISTED",
    "INSTAGRAM_TEXT_SENT",
    "INSTAGRAM_LOGOUT_COMPLETED",
    "RATE_LIMIT_BLOCKED",
    "LOGIN_ATTEMPT_STARTED",
    "LOGIN_SUCCEEDED",
    "LOGIN_TWO_FACTOR_REQUIRED",
    "LOGIN_CHALLENGE_REQUIRED",
    "LOGIN_CHECKPOINT_REQUIRED",
    "LOGIN_BAD_PASSWORD_OR_CONTEXT_REJECTED",
    "LOGIN_FEEDBACK_REQUIRED",
    "LOGIN_CONSENT_REQUIRED",
    "LOGIN_GEOBLOCK_REQUIRED",
    "LOGIN_UNCLASSIFIED_FAILURE",
    "LOGIN_BLOCKED_BY_AUTH_GUARD",
    "CHALLENGE_CONTEXT_STORED",
    "CHALLENGE_CONTEXT_NOT_PERSISTABLE",
    "VERIFICATION_CODE_SUBMITTED",
    "VERIFICATION_SUCCEEDED",
    "VERIFICATION_FAILED",
    "VERIFICATION_RATE_LIMITED",
    "REAL_SESSION_ENCRYPTED_AND_STORED",
    "AUTH_ATTEMPT_DIAGNOSTIC",
}

SENSITIVE_KEY_PARTS = (
    "password",
    "token",
    "secret",
    "cookie",
    "session",
    "settings",
    "authorization",
    "credential",
    "mongodb_uri",
    "uri",
    "encryption",
)


def _safe_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    if not metadata:
        return {}
    safe: dict[str, Any] = {}
    for key, value in metadata.items():
        lowered = key.lower()
        if isinstance(value, bool):
            safe[key] = value
        elif any(part in lowered for part in SENSITIVE_KEY_PARTS):
            safe[key] = "[REDACTED]"
        elif isinstance(value, (str, int, float, bool)) or value is None:
            safe[key] = value
        else:
            safe[key] = str(type(value).__name__)
    return safe


class AuditService:
    def __init__(self, collection_provider: Callable[[], Any] | None = None):
        self._collection_provider = collection_provider
        self.memory_events: list[dict[str, Any]] = []

    async def record(
        self,
        event: str,
        *,
        account_key: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        safe_event = event if event in SAFE_EVENTS else "REAL_CONNECTION_BLOCKED"
        document = {
            "event": safe_event,
            "accountKey": account_key,
            "metadata": _safe_metadata(metadata),
            "createdAt": datetime.now(UTC),
        }
        self.memory_events.append(document)
        if self._collection_provider is None:
            return
        try:
            collection = self._collection_provider()
            await collection.insert_one(document)
        except Exception:
            # Audit persistence must never leak secrets or break health/status endpoints.
            return
