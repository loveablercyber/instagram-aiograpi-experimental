from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from io import StringIO
from typing import Any

from aiograpi import Client
from aiograpi.exceptions import (
    BadCredentials,
    BadPassword,
    CaptchaChallengeRequired,
    ChallengeRequired,
    ChallengeSelfieCaptcha,
    CheckpointRequired,
    ClientError,
    ClientLoginRequired,
    ClientThrottledError,
    ConsentRequired,
    FeedbackRequired,
    GeoBlockRequired,
    LoginRequired,
    PleaseWaitFewMinutes,
    SentryBlock,
    TwoFactorRequired,
)

from src.config import Settings
from src.services.audit import AuditService
from src.session_store import MemorySessionStore, MongoSessionStore


class RealConnectionDisabledError(RuntimeError):
    """Raised whenever code attempts to touch real Instagram APIs while disabled."""


class InstagramAuthError(RuntimeError):
    """Raised for authentication failures without exposing provider details."""


class InstagramChallengeRequiredError(RuntimeError):
    """Raised when Instagram requires an interactive challenge or 2FA code."""

    def __init__(self, challenge_type: str):
        super().__init__("Instagram challenge required")
        self.challenge_type = challenge_type


class InstagramRiskStopError(RuntimeError):
    """Raised when Instagram returns a high-risk state and testing should stop."""

    def __init__(self, reason: str):
        super().__init__("Instagram safety stop")
        self.reason = reason


class InstagramOperationError(RuntimeError):
    """Raised for non-auth Instagram operation failures."""


class _SilentLogger:
    def debug(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def info(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def warning(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def error(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def exception(self, *_args: Any, **_kwargs: Any) -> None:
        return None

    def critical(self, *_args: Any, **_kwargs: Any) -> None:
        return None


@dataclass
class PendingLogin:
    username: str
    password: str
    settings_payload: dict[str, Any]
    challenge_type: str
    created_at: datetime


class InstagramClientService:
    def __init__(
        self,
        settings: Settings,
        session_store: MongoSessionStore | MemorySessionStore,
        audit: AuditService,
        client_factory: Any = Client,
    ):
        self.settings = settings
        self.session_store = session_store
        self.audit = audit
        self._client_factory = client_factory
        self._client: Any | None = None
        self._pending_login: PendingLogin | None = None

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

    def _new_client(self, settings_payload: dict[str, Any] | None = None, challenge_code: str | None = None) -> Any:
        client = self._client_factory(
            settings=settings_payload or {},
            proxy=self.settings.instagram_proxy_url or None,
            logger=_SilentLogger(),
        )

        async def challenge_code_handler(_username: str, _choice: Any = None, **_kwargs: Any) -> str | None:
            return challenge_code or None

        client.challenge_code_handler = challenge_code_handler
        return client

    async def _run_silently(self, awaitable: Any) -> Any:
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            return await awaitable

    def _pending_login_valid(self) -> bool:
        if self._pending_login is None:
            return False
        return datetime.now(UTC) - self._pending_login.created_at < timedelta(minutes=10)

    def _set_pending_login(self, username: str, password: str, client: Any, challenge_type: str) -> None:
        self._pending_login = PendingLogin(
            username=username,
            password=password,
            settings_payload=client.get_settings(),
            challenge_type=challenge_type,
            created_at=datetime.now(UTC),
        )

    def _clear_pending_login(self) -> None:
        self._pending_login = None

    def _classify_challenge(self, exc: Exception) -> str:
        if isinstance(exc, TwoFactorRequired):
            return "two_factor_required"
        if isinstance(exc, CaptchaChallengeRequired):
            return "captcha_required"
        if isinstance(exc, ChallengeSelfieCaptcha):
            return "selfie_captcha_required"
        if isinstance(exc, CheckpointRequired):
            return "checkpoint_required"
        return "challenge_required"

    def _raise_safe_provider_error(self, exc: Exception) -> None:
        if isinstance(exc, (TwoFactorRequired, ChallengeRequired)):
            raise InstagramChallengeRequiredError(self._classify_challenge(exc)) from exc
        if isinstance(exc, (CaptchaChallengeRequired, ChallengeSelfieCaptcha, CheckpointRequired)):
            raise InstagramRiskStopError(self._classify_challenge(exc)) from exc
        if isinstance(exc, (PleaseWaitFewMinutes, ClientThrottledError, FeedbackRequired, SentryBlock)):
            raise InstagramRiskStopError("rate_or_abuse_protection") from exc
        if isinstance(exc, (ConsentRequired, GeoBlockRequired)):
            raise InstagramRiskStopError("manual_account_action_required") from exc
        if isinstance(exc, (BadCredentials, BadPassword)):
            raise InstagramAuthError("Invalid Instagram credentials") from exc
        if isinstance(exc, (ClientLoginRequired, LoginRequired)):
            raise InstagramAuthError("Stored Instagram session is invalid") from exc
        if isinstance(exc, ClientError):
            raise InstagramOperationError("Instagram client operation failed") from exc
        raise InstagramOperationError("Instagram operation failed") from exc

    async def validate_session_future(self, account_key: str) -> bool:
        await self._block_real_connection("validate_session")
        settings_payload = await self.load_session_from_store(account_key)
        if not settings_payload:
            return False
        client = self._new_client(settings_payload=settings_payload)
        try:
            await self._run_silently(client.account_info())
            await self.save_session_to_store(account_key, client.get_settings())
            self._client = client
            await self.audit.record("INSTAGRAM_SESSION_VALIDATED", account_key=account_key)
            return True
        except Exception as exc:
            await self.audit.record("INSTAGRAM_SESSION_INVALID", account_key=account_key)
            self._raise_safe_provider_error(exc)
        return False

    async def login_future(self, username: str, password: str, challenge_data: dict[str, Any] | None = None) -> bool:
        await self._block_real_connection("login")
        if not username or not password:
            raise InstagramAuthError("Instagram username and password are required")
        challenge_data = challenge_data or {}
        verification_code = challenge_data.get("verificationCode") or challenge_data.get("code") or ""
        settings_payload = challenge_data.get("settingsPayload")
        client = self._new_client(settings_payload=settings_payload, challenge_code=verification_code)
        try:
            logged_in = await self._run_silently(
                client.login(username=username, password=password, verification_code=verification_code)
            )
        except (TwoFactorRequired, ChallengeRequired) as exc:
            challenge_type = self._classify_challenge(exc)
            self._set_pending_login(username, password, client, challenge_type)
            await self.audit.record(
                "INSTAGRAM_LOGIN_CHALLENGE_REQUIRED",
                account_key=self.settings.instagram_test_account_key,
                metadata={"challengeType": challenge_type},
            )
            raise InstagramChallengeRequiredError(challenge_type) from exc
        except Exception as exc:
            self._clear_pending_login()
            await self.audit.record("INSTAGRAM_LOGIN_FAILED", account_key=self.settings.instagram_test_account_key)
            self._raise_safe_provider_error(exc)
        if not logged_in:
            await self.audit.record("INSTAGRAM_LOGIN_FAILED", account_key=self.settings.instagram_test_account_key)
            raise InstagramAuthError("Instagram login was not accepted")
        await self.save_session_to_store(self.settings.instagram_test_account_key, client.get_settings())
        self._client = client
        self._clear_pending_login()
        await self.audit.record("INSTAGRAM_LOGIN_SUCCEEDED", account_key=self.settings.instagram_test_account_key)
        return True

    async def resolve_challenge_future(
        self,
        code: str,
        username: str | None = None,
        password: str | None = None,
    ) -> bool:
        await self._block_real_connection("challenge_resolve")
        if not code:
            raise InstagramChallengeRequiredError("code_required")
        if username and password:
            return await self.login_future(username, password, {"verificationCode": code, "code": code})
        if not self._pending_login_valid() or self._pending_login is None:
            raise InstagramChallengeRequiredError("pending_login_not_available")
        pending = self._pending_login
        self._clear_pending_login()
        return await self.login_future(
            pending.username,
            pending.password,
            {
                "verificationCode": code,
                "code": code,
                "settingsPayload": pending.settings_payload,
            },
        )

    async def _authenticated_client(self) -> Any:
        settings_payload = await self.load_session_from_store(self.settings.instagram_test_account_key)
        if not settings_payload:
            raise InstagramAuthError("No stored Instagram session")
        client = self._new_client(settings_payload=settings_payload)
        return client

    async def list_threads_future(self, amount: int = 20) -> list[dict[str, Any]]:
        await self._block_real_connection("list_threads")
        amount = max(1, min(amount, 5))
        client = await self._authenticated_client()
        try:
            threads = await self._run_silently(client.direct_threads(amount=amount, thread_message_limit=1))
            await self.save_session_to_store(self.settings.instagram_test_account_key, client.get_settings())
            self._client = client
            await self.audit.record(
                "INSTAGRAM_THREADS_LISTED",
                account_key=self.settings.instagram_test_account_key,
                metadata={"amount": len(threads)},
            )
            return [_serialize_thread(thread) for thread in threads[:amount]]
        except Exception as exc:
            self._raise_safe_provider_error(exc)

    async def list_messages_future(self, thread_id: str, amount: int = 20) -> list[dict[str, Any]]:
        await self._block_real_connection("list_messages")
        amount = max(1, min(amount, self.settings.instagram_max_messages_per_fetch, 10))
        client = await self._authenticated_client()
        try:
            messages = await self._run_silently(client.direct_messages(thread_id, amount=amount))
            await self.save_session_to_store(self.settings.instagram_test_account_key, client.get_settings())
            self._client = client
            await self.audit.record(
                "INSTAGRAM_MESSAGES_LISTED",
                account_key=self.settings.instagram_test_account_key,
                metadata={"amount": len(messages)},
            )
            return [_serialize_message(message) for message in messages[:amount]]
        except Exception as exc:
            self._raise_safe_provider_error(exc)

    async def send_text_future(self, thread_id: str, text: str) -> dict[str, Any]:
        await self._block_real_connection("send_text")
        if not text or not text.strip():
            raise InstagramOperationError("Message text is required")
        client = await self._authenticated_client()
        try:
            message = await self._run_silently(client.direct_send(text.strip(), thread_ids=[thread_id]))
            await self.save_session_to_store(self.settings.instagram_test_account_key, client.get_settings())
            self._client = client
            await self.audit.record("INSTAGRAM_TEXT_SENT", account_key=self.settings.instagram_test_account_key)
            return _serialize_message(message)
        except Exception as exc:
            self._raise_safe_provider_error(exc)

    async def logout_future(self, account_key: str) -> bool:
        await self._block_real_connection("logout")
        settings_payload = await self.load_session_from_store(account_key)
        if settings_payload:
            client = self._new_client(settings_payload=settings_payload)
            try:
                await self._run_silently(client.logout())
            except Exception:
                pass
        removed = await self.delete_session_from_store(account_key)
        self._client = None
        self._clear_pending_login()
        await self.audit.record("INSTAGRAM_LOGOUT_COMPLETED", account_key=account_key)
        return removed


def _model_value(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _safe_iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    if value is None:
        return None
    return str(value)


def _serialize_user(user: Any) -> dict[str, Any]:
    return {
        "id": str(_model_value(user, "pk", "")),
        "username": _model_value(user, "username", ""),
        "fullName": _model_value(user, "full_name", ""),
    }


def _serialize_message(message: Any) -> dict[str, Any]:
    return {
        "id": str(_model_value(message, "id", "")),
        "threadId": str(_model_value(message, "thread_id", "")),
        "userId": str(_model_value(message, "user_id", "")),
        "timestamp": _safe_iso(_model_value(message, "timestamp")),
        "itemType": _model_value(message, "item_type", ""),
        "isSentByViewer": bool(_model_value(message, "is_sent_by_viewer", False)),
        "text": _model_value(message, "text", None),
    }


def _serialize_thread(thread: Any) -> dict[str, Any]:
    messages = list(_model_value(thread, "messages", []) or [])
    users = list(_model_value(thread, "users", []) or [])
    return {
        "threadId": str(_model_value(thread, "id", _model_value(thread, "pk", ""))),
        "threadTitle": _model_value(thread, "thread_title", ""),
        "isGroup": bool(_model_value(thread, "is_group", False)),
        "lastActivityAt": _safe_iso(_model_value(thread, "last_activity_at")),
        "users": [_serialize_user(user) for user in users[:5]],
        "lastMessage": _serialize_message(messages[0]) if messages else None,
    }
