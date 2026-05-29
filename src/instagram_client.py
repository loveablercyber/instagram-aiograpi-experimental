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
    ChallengeRedirection,
    ChallengeRequired,
    ChallengeSelfieCaptcha,
    ChallengeUnknownStep,
    CheckpointRequired,
    ClientConnectionError,
    ClientError,
    ClientForbiddenError,
    ClientLoginRequired,
    ClientRequestTimeout,
    ClientThrottledError,
    ClientUnauthorizedError,
    ConsentRequired,
    FeedbackRequired,
    GeoBlockRequired,
    LegacyForceSetNewPasswordForm,
    LoginRequired,
    PleaseWaitFewMinutes,
    RateLimitError,
    RecaptchaChallengeForm,
    SelectContactPointRecoveryForm,
    SentryBlock,
    SubmitPhoneNumberForm,
    TwoFactorRequired,
    UnknownError,
)

from src.auth_diagnostics import (
    InstagramAuthDiagnosticResult,
    diagnostic_from_exception,
    diagnostic_success,
    new_attempt_id,
    redact_diagnostic,
    utc_now_iso,
)
from src.config import Settings
from src.services.audit import AuditService
from src.session_store import MemorySessionStore, MongoSessionStore, SessionStoreError


class RealConnectionDisabledError(RuntimeError):
    """Raised whenever code attempts to touch real Instagram APIs while disabled."""


class InstagramAuthError(RuntimeError):
    """Raised for authentication failures without exposing provider details."""


@dataclass(frozen=True)
class InstagramAuthResult:
    status: str
    session_stored: bool = False
    verification_type: str | None = None
    challenge_method: str | None = None
    reason: str | None = None
    next_action: str = "do_not_retry_automatically"

    def to_response(self) -> dict[str, Any]:
        response: dict[str, Any] = {
            "status": self.status,
            "nextAction": self.next_action,
        }
        if self.session_stored:
            response["sessionStored"] = True
        if self.verification_type:
            response["verificationType"] = self.verification_type
        if self.challenge_method:
            response["challengeMethod"] = self.challenge_method
        if self.reason:
            response["reason"] = self.reason
        return response


class InstagramAuthFlowError(RuntimeError):
    """Raised when login completes with a safe, actionable non-success status."""

    def __init__(self, result: InstagramAuthResult):
        super().__init__(result.status)
        self.result = result


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
class PendingVerificationContext:
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
        self._pending_context: PendingVerificationContext | None = None

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
            raise RealConnectionDisabledError("Real Instagram connection is disabled")

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

    def _pending_context_valid(self) -> bool:
        if self._pending_context is None:
            return False
        return datetime.now(UTC) - self._pending_context.created_at < timedelta(minutes=10)

    async def _set_pending_context(self, client: Any, challenge_type: str) -> None:
        context = {
            "settingsPayload": client.get_settings(),
            "createdAt": datetime.now(UTC).isoformat(),
        }
        expires_at = datetime.now(UTC) + timedelta(minutes=10)
        try:
            await self.session_store.save_verification_context(
                self.settings.instagram_test_account_key,
                context,
                challenge_type=challenge_type,
                expires_at=expires_at,
            )
            await self.audit.record("CHALLENGE_CONTEXT_STORED", account_key=self.settings.instagram_test_account_key)
        except Exception:
            await self.audit.record(
                "CHALLENGE_CONTEXT_NOT_PERSISTABLE",
                account_key=self.settings.instagram_test_account_key,
            )
        self._pending_context = PendingVerificationContext(
            settings_payload=client.get_settings(),
            challenge_type=challenge_type,
            created_at=datetime.now(UTC),
        )

    async def _load_pending_context(self) -> dict[str, Any] | None:
        context = await self.session_store.restore_verification_context(self.settings.instagram_test_account_key)
        if context:
            return context
        if self._pending_context_valid() and self._pending_context is not None:
            return {
                "settingsPayload": self._pending_context.settings_payload,
                "challengeType": self._pending_context.challenge_type,
            }
        return None

    async def _clear_pending_context(self) -> None:
        self._pending_context = None
        try:
            await self.session_store.delete_verification_context(self.settings.instagram_test_account_key)
        except Exception:
            return None

    async def latest_auth_attempt(self) -> dict[str, Any] | None:
        return await self.session_store.latest_auth_attempt(self.settings.instagram_test_account_key)

    async def _save_auth_diagnostic(self, diagnostic: InstagramAuthDiagnosticResult) -> None:
        await self.session_store.save_auth_attempt(
            self.settings.instagram_test_account_key,
            diagnostic.to_public_dict(),
        )
        await self.audit.record(
            "AUTH_ATTEMPT_DIAGNOSTIC",
            account_key=self.settings.instagram_test_account_key,
            metadata={
                "attemptId": diagnostic.attempt_id,
                "status": diagnostic.status,
                "exceptionClass": diagnostic.exception_class,
                "httpStatus": diagnostic.http_status,
                "hasChallengeContext": diagnostic.has_challenge_context,
                "hasTwoFactorIdentifier": diagnostic.has_two_factor_identifier,
                "hasCheckpointUrl": diagnostic.has_checkpoint_url,
            },
        )

    async def blocked_auth_diagnostic(self, reason: str) -> InstagramAuthDiagnosticResult:
        diagnostic = InstagramAuthDiagnosticResult.blocked(reason)
        await self.audit.record(
            "LOGIN_BLOCKED_BY_AUTH_GUARD",
            account_key=self.settings.instagram_test_account_key,
            metadata={"attemptId": diagnostic.attempt_id, "reason": reason},
        )
        await self._save_auth_diagnostic(diagnostic)
        return diagnostic

    def _classify_challenge(self, exc: Exception) -> str:
        if isinstance(exc, TwoFactorRequired):
            return "two_factor"
        if isinstance(exc, CaptchaChallengeRequired):
            return "captcha"
        if isinstance(exc, ChallengeSelfieCaptcha):
            return "selfie_captcha"
        if isinstance(exc, CheckpointRequired):
            return "checkpoint"
        if isinstance(exc, SelectContactPointRecoveryForm):
            return "select_contact_point"
        if isinstance(exc, SubmitPhoneNumberForm):
            return "submit_phone_number"
        if isinstance(exc, RecaptchaChallengeForm):
            return "recaptcha"
        if isinstance(exc, ChallengeUnknownStep):
            return "unknown_step"
        return "challenge"

    def _result_for_exception(self, exc: Exception) -> tuple[InstagramAuthResult, str]:
        if isinstance(exc, TwoFactorRequired):
            return (
                InstagramAuthResult(
                    status="verification_required",
                    verification_type="two_factor",
                    next_action="submit_verification_code",
                ),
                "LOGIN_TWO_FACTOR_REQUIRED",
            )
        if isinstance(exc, (ChallengeRequired, ChallengeRedirection, SelectContactPointRecoveryForm)):
            return (
                InstagramAuthResult(
                    status="verification_required",
                    verification_type="challenge",
                    challenge_method="email_or_sms_or_unknown",
                    next_action="submit_verification_code",
                ),
                "LOGIN_CHALLENGE_REQUIRED",
            )
        if isinstance(exc, (RecaptchaChallengeForm, SubmitPhoneNumberForm, ChallengeUnknownStep)):
            return (
                InstagramAuthResult(
                    status="manual_action_required",
                    reason="challenge_requires_manual_account_action",
                    next_action="check_instagram_app_or_email",
                ),
                "LOGIN_CHALLENGE_REQUIRED",
            )
        if isinstance(exc, (CheckpointRequired, ChallengeSelfieCaptcha, CaptchaChallengeRequired)):
            return (
                InstagramAuthResult(
                    status="manual_action_required",
                    reason="checkpoint_or_login_confirmation",
                    next_action="check_instagram_app_or_email",
                ),
                "LOGIN_CHECKPOINT_REQUIRED",
            )
        if isinstance(exc, LegacyForceSetNewPasswordForm):
            return (
                InstagramAuthResult(
                    status="manual_action_required",
                    reason="password_reset_required",
                    next_action="check_instagram_app_or_email",
                ),
                "LOGIN_CHECKPOINT_REQUIRED",
            )
        if isinstance(exc, (BadPassword, BadCredentials)):
            return (
                InstagramAuthResult(
                    status="authentication_rejected",
                    reason="credentials_or_login_context_rejected",
                    next_action="do_not_retry_automatically",
                ),
                "LOGIN_BAD_PASSWORD_OR_CONTEXT_REJECTED",
            )
        if isinstance(exc, (FeedbackRequired, PleaseWaitFewMinutes, ClientThrottledError, SentryBlock)):
            return (
                InstagramAuthResult(
                    status="manual_action_required",
                    reason="feedback_required_or_rate_limited",
                    next_action="do_not_retry_automatically",
                ),
                "LOGIN_FEEDBACK_REQUIRED",
            )
        if isinstance(exc, ConsentRequired):
            return (
                InstagramAuthResult(
                    status="manual_action_required",
                    reason="consent_required",
                    next_action="check_instagram_app_or_email",
                ),
                "LOGIN_CONSENT_REQUIRED",
            )
        if isinstance(exc, GeoBlockRequired):
            return (
                InstagramAuthResult(
                    status="manual_action_required",
                    reason="geoblock_required",
                    next_action="do_not_retry_automatically",
                ),
                "LOGIN_GEOBLOCK_REQUIRED",
            )
        return (
            InstagramAuthResult(
                status="authentication_failed_unclassified",
                reason="sanitized_unclassified_instagram_response",
                next_action="inspect_sanitized_server_log_before_retry",
            ),
            "LOGIN_UNCLASSIFIED_FAILURE",
        )

    def _diagnostic_for_exception(
        self,
        *,
        attempt_id: str,
        exc: Exception,
        client: Any,
    ) -> tuple[InstagramAuthDiagnosticResult, str]:
        if isinstance(exc, TwoFactorRequired):
            return (
                diagnostic_from_exception(
                    attempt_id=attempt_id,
                    status="two_factor_required",
                    safe_message="Instagram requires two-factor verification.",
                    exc=exc,
                    client=client,
                    requires_manual_action=True,
                    retry_allowed=False,
                    sensitive_values=(self.settings.instagram_username,),
                ),
                "LOGIN_TWO_FACTOR_REQUIRED",
            )
        if isinstance(exc, (ChallengeRequired, ChallengeRedirection, SelectContactPointRecoveryForm)):
            return (
                diagnostic_from_exception(
                    attempt_id=attempt_id,
                    status="challenge_required",
                    safe_message="Instagram requires a manual challenge step.",
                    exc=exc,
                    client=client,
                    requires_manual_action=True,
                    retry_allowed=False,
                    sensitive_values=(self.settings.instagram_username,),
                ),
                "LOGIN_CHALLENGE_REQUIRED",
            )
        if isinstance(
            exc,
            (
                CheckpointRequired,
                ChallengeSelfieCaptcha,
                CaptchaChallengeRequired,
                RecaptchaChallengeForm,
                SubmitPhoneNumberForm,
                ChallengeUnknownStep,
                LegacyForceSetNewPasswordForm,
            ),
        ):
            return (
                diagnostic_from_exception(
                    attempt_id=attempt_id,
                    status="checkpoint_required",
                    safe_message="Instagram requires manual account action before another login attempt.",
                    exc=exc,
                    client=client,
                    requires_manual_action=True,
                    retry_allowed=False,
                    sensitive_values=(self.settings.instagram_username,),
                ),
                "LOGIN_CHECKPOINT_REQUIRED",
            )
        if isinstance(exc, (BadPassword, BadCredentials)):
            return (
                diagnostic_from_exception(
                    attempt_id=attempt_id,
                    status="invalid_credentials",
                    safe_message="Instagram rejected the credentials or login context.",
                    exc=exc,
                    client=client,
                    requires_manual_action=True,
                    retry_allowed=False,
                    sensitive_values=(self.settings.instagram_username,),
                ),
                "LOGIN_BAD_PASSWORD_OR_CONTEXT_REJECTED",
            )
        if isinstance(
            exc,
            (
                FeedbackRequired,
                PleaseWaitFewMinutes,
                ClientForbiddenError,
                ClientThrottledError,
                SentryBlock,
                RateLimitError,
                ClientUnauthorizedError,
                ClientLoginRequired,
                LoginRequired,
            ),
        ):
            return (
                diagnostic_from_exception(
                    attempt_id=attempt_id,
                    status="blocked",
                    safe_message="Instagram blocked or rate-limited the authentication flow.",
                    exc=exc,
                    client=client,
                    requires_manual_action=True,
                    retry_allowed=False,
                    sensitive_values=(self.settings.instagram_username,),
                ),
                "LOGIN_FEEDBACK_REQUIRED",
            )
        if isinstance(exc, ConsentRequired):
            return (
                diagnostic_from_exception(
                    attempt_id=attempt_id,
                    status="blocked",
                    safe_message="Instagram requires consent or account review before login can continue.",
                    exc=exc,
                    client=client,
                    requires_manual_action=True,
                    retry_allowed=False,
                    sensitive_values=(self.settings.instagram_username,),
                ),
                "LOGIN_CONSENT_REQUIRED",
            )
        if isinstance(exc, GeoBlockRequired):
            return (
                diagnostic_from_exception(
                    attempt_id=attempt_id,
                    status="blocked",
                    safe_message="Instagram rejected the login because of geoblocking or network context.",
                    exc=exc,
                    client=client,
                    requires_manual_action=True,
                    retry_allowed=False,
                    sensitive_values=(self.settings.instagram_username,),
                ),
                "LOGIN_GEOBLOCK_REQUIRED",
            )
        if isinstance(exc, (ClientConnectionError, ClientRequestTimeout)):
            return (
                diagnostic_from_exception(
                    attempt_id=attempt_id,
                    status="transport_error",
                    safe_message="The Instagram request failed at the transport layer.",
                    exc=exc,
                    client=client,
                    requires_manual_action=False,
                    retry_allowed=False,
                    sensitive_values=(self.settings.instagram_username,),
                ),
                "LOGIN_UNCLASSIFIED_FAILURE",
            )
        return (
            diagnostic_from_exception(
                attempt_id=attempt_id,
                status="unknown_error",
                safe_message=(
                    "Instagram returned an unclassified authentication response. "
                    "Review the sanitized diagnostic before any new attempt."
                ),
                exc=exc,
                client=client,
                requires_manual_action=True,
                retry_allowed=False,
                sensitive_values=(self.settings.instagram_username,),
            ),
            "LOGIN_UNCLASSIFIED_FAILURE",
        )

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
        if isinstance(exc, (ClientError, UnknownError)):
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

    async def login_future(
        self,
        username: str,
        password: str,
        challenge_data: dict[str, Any] | None = None,
    ) -> InstagramAuthResult:
        await self._block_real_connection("login")
        if not username or not password:
            raise InstagramAuthError("Instagram username and password are required")
        challenge_data = challenge_data or {}
        verification_code = challenge_data.get("verificationCode") or challenge_data.get("code") or ""
        settings_payload = challenge_data.get("settingsPayload")
        is_verification_attempt = bool(challenge_data.get("isVerificationAttempt"))
        client = self._new_client(settings_payload=settings_payload, challenge_code=verification_code)
        await self.audit.record("LOGIN_ATTEMPT_STARTED", account_key=self.settings.instagram_test_account_key)
        try:
            logged_in = await self._run_silently(
                client.login(username=username, password=password, verification_code=verification_code)
            )
        except Exception as exc:
            result, audit_event = self._result_for_exception(exc)
            if is_verification_attempt:
                await self.audit.record("VERIFICATION_FAILED", account_key=self.settings.instagram_test_account_key)
                raise InstagramAuthFlowError(
                    InstagramAuthResult(
                        status="verification_failed",
                        reason=result.reason or result.verification_type or "verification_not_accepted",
                        next_action="do_not_retry_automatically",
                    )
                ) from exc
            challenge_type = self._classify_challenge(exc)
            if result.status == "verification_required":
                await self._set_pending_context(client, challenge_type)
            metadata = {
                "classification": result.status,
                "exceptionClass": type(exc).__name__,
            }
            if result.status == "verification_required":
                metadata["challengeType"] = challenge_type
            await self.audit.record(
                audit_event,
                account_key=self.settings.instagram_test_account_key,
                metadata=metadata,
            )
            raise InstagramAuthFlowError(result) from exc
        if not logged_in:
            await self.audit.record(
                "LOGIN_BAD_PASSWORD_OR_CONTEXT_REJECTED",
                account_key=self.settings.instagram_test_account_key,
            )
            raise InstagramAuthFlowError(
                InstagramAuthResult(
                    status="authentication_rejected",
                    reason="credentials_or_login_context_rejected",
                    next_action="do_not_retry_automatically",
                )
            )
        await self.save_session_to_store(self.settings.instagram_test_account_key, client.get_settings())
        self._client = client
        await self._clear_pending_context()
        await self.audit.record("LOGIN_SUCCEEDED", account_key=self.settings.instagram_test_account_key)
        await self.audit.record("REAL_SESSION_ENCRYPTED_AND_STORED", account_key=self.settings.instagram_test_account_key)
        if is_verification_attempt:
            await self.audit.record("VERIFICATION_SUCCEEDED", account_key=self.settings.instagram_test_account_key)
        return InstagramAuthResult(
            status="authenticated",
            session_stored=True,
            next_action="validate_session",
        )

    async def login_diagnostic_future(
        self,
        username: str,
        password: str,
        challenge_data: dict[str, Any] | None = None,
    ) -> InstagramAuthDiagnosticResult:
        await self._block_real_connection("login")
        if not username or not password:
            return await self.blocked_auth_diagnostic("Instagram username and password are required")
        challenge_data = challenge_data or {}
        verification_code = challenge_data.get("verificationCode") or challenge_data.get("code") or ""
        settings_payload = challenge_data.get("settingsPayload")
        attempt_id = new_attempt_id()
        client = self._new_client(settings_payload=settings_payload, challenge_code=verification_code)
        await self.audit.record(
            "LOGIN_ATTEMPT_STARTED",
            account_key=self.settings.instagram_test_account_key,
            metadata={"attemptId": attempt_id},
        )
        try:
            logged_in = await self._run_silently(
                client.login(username=username, password=password, verification_code=verification_code)
            )
        except Exception as exc:
            diagnostic, audit_event = self._diagnostic_for_exception(attempt_id=attempt_id, exc=exc, client=client)
            challenge_type = self._classify_challenge(exc)
            if diagnostic.status in {"challenge_required", "two_factor_required"}:
                await self._set_pending_context(client, challenge_type)
            await self.audit.record(
                audit_event,
                account_key=self.settings.instagram_test_account_key,
                metadata={
                    "attemptId": diagnostic.attempt_id,
                    "classification": diagnostic.status,
                    "exceptionClass": diagnostic.exception_class,
                    "httpStatus": diagnostic.http_status,
                    "hasChallengeContext": diagnostic.has_challenge_context,
                    "hasTwoFactorIdentifier": diagnostic.has_two_factor_identifier,
                    "hasCheckpointUrl": diagnostic.has_checkpoint_url,
                },
            )
            await self._save_auth_diagnostic(diagnostic)
            return diagnostic
        if not logged_in:
            diagnostic = InstagramAuthDiagnosticResult(
                attempt_id=attempt_id,
                created_at=utc_now_iso(),
                status="invalid_credentials",
                exception_class=None,
                safe_message="Instagram rejected the credentials or login context.",
                http_status=None,
                response_message=None,
                response_error_type=None,
                has_challenge_context=False,
                has_two_factor_identifier=False,
                has_checkpoint_url=False,
                has_session=False,
                has_settings=bool(client.get_settings()),
                requires_manual_action=True,
                retry_allowed=False,
                raw_response_sanitized={},
            )
            await self.audit.record(
                "LOGIN_BAD_PASSWORD_OR_CONTEXT_REJECTED",
                account_key=self.settings.instagram_test_account_key,
                metadata={"attemptId": attempt_id, "classification": diagnostic.status},
            )
            await self._save_auth_diagnostic(diagnostic)
            return diagnostic
        await self.save_session_to_store(self.settings.instagram_test_account_key, client.get_settings())
        self._client = client
        await self._clear_pending_context()
        diagnostic = redact_diagnostic(
            diagnostic_success(attempt_id=attempt_id, client=client),
            sensitive_values=(self.settings.instagram_username,),
        )
        await self.audit.record(
            "LOGIN_SUCCEEDED",
            account_key=self.settings.instagram_test_account_key,
            metadata={"attemptId": attempt_id},
        )
        await self.audit.record("REAL_SESSION_ENCRYPTED_AND_STORED", account_key=self.settings.instagram_test_account_key)
        await self._save_auth_diagnostic(diagnostic)
        return diagnostic

    async def resolve_challenge_future(
        self,
        code: str,
        username: str | None = None,
        password: str | None = None,
    ) -> InstagramAuthResult:
        await self._block_real_connection("challenge_resolve")
        if not code:
            raise InstagramAuthFlowError(
                InstagramAuthResult(
                    status="verification_required",
                    verification_type="challenge",
                    reason="code_required",
                    next_action="submit_verification_code",
                )
            )
        try:
            await self.session_store.record_verification_attempt(
                self.settings.instagram_test_account_key,
                max_attempts=2,
            )
        except SessionStoreError as exc:
            await self.audit.record("VERIFICATION_RATE_LIMITED", account_key=self.settings.instagram_test_account_key)
            raise InstagramAuthFlowError(
                InstagramAuthResult(
                    status="verification_failed",
                    reason="verification_attempt_limit_exceeded_or_context_missing",
                    next_action="start_new_login_after_manual_approval",
                )
            ) from exc
        await self.audit.record("VERIFICATION_CODE_SUBMITTED", account_key=self.settings.instagram_test_account_key)
        context = await self._load_pending_context()
        if not context:
            raise InstagramAuthFlowError(
                InstagramAuthResult(
                    status="verification_failed",
                    reason="challenge_context_missing_or_expired",
                    next_action="start_new_login_after_manual_approval",
                )
            )
        if not username or not password:
            raise InstagramAuthFlowError(
                InstagramAuthResult(
                    status="verification_failed",
                    reason="credentials_required_for_verification",
                    next_action="start_new_login_after_manual_approval",
                )
            )
        return await self.login_future(
            username,
            password,
            {
                "verificationCode": code,
                "code": code,
                "settingsPayload": context.get("settingsPayload"),
                "isVerificationAttempt": True,
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
        await self._clear_pending_context()
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
