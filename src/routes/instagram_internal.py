from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse

from src.auth_diagnostics import auth_status_http_code, sanitize_diagnostic_dict
from src.config import Settings
from src.dependencies import require_internal_auth
from src.instagram_client import (
    InstagramAuthError,
    InstagramAuthFlowError,
    InstagramChallengeRequiredError,
    InstagramOperationError,
    InstagramRiskStopError,
    RealConnectionDisabledError,
)
from src.models import (
    InstagramActionResponse,
    InstagramAccountPreflightResponse,
    InstagramAuthAttemptLatestResponse,
    InstagramAuthDiagnosticResponse,
    InstagramAuthResponse,
    InstagramChallengeResolveRequest,
    InstagramLoginRequest,
    InstagramLogoutRequest,
    InstagramMessagesResponse,
    InstagramSendTextResponse,
    InstagramSessionValidateResponse,
    InstagramTextSendRequest,
    InstagramThreadsResponse,
    InternalStatusResponse,
    RemoveSessionRequest,
    SessionActionResponse,
)
from src.services.rate_limit import RateLimitExceeded


router = APIRouter(prefix="/internal", dependencies=[Depends(require_internal_auth)])

REMOVE_CONFIRMATION = "REMOVE_EXPERIMENTAL_SESSION"
MANUAL_LOGIN_CONFIRMATION = "RUN_ONE_MANUAL_LOGIN_ATTEMPT"

FAKE_SETTINGS: dict[str, Any] = {
    "device_settings": {
        "app_version": "fake-app-version",
        "android_version": 34,
        "uuid": "fake-device-uuid",
    },
    "cookies": {
        "sessionid": "fake-sessionid-should-never-appear-in-documents",
    },
    "authorization_data": {
        "ds_user_id": "0",
    },
    "user_agent": "fake-user-agent",
}


def _settings(request: Request) -> Settings:
    return request.app.state.settings


def _ensure_test_phase(settings: Settings) -> None:
    if settings.app_env not in {"development", "experimental", "test"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Endpoint disabled in this environment")


def _safe_instagram_exception(exc: Exception) -> HTTPException:
    if isinstance(exc, RealConnectionDisabledError):
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Real Instagram connection is disabled")
    if isinstance(exc, InstagramChallengeRequiredError):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"challengeRequired": True, "challengeType": exc.challenge_type},
        )
    if isinstance(exc, InstagramAuthError):
        return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Instagram authentication failed")
    if isinstance(exc, InstagramRiskStopError):
        return HTTPException(status_code=status.HTTP_409_CONFLICT, detail={"safetyStop": True, "reason": exc.reason})
    if isinstance(exc, RateLimitExceeded):
        return HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Send rate limit exceeded")
    if isinstance(exc, InstagramOperationError):
        return HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Instagram operation failed")
    return HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Instagram operation failed")


def _auth_flow_response(exc: InstagramAuthFlowError) -> InstagramAuthResponse:
    return InstagramAuthResponse(**exc.result.to_response())


def _auth_diagnostic_response(diagnostic) -> JSONResponse:
    return JSONResponse(
        status_code=auth_status_http_code(diagnostic.status),
        content=diagnostic.to_public_dict(),
    )


@router.get("/status", response_model=InternalStatusResponse)
async def internal_status(request: Request) -> InternalStatusResponse:
    settings = _settings(request)
    store = request.app.state.session_store
    mongodb_connected = await store.ping()
    try:
        session_stored = await store.session_exists(settings.instagram_test_account_key)
    except Exception:
        session_stored = False
    return InternalStatusResponse(
        environment=settings.app_env,
        mongodbConnected=mongodb_connected,
        sessionExperimentalStored=session_stored,
        instagramRealConnectionEnabled=settings.instagram_real_connection_enabled,
        pollingEnabled=settings.instagram_polling_enabled,
        applicationVersion=settings.app_version,
    )


@router.post("/session/test-store", response_model=SessionActionResponse)
async def session_test_store(request: Request) -> SessionActionResponse:
    settings = _settings(request)
    _ensure_test_phase(settings)
    instagram = request.app.state.instagram
    audit = request.app.state.audit
    try:
        await instagram.save_session_to_store(settings.instagram_test_account_key, FAKE_SETTINGS)
    except Exception as exc:
        await audit.record("MONGODB_CONNECTION_FAILED", account_key=settings.instagram_test_account_key)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Session store unavailable") from exc
    await audit.record("SESSION_TEST_STORED", account_key=settings.instagram_test_account_key)
    return SessionActionResponse(ok=True, action="test-store", accountKey=settings.instagram_test_account_key)


@router.post("/session/test-restore", response_model=SessionActionResponse)
async def session_test_restore(request: Request) -> SessionActionResponse:
    settings = _settings(request)
    _ensure_test_phase(settings)
    instagram = request.app.state.instagram
    audit = request.app.state.audit
    try:
        restored = await instagram.load_session_from_store(settings.instagram_test_account_key)
    except Exception as exc:
        await audit.record("MONGODB_CONNECTION_FAILED", account_key=settings.instagram_test_account_key)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Session store unavailable") from exc
    if not restored:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No experimental session stored")
    if restored.get("cookies", {}).get("sessionid") != FAKE_SETTINGS["cookies"]["sessionid"]:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Stored session failed validation")
    await audit.record("SESSION_TEST_RESTORED", account_key=settings.instagram_test_account_key)
    return SessionActionResponse(ok=True, action="test-restore", accountKey=settings.instagram_test_account_key)


@router.delete("/session", response_model=SessionActionResponse)
async def delete_session(request: Request, body: RemoveSessionRequest) -> SessionActionResponse:
    if body.confirm != REMOVE_CONFIRMATION:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid confirmation")
    settings = _settings(request)
    instagram = request.app.state.instagram
    audit = request.app.state.audit
    try:
        removed = await instagram.delete_session_from_store(settings.instagram_test_account_key)
    except Exception as exc:
        await audit.record("MONGODB_CONNECTION_FAILED", account_key=settings.instagram_test_account_key)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Session store unavailable") from exc
    await audit.record("SESSION_REMOVED", account_key=settings.instagram_test_account_key)
    return SessionActionResponse(ok=removed, action="delete", accountKey=settings.instagram_test_account_key)


@router.post("/instagram/login", response_model=InstagramAuthDiagnosticResponse)
async def instagram_login(request: Request, body: InstagramLoginRequest):
    settings = _settings(request)
    _ensure_test_phase(settings)
    instagram = request.app.state.instagram
    if not settings.instagram_real_connection_enabled:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Real Instagram connection is disabled")
    if body.confirmManualAttempt != MANUAL_LOGIN_CONFIRMATION:
        diagnostic = await instagram.blocked_auth_diagnostic(
            "Manual login requires confirmManualAttempt=RUN_ONE_MANUAL_LOGIN_ATTEMPT"
        )
        return _auth_diagnostic_response(diagnostic)
    if settings.instagram_polling_enabled:
        diagnostic = await instagram.blocked_auth_diagnostic("Polling must be disabled before a login attempt")
        return _auth_diagnostic_response(diagnostic)
    username = body.username or settings.instagram_username
    password = body.password.get_secret_value() if body.password else settings.instagram_password
    if not username or not password:
        diagnostic = await instagram.blocked_auth_diagnostic("Instagram credentials are not configured")
        return _auth_diagnostic_response(diagnostic)
    try:
        diagnostic = await instagram.login_diagnostic_future(
            username,
            password,
            {
                "verificationCode": body.verificationCode.get_secret_value() if body.verificationCode else "",
            },
        )
    except Exception as exc:
        raise _safe_instagram_exception(exc) from exc
    return _auth_diagnostic_response(diagnostic)


@router.get("/instagram/account/preflight", response_model=InstagramAccountPreflightResponse)
async def instagram_account_preflight(request: Request) -> InstagramAccountPreflightResponse:
    settings = _settings(request)
    _ensure_test_phase(settings)
    instagram = request.app.state.instagram
    preflight = await instagram.account_preflight_future(settings.instagram_username)
    return InstagramAccountPreflightResponse(**preflight)


@router.get("/instagram/auth-attempts/latest", response_model=InstagramAuthAttemptLatestResponse)
async def instagram_latest_auth_attempt(request: Request) -> InstagramAuthAttemptLatestResponse:
    instagram = request.app.state.instagram
    latest = await instagram.latest_auth_attempt()
    if not latest:
        return InstagramAuthAttemptLatestResponse(
            found=False,
            diagnostic=None,
            recommendation="No Instagram authentication attempt has been recorded.",
        )
    settings = _settings(request)
    latest = sanitize_diagnostic_dict(latest, sensitive_values=(settings.instagram_username,))
    preflight = await instagram.latest_account_preflight()
    recommendation = "Review the sanitized diagnostic before any new manual attempt."
    if latest.get("status") == "success":
        recommendation = "Validate the restored session before using Direct endpoints."
    elif latest.get("status") in {"challenge_required", "two_factor_required"}:
        recommendation = "Submit the verification code only through the protected verification endpoint."
    elif latest.get("status") in {"unknown_error", "checkpoint_required", "blocked"}:
        recommendation = "Do not retry automatically; inspect the Instagram app, e-mail, account state, and network context first."
    correlation = _auth_preflight_correlation(latest, preflight)
    return InstagramAuthAttemptLatestResponse(
        found=True,
        diagnostic=latest,
        preflight=preflight,
        correlation=correlation,
        recommendation=recommendation,
    )


def _auth_preflight_correlation(latest: dict[str, Any], preflight: dict[str, Any] | None) -> dict[str, Any]:
    public_exists = preflight.get("public_profile_exists") if preflight else None
    private_status = latest.get("status")
    private_error_type = latest.get("response_error_type")
    if public_exists is True and private_error_type == "invalid_user":
        interpretation = (
            "Public profile exists, but Instagram rejected the private login context. "
            "Investigate network/device/session trust before any new login attempt."
        )
    elif private_error_type == "invalid_user":
        interpretation = (
            "Instagram rejected the identifier during private login. This does not prove the account does not exist; "
            "it can indicate rejection of the authentication context, device, IP, session, or private flow."
        )
    elif public_exists is False:
        interpretation = "Public preflight did not find the profile; verify the account identifier manually before private login."
    elif public_exists is None:
        interpretation = "Public preflight is absent or inconclusive; do not use private login errors alone as existence proof."
    else:
        interpretation = "Review public preflight and private login diagnostics together before any new manual attempt."
    return {
        "public_profile_exists": public_exists,
        "private_login_status": private_status,
        "private_login_error_type": private_error_type,
        "safe_interpretation": interpretation,
    }


async def _resolve_verification(request: Request, body: InstagramChallengeResolveRequest) -> InstagramAuthResponse:
    settings = _settings(request)
    _ensure_test_phase(settings)
    instagram = request.app.state.instagram
    username = body.username or settings.instagram_username or None
    password = body.password.get_secret_value() if body.password else settings.instagram_password or None
    try:
        result = await instagram.resolve_challenge_future(
            body.code.get_secret_value(),
            username=username,
            password=password,
        )
    except InstagramAuthFlowError as exc:
        return _auth_flow_response(exc)
    except Exception as exc:
        raise _safe_instagram_exception(exc) from exc
    return InstagramAuthResponse(**result.to_response())


@router.post("/instagram/challenge/resolve", response_model=InstagramAuthResponse)
async def instagram_challenge_resolve(
    request: Request,
    body: InstagramChallengeResolveRequest,
) -> InstagramAuthResponse:
    return await _resolve_verification(request, body)


@router.post("/instagram/verification/two-factor", response_model=InstagramAuthResponse)
async def instagram_two_factor_verification(
    request: Request,
    body: InstagramChallengeResolveRequest,
) -> InstagramAuthResponse:
    return await _resolve_verification(request, body)


@router.post("/instagram/verification/challenge", response_model=InstagramAuthResponse)
async def instagram_challenge_verification(
    request: Request,
    body: InstagramChallengeResolveRequest,
) -> InstagramAuthResponse:
    return await _resolve_verification(request, body)


@router.post("/instagram/session/validate", response_model=InstagramSessionValidateResponse)
async def instagram_session_validate(request: Request) -> InstagramSessionValidateResponse:
    settings = _settings(request)
    instagram = request.app.state.instagram
    try:
        authenticated = await instagram.validate_session_future(settings.instagram_test_account_key)
    except Exception as exc:
        raise _safe_instagram_exception(exc) from exc
    return InstagramSessionValidateResponse(ok=True, authenticated=authenticated)


@router.get("/instagram/threads", response_model=InstagramThreadsResponse)
async def instagram_threads(request: Request, amount: int = 5) -> InstagramThreadsResponse:
    instagram = request.app.state.instagram
    try:
        threads = await instagram.list_threads_future(amount=amount)
    except Exception as exc:
        raise _safe_instagram_exception(exc) from exc
    return InstagramThreadsResponse(ok=True, threads=threads)


@router.get("/instagram/threads/{thread_id}/messages", response_model=InstagramMessagesResponse)
async def instagram_thread_messages(request: Request, thread_id: str, amount: int = 10) -> InstagramMessagesResponse:
    instagram = request.app.state.instagram
    try:
        messages = await instagram.list_messages_future(thread_id, amount=amount)
    except Exception as exc:
        raise _safe_instagram_exception(exc) from exc
    return InstagramMessagesResponse(ok=True, messages=messages)


@router.post("/instagram/threads/{thread_id}/send-text", response_model=InstagramSendTextResponse)
async def instagram_send_text(
    request: Request,
    thread_id: str,
    body: InstagramTextSendRequest,
) -> InstagramSendTextResponse:
    settings = _settings(request)
    instagram = request.app.state.instagram
    audit = request.app.state.audit
    rate_limit = request.app.state.rate_limit
    try:
        rate_limit.assert_send_allowed(settings.instagram_test_account_key)
        message = await instagram.send_text_future(thread_id, body.text)
        rate_limit.record_send(settings.instagram_test_account_key)
    except RateLimitExceeded as exc:
        await audit.record("RATE_LIMIT_BLOCKED", account_key=settings.instagram_test_account_key)
        raise _safe_instagram_exception(exc) from exc
    except Exception as exc:
        raise _safe_instagram_exception(exc) from exc
    return InstagramSendTextResponse(ok=True, message=message)


@router.post("/instagram/logout", response_model=InstagramActionResponse)
async def instagram_logout(request: Request, body: InstagramLogoutRequest) -> InstagramActionResponse:
    if body.confirm != "LOGOUT_INSTAGRAM_TEST_ACCOUNT":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid confirmation")
    settings = _settings(request)
    instagram = request.app.state.instagram
    try:
        await instagram.logout_future(settings.instagram_test_account_key)
    except Exception as exc:
        raise _safe_instagram_exception(exc) from exc
    return InstagramActionResponse(ok=True, action="logout")
