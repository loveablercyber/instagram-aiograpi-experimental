from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from src.config import Settings
from src.dependencies import require_internal_auth
from src.models import InternalStatusResponse, RemoveSessionRequest, SessionActionResponse


router = APIRouter(prefix="/internal", dependencies=[Depends(require_internal_auth)])

REMOVE_CONFIRMATION = "REMOVE_EXPERIMENTAL_SESSION"

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
