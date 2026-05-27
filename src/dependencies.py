from __future__ import annotations

from typing import Optional

from fastapi import Header, HTTPException, Request, status

from src.config import Settings
from src.instagram_client import InstagramClientService
from src.security.internal_auth import is_authorized
from src.services.audit import AuditService
from src.session_store import MemorySessionStore, MongoSessionStore


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_session_store(request: Request) -> MongoSessionStore | MemorySessionStore:
    return request.app.state.session_store


def get_audit_service(request: Request) -> AuditService:
    return request.app.state.audit


def get_instagram_service(request: Request) -> InstagramClientService:
    return request.app.state.instagram


async def require_internal_auth(
    request: Request,
    x_internal_token: Optional[str] = Header(None, alias="X-Internal-Token"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> None:
    settings = get_settings(request)
    if is_authorized(settings, x_internal_token, authorization):
        return
    audit = get_audit_service(request)
    await audit.record("UNAUTHORIZED_REQUEST_BLOCKED", metadata={"path": request.url.path})
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
