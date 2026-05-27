from __future__ import annotations

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    service: str


class InternalStatusResponse(BaseModel):
    environment: str
    mongodbConnected: bool
    sessionExperimentalStored: bool
    instagramRealConnectionEnabled: bool
    pollingEnabled: bool
    applicationVersion: str


class SessionActionResponse(BaseModel):
    ok: bool
    action: str
    accountKey: str | None = None


class RemoveSessionRequest(BaseModel):
    confirm: str = Field(..., min_length=1)


class ErrorResponse(BaseModel):
    detail: str
