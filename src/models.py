from __future__ import annotations

from pydantic import BaseModel, Field, SecretStr


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


class InstagramLoginRequest(BaseModel):
    username: str | None = None
    password: SecretStr | None = None
    verificationCode: SecretStr | None = None


class InstagramChallengeResolveRequest(BaseModel):
    code: SecretStr = Field(..., min_length=1)
    username: str | None = None
    password: SecretStr | None = None


class InstagramTextSendRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=1000)


class InstagramLogoutRequest(BaseModel):
    confirm: str = Field(..., min_length=1)


class InstagramActionResponse(BaseModel):
    ok: bool
    action: str
    challengeRequired: bool = False
    challengeType: str | None = None


class InstagramSessionValidateResponse(BaseModel):
    ok: bool
    authenticated: bool


class InstagramThreadsResponse(BaseModel):
    ok: bool
    threads: list[dict]


class InstagramMessagesResponse(BaseModel):
    ok: bool
    messages: list[dict]


class InstagramSendTextResponse(BaseModel):
    ok: bool
    message: dict


class ErrorResponse(BaseModel):
    detail: str
