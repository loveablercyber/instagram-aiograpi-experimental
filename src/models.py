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
    confirmManualAttempt: str | None = None


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


class InstagramAuthResponse(BaseModel):
    status: str
    nextAction: str
    sessionStored: bool | None = None
    verificationType: str | None = None
    challengeMethod: str | None = None
    reason: str | None = None


class InstagramAuthDiagnosticResponse(BaseModel):
    attempt_id: str
    created_at: str
    status: str
    exception_class: str | None = None
    safe_message: str
    http_status: int | None = None
    response_message: str | None = None
    response_error_type: str | None = None
    has_challenge_context: bool
    has_two_factor_identifier: bool
    has_checkpoint_url: bool
    has_session: bool
    has_settings: bool
    requires_manual_action: bool
    retry_allowed: bool
    raw_response_sanitized: dict
    library_name: str
    library_version: str
    app_device_profile_configured: bool = False
    device_settings_persisted: bool = False
    outbound_network_identity_configured: bool = False
    stored_session_available: bool = False
    login_origin: str = "render"


class InstagramAccountPreflightResponse(BaseModel):
    username_redacted: str
    public_profile_exists: bool | None
    profile_identifier_present: bool
    login_attempt_performed: bool
    checked_at: str
    safe_interpretation: str


class InstagramAuthAttemptLatestResponse(BaseModel):
    found: bool
    diagnostic: InstagramAuthDiagnosticResponse | None = None
    preflight: InstagramAccountPreflightResponse | None = None
    correlation: dict | None = None
    recommendation: str


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
