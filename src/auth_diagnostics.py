from __future__ import annotations

import importlib.metadata as metadata
import re
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4


LIBRARY_NAME = "aiograpi"
LIBRARY_VERSION = metadata.version("aiograpi")

SENSITIVE_KEY_PARTS = (
    "password",
    "authorization",
    "cookie",
    "sessionid",
    "csrftoken",
    "csrf",
    "token",
    "secret",
    "enc_password",
    "challenge_code",
    "verification_code",
    "security_code",
)

PRESENCE_ONLY_KEY_PARTS = (
    "challenge_context",
    "two_factor_identifier",
    "device_id",
    "uuid",
    "phone",
    "email",
    "mid",
    "guid",
    "adid",
)

IMPORTANT_KEYS = {
    "message",
    "error_type",
    "status",
    "challenge",
    "challenge_context",
    "checkpoint_url",
    "two_factor_info",
    "two_factor_identifier",
    "user_id",
    "step_name",
    "bloks_action",
    "challengeType",
    "challenge_type_enum",
    "challenge_type_enum_str",
    "logout_reason",
    "error_title",
    "error_body",
    "feedback_message",
}

BLOCKING_STATUSES = {"unknown_error", "checkpoint_required", "blocked"}


@dataclass(frozen=True)
class InstagramAuthDiagnosticResult:
    attempt_id: str
    created_at: str
    status: str
    exception_class: str | None
    safe_message: str
    http_status: int | None
    response_message: str | None
    response_error_type: str | None
    has_challenge_context: bool
    has_two_factor_identifier: bool
    has_checkpoint_url: bool
    has_session: bool
    has_settings: bool
    requires_manual_action: bool
    retry_allowed: bool
    raw_response_sanitized: dict[str, Any]
    library_name: str = LIBRARY_NAME
    library_version: str = LIBRARY_VERSION

    @classmethod
    def blocked(cls, reason: str) -> "InstagramAuthDiagnosticResult":
        return cls(
            attempt_id=new_attempt_id(),
            created_at=utc_now_iso(),
            status="blocked",
            exception_class=None,
            safe_message=reason,
            http_status=None,
            response_message=None,
            response_error_type=None,
            has_challenge_context=False,
            has_two_factor_identifier=False,
            has_checkpoint_url=False,
            has_session=False,
            has_settings=False,
            requires_manual_action=True,
            retry_allowed=False,
            raw_response_sanitized={},
        )

    def to_public_dict(self) -> dict[str, Any]:
        return asdict(self)


def new_attempt_id() -> str:
    return f"ig-auth-{uuid4().hex}"


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def sanitize_instagram_auth_payload(
    payload: Any,
    *,
    depth: int = 0,
    sensitive_values: tuple[str, ...] = (),
) -> Any:
    if depth > 5:
        return "[MAX_DEPTH]"
    if isinstance(payload, dict):
        safe: dict[str, Any] = {}
        for key, value in payload.items():
            key_str = str(key)
            lowered = key_str.lower()
            if lowered.startswith("has_") and isinstance(value, bool):
                safe[key_str] = value
            elif any(part in lowered for part in SENSITIVE_KEY_PARTS):
                safe[key_str] = "[REDACTED]"
            elif any(part in lowered for part in PRESENCE_ONLY_KEY_PARTS):
                safe[key_str] = "[PRESENT]" if value not in (None, "", [], {}) else None
            elif key_str in IMPORTANT_KEYS or isinstance(value, (dict, list, tuple, str, int, float, bool)) or value is None:
                safe[key_str] = sanitize_instagram_auth_payload(
                    value,
                    depth=depth + 1,
                    sensitive_values=sensitive_values,
                )
            else:
                safe[key_str] = str(type(value).__name__)
        return safe
    if isinstance(payload, (list, tuple)):
        return [
            sanitize_instagram_auth_payload(item, depth=depth + 1, sensitive_values=sensitive_values)
            for item in payload[:20]
        ]
    if isinstance(payload, str):
        return _sanitize_text(payload, sensitive_values=sensitive_values)
    if isinstance(payload, (int, float, bool)) or payload is None:
        return payload
    return str(type(payload).__name__)


def build_exception_payload(exc: Exception, client: Any | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if client is not None:
        last_json = getattr(client, "last_json", None)
        if isinstance(last_json, dict):
            payload.update(last_json)
        response = getattr(client, "last_response", None)
        _add_response(payload, response)
    for key, value in vars(exc).items():
        if key == "response":
            _add_response(payload, value)
            continue
        payload[key] = value
    message = getattr(exc, "message", None) or str(exc)
    if message:
        payload.setdefault("message", message)
    return payload


def diagnostic_from_exception(
    *,
    attempt_id: str,
    status: str,
    safe_message: str,
    exc: Exception,
    client: Any | None,
    requires_manual_action: bool,
    retry_allowed: bool,
    sensitive_values: tuple[str, ...] = (),
) -> InstagramAuthDiagnosticResult:
    payload = build_exception_payload(exc, client)
    sanitized = sanitize_instagram_auth_payload(_important_payload(payload), sensitive_values=sensitive_values)
    http_status = _http_status_from_payload(payload)
    response_message = _safe_value(payload.get("message"), sensitive_values=sensitive_values)
    response_error_type = _safe_value(payload.get("error_type"), sensitive_values=sensitive_values)
    settings_payload = _safe_get_settings(client)
    return InstagramAuthDiagnosticResult(
        attempt_id=attempt_id,
        created_at=utc_now_iso(),
        status=status,
        exception_class=type(exc).__name__,
        safe_message=safe_message,
        http_status=http_status,
        response_message=response_message,
        response_error_type=response_error_type,
        has_challenge_context=_has_nested_key(payload, "challenge_context"),
        has_two_factor_identifier=_has_nested_key(payload, "two_factor_identifier"),
        has_checkpoint_url=_has_nested_key(payload, "checkpoint_url"),
        has_session=_settings_has_session(settings_payload),
        has_settings=bool(settings_payload),
        requires_manual_action=requires_manual_action,
        retry_allowed=retry_allowed,
        raw_response_sanitized=sanitized,
    )


def diagnostic_success(*, attempt_id: str, client: Any) -> InstagramAuthDiagnosticResult:
    settings_payload = _safe_get_settings(client)
    return InstagramAuthDiagnosticResult(
        attempt_id=attempt_id,
        created_at=utc_now_iso(),
        status="success",
        exception_class=None,
        safe_message="Instagram authentication succeeded and settings were encrypted.",
        http_status=_http_status_from_response(getattr(client, "last_response", None)),
        response_message=None,
        response_error_type=None,
        has_challenge_context=False,
        has_two_factor_identifier=False,
        has_checkpoint_url=False,
        has_session=_settings_has_session(settings_payload),
        has_settings=bool(settings_payload),
        requires_manual_action=False,
        retry_allowed=False,
        raw_response_sanitized={},
    )


def auth_status_http_code(status: str) -> int:
    return {
        "success": 200,
        "challenge_required": 409,
        "two_factor_required": 409,
        "checkpoint_required": 409,
        "unknown_error": 409,
        "blocked": 409,
        "invalid_credentials": 401,
        "transport_error": 502,
    }.get(status, 502)


def sanitize_diagnostic_dict(
    diagnostic: dict[str, Any],
    *,
    sensitive_values: tuple[str, ...] = (),
) -> dict[str, Any]:
    sanitized = sanitize_instagram_auth_payload(diagnostic, sensitive_values=sensitive_values)
    return sanitized if isinstance(sanitized, dict) else {}


def redact_diagnostic(
    diagnostic: InstagramAuthDiagnosticResult,
    *,
    sensitive_values: tuple[str, ...] = (),
) -> InstagramAuthDiagnosticResult:
    return replace(
        diagnostic,
        safe_message=_sanitize_text(diagnostic.safe_message, sensitive_values=sensitive_values),
        response_message=_sanitize_text(diagnostic.response_message, sensitive_values=sensitive_values)
        if diagnostic.response_message
        else None,
        response_error_type=_sanitize_text(diagnostic.response_error_type, sensitive_values=sensitive_values)
        if diagnostic.response_error_type
        else None,
        raw_response_sanitized=sanitize_instagram_auth_payload(
            diagnostic.raw_response_sanitized,
            sensitive_values=sensitive_values,
        ),
    )


def _important_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key in IMPORTANT_KEYS}


def _safe_value(value: Any, *, sensitive_values: tuple[str, ...] = ()) -> str | None:
    if value in (None, ""):
        return None
    return str(sanitize_instagram_auth_payload(str(value), sensitive_values=sensitive_values))[:240]


def _sanitize_text(value: str, *, sensitive_values: tuple[str, ...] = ()) -> str:
    text = value[:1000]
    for sensitive in sensitive_values:
        if sensitive:
            text = text.replace(sensitive, "[ACCOUNT_IDENTIFIER_REDACTED]")
    text = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", "[EMAIL_REDACTED]", text)
    text = re.sub(r"\b\d{5,}\b", "[NUMBER_REDACTED]", text)
    text = re.sub(r"(?i)(sessionid|csrftoken|authorization|password|token)=([^;\s]+)", r"\1=[REDACTED]", text)
    return text


def _has_nested_key(payload: Any, wanted: str) -> bool:
    if isinstance(payload, dict):
        for key, value in payload.items():
            if str(key) == wanted and value not in (None, "", [], {}):
                return True
            if _has_nested_key(value, wanted):
                return True
    elif isinstance(payload, (list, tuple)):
        return any(_has_nested_key(item, wanted) for item in payload)
    return False


def _safe_get_settings(client: Any | None) -> dict[str, Any]:
    if client is None or not hasattr(client, "get_settings"):
        return {}
    try:
        settings = client.get_settings()
    except Exception:
        return {}
    return settings if isinstance(settings, dict) else {}


def _settings_has_session(settings_payload: dict[str, Any]) -> bool:
    cookies = settings_payload.get("cookies")
    if isinstance(cookies, dict) and cookies.get("sessionid"):
        return True
    auth_data = settings_payload.get("authorization_data")
    return bool(isinstance(auth_data, dict) and auth_data.get("sessionid"))


def _http_status_from_payload(payload: dict[str, Any]) -> int | None:
    explicit_status = payload.get("http_status")
    if isinstance(explicit_status, int):
        return explicit_status
    response = payload.get("response")
    status = _http_status_from_response(response)
    if status is not None:
        return status
    code = payload.get("code")
    return code if isinstance(code, int) else None


def _http_status_from_response(response: Any) -> int | None:
    status = getattr(response, "status_code", None)
    return status if isinstance(status, int) else None


def _add_response(payload: dict[str, Any], response: Any) -> None:
    if response is None:
        return
    status = _http_status_from_response(response)
    if status is not None:
        payload["http_status"] = status
    try:
        json_payload = response.json()
    except Exception:
        return
    if isinstance(json_payload, dict):
        payload.update(json_payload)
