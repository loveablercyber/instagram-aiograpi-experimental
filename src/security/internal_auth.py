from __future__ import annotations

import hmac
from typing import Optional

from src.config import Settings


def _bearer_token(authorization: Optional[str]) -> str:
    if not authorization:
        return ""
    prefix = "Bearer "
    if authorization.startswith(prefix):
        return authorization[len(prefix) :].strip()
    return ""


def is_authorized(settings: Settings, x_internal_token: Optional[str], authorization: Optional[str]) -> bool:
    expected = settings.internal_api_token
    if not expected:
        return False
    supplied = (x_internal_token or "").strip() or _bearer_token(authorization)
    if not supplied:
        return False
    return hmac.compare_digest(supplied, expected)
