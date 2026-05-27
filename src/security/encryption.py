from __future__ import annotations

import json
import os
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


ENCRYPTION_VERSION = "v1"


class EncryptionError(RuntimeError):
    """Raised for encryption or decryption failures without leaking payload data."""


class EncryptionService:
    def __init__(self, key: str):
        if not key:
            raise EncryptionError("Encryption key is required")
        try:
            self._fernet = Fernet(key.encode("utf-8"))
        except Exception as exc:  # Fernet intentionally raises multiple validation errors.
            raise EncryptionError("Invalid encryption key") from exc

    def encrypt_json(self, data: dict[str, Any]) -> str:
        if not isinstance(data, dict):
            raise EncryptionError("Only JSON objects can be encrypted")
        try:
            plaintext = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
            token = self._fernet.encrypt(plaintext).decode("utf-8")
        except Exception as exc:
            raise EncryptionError("Unable to encrypt payload") from exc
        return f"{ENCRYPTION_VERSION}:{token}"

    def decrypt_json(self, payload: str) -> dict[str, Any]:
        if not isinstance(payload, str) or not payload.startswith(f"{ENCRYPTION_VERSION}:"):
            raise EncryptionError("Unable to decrypt payload")
        token = payload.split(":", 1)[1]
        try:
            plaintext = self._fernet.decrypt(token.encode("utf-8"))
            decoded = json.loads(plaintext.decode("utf-8"))
        except (InvalidToken, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise EncryptionError("Unable to decrypt payload") from exc
        if not isinstance(decoded, dict):
            raise EncryptionError("Unable to decrypt payload")
        return decoded


def _service_from_env() -> EncryptionService:
    return EncryptionService(os.getenv("SESSION_ENCRYPTION_KEY", ""))


def encrypt_json(data: dict[str, Any]) -> str:
    return _service_from_env().encrypt_json(data)


def decrypt_json(payload: str) -> dict[str, Any]:
    return _service_from_env().decrypt_json(payload)
