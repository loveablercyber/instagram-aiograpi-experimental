from __future__ import annotations

from cryptography.fernet import Fernet
import pytest

from src.security.encryption import EncryptionError, EncryptionService


SENSITIVE_VALUE = "fake-sessionid-should-never-appear"


def test_encrypts_and_restores_fake_settings():
    service = EncryptionService(Fernet.generate_key().decode("utf-8"))
    payload = {"cookies": {"sessionid": SENSITIVE_VALUE}, "device": "fake"}

    encrypted = service.encrypt_json(payload)
    restored = service.decrypt_json(encrypted)

    assert restored == payload
    assert SENSITIVE_VALUE not in encrypted


def test_wrong_key_fails_without_leaking_payload():
    encrypted = EncryptionService(Fernet.generate_key().decode("utf-8")).encrypt_json(
        {"cookies": {"sessionid": SENSITIVE_VALUE}}
    )
    wrong = EncryptionService(Fernet.generate_key().decode("utf-8"))

    with pytest.raises(EncryptionError) as exc_info:
        wrong.decrypt_json(encrypted)

    assert SENSITIVE_VALUE not in str(exc_info.value)


def test_tampered_payload_fails_without_leaking_payload():
    service = EncryptionService(Fernet.generate_key().decode("utf-8"))
    encrypted = service.encrypt_json({"cookies": {"sessionid": SENSITIVE_VALUE}})
    tampered = encrypted[:-3] + "abc"

    with pytest.raises(EncryptionError) as exc_info:
        service.decrypt_json(tampered)

    assert SENSITIVE_VALUE not in str(exc_info.value)
