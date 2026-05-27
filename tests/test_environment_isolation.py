from __future__ import annotations

from pathlib import Path

import pytest

from src.config import ConfigError
from tests.conftest import make_settings


def test_database_must_be_dedicated_experimental_database():
    with pytest.raises(ConfigError):
        make_settings(mongodb_database="production")


def test_baileys_or_whatsapp_terms_are_rejected_in_config():
    with pytest.raises(ConfigError):
        make_settings(instagram_test_account_key="baileys")


def test_created_configuration_files_do_not_reference_baileys_service():
    root = Path(__file__).resolve().parents[1]
    files = [
        root / "render.yaml",
        root / ".env.example",
        root / "Dockerfile",
    ]
    combined = "\n".join(path.read_text(encoding="utf-8").lower() for path in files)

    assert "baileys" not in combined
    assert "whatsapp" not in combined
