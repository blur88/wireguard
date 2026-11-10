import os
from unittest import mock

import pytest

from wireguard_dashboard.config import get_settings


def test_default_port_is_8080() -> None:
    with mock.patch.dict(os.environ, {}, clear=True):
        settings = get_settings()
        assert settings.port == 8080


def test_custom_valid_port() -> None:
    with mock.patch.dict(os.environ, {"PORT": "9090"}):
        settings = get_settings()
        assert settings.port == 9090


@pytest.mark.parametrize("invalid_port", ["abc", "-1", "0", "65536", "70000", "80.5"])
def test_invalid_port_fails_safely(invalid_port: str) -> None:
    with mock.patch.dict(os.environ, {"PORT": invalid_port}):
        with pytest.raises(ValueError, match="Invalid PORT"):
            get_settings()
