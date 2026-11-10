import os
from pathlib import Path
from unittest import mock

import pytest

from wireguard_dashboard.config import get_settings


def test_default_port_is_8080() -> None:
    with mock.patch.dict(
        os.environ,
        {
            "DASHBOARD_PASSWORD": "valid_test_password_123",
            "SESSION_SECRET": "a" * 32,
        },
        clear=True,
    ):
        settings = get_settings()
        assert settings.port == 8080


def test_custom_valid_port() -> None:
    with mock.patch.dict(
        os.environ,
        {
            "PORT": "9090",
            "DASHBOARD_PASSWORD": "valid_test_password_123",
            "SESSION_SECRET": "a" * 32,
        },
        clear=True,
    ):
        settings = get_settings()
        assert settings.port == 9090


@pytest.mark.parametrize("invalid_port", ["abc", "-1", "0", "65536", "70000", "80.5"])
def test_invalid_port_fails_safely(invalid_port: str) -> None:
    with mock.patch.dict(
        os.environ,
        {
            "PORT": invalid_port,
            "DASHBOARD_PASSWORD": "valid_test_password_123",
            "SESSION_SECRET": "a" * 32,
        },
    ):
        with pytest.raises(ValueError, match="Invalid PORT"):
            get_settings()


def test_missing_credentials_fails_securely() -> None:
    with mock.patch.dict(os.environ, {}, clear=True):
        with pytest.raises(ValueError, match="DASHBOARD_PASSWORD.*required"):
            get_settings()


def test_password_loaded_from_env() -> None:
    with mock.patch.dict(
        os.environ,
        {
            "DASHBOARD_PASSWORD": "super-secret-admin-pass",
            "SESSION_SECRET": "s" * 32,
        },
        clear=True,
    ):
        settings = get_settings()
        assert settings.dashboard_password == "super-secret-admin-pass"
        assert settings.session_secret == "s" * 32
        assert settings.auth_disabled is False


def test_password_loaded_from_file(tmp_path: Path) -> None:
    secret_file = tmp_path / "password.txt"
    secret_file.write_text("file-secret-password\n", encoding="utf-8")
    with mock.patch.dict(
        os.environ,
        {
            "DASHBOARD_PASSWORD_FILE": str(secret_file),
            "SESSION_SECRET": "s" * 32,
        },
        clear=True,
    ):
        settings = get_settings()
        assert settings.dashboard_password == "file-secret-password"


def test_session_secret_loaded_from_file(tmp_path: Path) -> None:
    secret_file = tmp_path / "session_secret.txt"
    secret_content = "x" * 48
    secret_file.write_text(f"{secret_content}\n", encoding="utf-8")
    with mock.patch.dict(
        os.environ,
        {
            "DASHBOARD_PASSWORD": "some-password",
            "SESSION_SECRET_FILE": str(secret_file),
        },
        clear=True,
    ):
        settings = get_settings()
        assert settings.session_secret == secret_content


def test_both_password_sources_simultaneously_fails_closed(tmp_path: Path) -> None:
    secret_file = tmp_path / "password.txt"
    secret_file.write_text("file-password", encoding="utf-8")
    with mock.patch.dict(
        os.environ,
        {
            "DASHBOARD_PASSWORD": "env-password",
            "DASHBOARD_PASSWORD_FILE": str(secret_file),
            "SESSION_SECRET": "s" * 32,
        },
        clear=True,
    ):
        with pytest.raises(ValueError, match="both DASHBOARD_PASSWORD and DASHBOARD_PASSWORD_FILE"):
            get_settings()


def test_both_session_secret_sources_simultaneously_fails_closed(tmp_path: Path) -> None:
    secret_file = tmp_path / "session.txt"
    secret_file.write_text("s" * 32, encoding="utf-8")
    with mock.patch.dict(
        os.environ,
        {
            "DASHBOARD_PASSWORD": "env-password",
            "SESSION_SECRET": "s" * 32,
            "SESSION_SECRET_FILE": str(secret_file),
        },
        clear=True,
    ):
        with pytest.raises(ValueError, match="both SESSION_SECRET and SESSION_SECRET_FILE"):
            get_settings()


def test_missing_secret_file_fails_securely() -> None:
    with mock.patch.dict(
        os.environ,
        {
            "DASHBOARD_PASSWORD_FILE": "/nonexistent/path/to/password.txt",
            "SESSION_SECRET": "s" * 32,
        },
        clear=True,
    ):
        with pytest.raises(ValueError, match="does not exist or is not a regular file"):
            get_settings()


def test_empty_secret_file_fails_securely(tmp_path: Path) -> None:
    secret_file = tmp_path / "empty.txt"
    secret_file.write_text("   \n", encoding="utf-8")
    with mock.patch.dict(
        os.environ,
        {
            "DASHBOARD_PASSWORD_FILE": str(secret_file),
            "SESSION_SECRET": "s" * 32,
        },
        clear=True,
    ):
        with pytest.raises(ValueError, match="is empty"):
            get_settings()


def test_session_secret_too_short_fails_securely() -> None:
    with mock.patch.dict(
        os.environ,
        {
            "DASHBOARD_PASSWORD": "env-password",
            "SESSION_SECRET": "too-short-secret",
        },
        clear=True,
    ):
        with pytest.raises(ValueError, match="SESSION_SECRET must be at least 32 characters long"):
            get_settings()


@pytest.mark.parametrize(
    "valid_val,expected",
    [("true", True), ("TRUE", True), ("1", True), ("false", False), ("0", False)],
)
def test_auth_disabled_strictly_supported_values(valid_val: str, expected: bool) -> None:
    env = {
        "AUTH_DISABLED": valid_val,
    }
    if not expected:
        env["DASHBOARD_PASSWORD"] = "test-pass"
        env["SESSION_SECRET"] = "s" * 32

    with mock.patch.dict(os.environ, env, clear=True):
        settings = get_settings()
        assert settings.auth_disabled is expected


@pytest.mark.parametrize("invalid_val", ["yes", "no", "disabled", "enabled", "2", "truee"])
def test_auth_disabled_invalid_values_fail_strictly(invalid_val: str) -> None:
    with mock.patch.dict(
        os.environ,
        {
            "AUTH_DISABLED": invalid_val,
            "DASHBOARD_PASSWORD": "test-pass",
            "SESSION_SECRET": "s" * 32,
        },
        clear=True,
    ):
        with pytest.raises(ValueError, match="Must be explicitly 'true', 'false', '1', or '0'"):
            get_settings()


def test_default_cookie_secure_is_true() -> None:
    with mock.patch.dict(
        os.environ,
        {
            "DASHBOARD_PASSWORD": "test-password-123",
            "SESSION_SECRET": "s" * 32,
        },
        clear=True,
    ):
        settings = get_settings()
        assert settings.cookie_secure is True


def test_explicit_cookie_secure_false() -> None:
    with mock.patch.dict(
        os.environ,
        {
            "DASHBOARD_PASSWORD": "test-password-123",
            "SESSION_SECRET": "s" * 32,
            "COOKIE_SECURE": "false",
        },
        clear=True,
    ):
        settings = get_settings()
        assert settings.cookie_secure is False


def test_session_cookie_secure_alternate_name() -> None:
    with mock.patch.dict(
        os.environ,
        {
            "DASHBOARD_PASSWORD": "test-password-123",
            "SESSION_SECRET": "s" * 32,
            "SESSION_COOKIE_SECURE": "0",
        },
        clear=True,
    ):
        settings = get_settings()
        assert settings.cookie_secure is False


def test_conflicting_cookie_secure_names_fails_closed() -> None:
    with mock.patch.dict(
        os.environ,
        {
            "DASHBOARD_PASSWORD": "test-password-123",
            "SESSION_SECRET": "s" * 32,
            "COOKIE_SECURE": "true",
            "SESSION_COOKIE_SECURE": "false",
        },
        clear=True,
    ):
        with pytest.raises(
            ValueError, match="Conflicting configuration: COOKIE_SECURE and SESSION_COOKIE_SECURE"
        ):
            get_settings()
