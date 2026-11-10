import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """Application configuration settings."""

    port: int = 8080
    auth_disabled: bool = False
    dashboard_password: str | None = None
    session_secret: str | None = None
    cookie_secure: bool = True
    config_dir: Path = Path("/config")


def _load_secret(
    env_var_name: str,
    file_var_name: str,
    secret_label: str,
    min_length: int = 1,
) -> str | None:
    """Load a secret from either an environment variable or a file path.

    Fails closed if both sources are set, or if the specified file is missing,
    unreadable, empty, or below the required minimum length.
    """
    env_val = os.environ.get(env_var_name)
    file_val = os.environ.get(file_var_name)

    has_env = env_val is not None and env_val.strip() != ""
    has_file = file_val is not None and file_val.strip() != ""

    if has_env and has_file:
        raise ValueError(
            f"Ambiguous configuration: both {env_var_name} and {file_var_name} are set. "
            "Configure only one credential source."
        )

    secret: str | None = None
    if has_env:
        assert env_val is not None
        secret = env_val.strip()
    elif has_file:
        assert file_val is not None
        secret_path = Path(file_val.strip())
        if not secret_path.is_file():
            raise ValueError(
                f"Configured {file_var_name} path '{secret_path}' "
                "does not exist or is not a regular file."
            )
        try:
            content = secret_path.read_text(encoding="utf-8")
        except OSError as err:
            raise ValueError(
                f"Configured {file_var_name} path '{secret_path}' could not be read: {err}"
            ) from err

        stripped = content.strip()
        if not stripped:
            raise ValueError(f"Configured {file_var_name} path '{secret_path}' is empty.")
        secret = stripped

    if secret is not None and len(secret) < min_length:
        raise ValueError(f"{secret_label} must be at least {min_length} characters long.")

    return secret


def _parse_bool(var_name: str, default: bool = False) -> bool:
    """Parse a boolean environment variable strictly."""
    raw = os.environ.get(var_name)
    if raw is None or raw.strip() == "":
        return default

    normalized = raw.strip().lower()
    if normalized in ("true", "1"):
        return True
    if normalized in ("false", "0"):
        return False

    raise ValueError(
        f"Invalid {var_name} value: '{raw}'. Must be explicitly 'true', 'false', '1', or '0'."
    )


def get_settings() -> Settings:
    """Parse and validate application settings from environment variables."""
    raw_port = os.environ.get("PORT", "").strip()
    port = 8080
    if raw_port:
        try:
            port = int(raw_port)
        except ValueError as err:
            raise ValueError(f"Invalid PORT: '{raw_port}' is not a valid integer") from err

        if port < 1 or port > 65535:
            raise ValueError(f"Invalid PORT: {port} must be between 1 and 65535")

    auth_disabled = _parse_bool("AUTH_DISABLED", default=False)
    dashboard_password = _load_secret(
        env_var_name="DASHBOARD_PASSWORD",
        file_var_name="DASHBOARD_PASSWORD_FILE",
        secret_label="DASHBOARD_PASSWORD",
        min_length=1,
    )
    session_secret = _load_secret(
        env_var_name="SESSION_SECRET",
        file_var_name="SESSION_SECRET_FILE",
        secret_label="SESSION_SECRET",
        min_length=32,
    )

    if not auth_disabled:
        if dashboard_password is None:
            raise ValueError(
                "DASHBOARD_PASSWORD or DASHBOARD_PASSWORD_FILE is required "
                "when authentication is enabled."
            )
        if session_secret is None:
            raise ValueError(
                "SESSION_SECRET or SESSION_SECRET_FILE is required when authentication is enabled."
            )

    cookie_secure_val = os.environ.get("COOKIE_SECURE")
    session_cookie_secure_val = os.environ.get("SESSION_COOKIE_SECURE")

    if (
        cookie_secure_val is not None
        and session_cookie_secure_val is not None
        and _parse_bool("COOKIE_SECURE") != _parse_bool("SESSION_COOKIE_SECURE")
    ):
        raise ValueError(
            "Conflicting configuration: COOKIE_SECURE and SESSION_COOKIE_SECURE "
            "have different values."
        )

    var_to_parse = "COOKIE_SECURE" if cookie_secure_val is not None else "SESSION_COOKIE_SECURE"
    cookie_secure = _parse_bool(var_to_parse, default=True)

    raw_config_dir = os.environ.get("CONFIG_DIR", "").strip()
    config_dir = Path(raw_config_dir) if raw_config_dir else Path("/config")

    return Settings(
        port=port,
        auth_disabled=auth_disabled,
        dashboard_password=dashboard_password,
        session_secret=session_secret,
        cookie_secure=cookie_secure,
        config_dir=config_dir,
    )
