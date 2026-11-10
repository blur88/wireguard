import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    """Application configuration settings."""

    port: int = 8080


def get_settings() -> Settings:
    """Parse and validate application settings from environment variables."""
    raw_port = os.environ.get("PORT", "").strip()
    if not raw_port:
        return Settings()

    try:
        port = int(raw_port)
    except ValueError:
        raise ValueError(f"Invalid PORT: '{raw_port}' is not a valid integer")

    if port < 1 or port > 65535:
        raise ValueError(f"Invalid PORT: {port} must be between 1 and 65535")

    return Settings(port=port)
