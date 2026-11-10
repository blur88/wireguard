import hashlib
import hmac
import secrets
import time
from typing import Any

from starlette.responses import Response

SESSION_COOKIE_NAME = "wg_dashboard_session"
DEFAULT_SESSION_TTL_SECONDS = 86400  # 24 hours


def create_session_token(
    fingerprint: str,
    session_secret: str,
    current_time: float | None = None,
    ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
) -> str:
    """Generate a cryptographically signed session token bound to a credential fingerprint."""
    session_id = secrets.token_hex(16)
    now = time.time() if current_time is None else current_time
    expires_at = int(now + ttl_seconds)

    payload = f"{session_id}.{fingerprint}.{expires_at}"
    signature = hmac.new(
        session_secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return f"{payload}.{signature}"


def verify_session_token(
    token: str,
    expected_fingerprint: str,
    session_secret: str,
    current_time: float | None = None,
) -> bool:
    """Verify cryptographic signature, expiration, and credential fingerprint of a session token."""
    if not token or not expected_fingerprint or not session_secret:
        return False

    parts = token.split(".")
    if len(parts) != 4:
        return False

    session_id, token_fingerprint, expires_at_str, signature = parts

    payload = f"{session_id}.{token_fingerprint}.{expires_at_str}"
    expected_sig = hmac.new(
        session_secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_sig):
        return False

    try:
        expires_at = int(expires_at_str)
    except ValueError:
        return False

    now = time.time() if current_time is None else current_time
    if now > expires_at:
        return False

    if not hmac.compare_digest(token_fingerprint, expected_fingerprint):
        return False

    return True


def set_session_cookie(
    response: Response,
    token: str,
    max_age: int = DEFAULT_SESSION_TTL_SECONDS,
    secure: bool = True,
) -> None:
    """Set the signed session cookie with strict security flags."""
    kwargs: dict[str, Any] = {
        "key": SESSION_COOKIE_NAME,
        "value": token,
        "max_age": max_age,
        "httponly": True,
        "samesite": "strict",
        "secure": secure,
        "path": "/",
    }
    response.set_cookie(**kwargs)


def clear_session_cookie(response: Response) -> None:
    """Clear the session cookie from the browser."""
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        httponly=True,
        samesite="strict",
    )
