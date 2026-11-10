import hashlib
import hmac
import secrets
from typing import Any

from starlette.responses import Response

CSRF_COOKIE_NAME = "wg_dashboard_csrf"
CSRF_FORM_FIELD = "csrf_token"
CSRF_HEADER_NAME = "x-csrf-token"


def create_preauth_csrf_token(session_secret: str) -> str:
    """Generate a signed CSRF token for pre-authenticated operations (such as login)."""
    nonce = secrets.token_hex(16)
    payload = f"preauth.{nonce}"
    signature = hmac.new(
        session_secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload}.{signature}"


def create_session_csrf_token(session_id: str, session_secret: str) -> str:
    """Generate a signed CSRF token bound to an active session ID."""
    nonce = secrets.token_hex(16)
    payload = f"auth.{session_id}.{nonce}"
    signature = hmac.new(
        session_secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload}.{signature}"


def verify_csrf_double_submit(
    cookie_token: str | None,
    submitted_token: str | None,
    session_secret: str,
    expected_session_id: str | None = None,
) -> bool:
    """Validate double-submit CSRF token matching, HMAC signature, and session binding."""
    if not cookie_token or not submitted_token or not session_secret:
        return False

    # Constant-time comparison between cookie token and submitted token
    if not hmac.compare_digest(cookie_token, submitted_token):
        return False

    parts = submitted_token.split(".")
    if expected_session_id is not None:
        # Authenticated route: expects "auth.<session_id>.<nonce>.<sig>"
        if len(parts) != 4 or parts[0] != "auth":
            return False
        token_session_id = parts[1]
        nonce = parts[2]
        signature = parts[3]

        if not hmac.compare_digest(token_session_id, expected_session_id):
            return False

        payload = f"auth.{token_session_id}.{nonce}"
        expected_sig = hmac.new(
            session_secret.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(signature, expected_sig)
    else:
        # Pre-auth route: expects "preauth.<nonce>.<sig>"
        if len(parts) != 3 or parts[0] != "preauth":
            return False
        nonce = parts[1]
        signature = parts[2]

        payload = f"preauth.{nonce}"
        expected_sig = hmac.new(
            session_secret.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return hmac.compare_digest(signature, expected_sig)


def set_csrf_cookie(
    response: Response,
    token: str,
    secure: bool = True,
) -> None:
    """Set the double-submit CSRF cookie.

    Accessible to JavaScript for X-CSRF-Token headers, strictly scoped with SameSite=Strict.
    """
    kwargs: dict[str, Any] = {
        "key": CSRF_COOKIE_NAME,
        "value": token,
        "httponly": False,
        "samesite": "strict",
        "secure": secure,
        "path": "/",
    }
    response.set_cookie(**kwargs)


def clear_csrf_cookie(
    response: Response,
    secure: bool = True,
) -> None:
    """Clear the CSRF cookie on logout or invalidation."""
    response.delete_cookie(
        key=CSRF_COOKIE_NAME,
        path="/",
        secure=secure,
        samesite="strict",
        httponly=False,
    )
