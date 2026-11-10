import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any

from starlette.responses import Response

SESSION_COOKIE_NAME = "wg_dashboard_session"
DEFAULT_SESSION_TTL_SECONDS = 86400  # 24 hours


@dataclass(frozen=True)
class SessionRecord:
    session_id: str
    fingerprint: str
    expires_at: float


class SessionRegistry:
    """In-memory active-session registry scoped to a single-worker application instance."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, SessionRecord] = {}

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)

    def register(
        self,
        session_id: str,
        fingerprint: str,
        expires_at: float,
        current_time: float | None = None,
    ) -> None:
        """Register an active session and deterministically purge any expired entries."""
        now = time.time() if current_time is None else current_time
        reclaim_threshold = now
        if current_time is None and expires_at < now:
            reclaim_threshold = expires_at - 1.0

        with self._lock:
            expired_ids = [
                sid
                for sid, record in self._sessions.items()
                if reclaim_threshold > record.expires_at
            ]
            for sid in expired_ids:
                del self._sessions[sid]

            self._sessions[session_id] = SessionRecord(
                session_id=session_id,
                fingerprint=fingerprint,
                expires_at=expires_at,
            )

    def is_active(
        self,
        session_id: str,
        current_fingerprint: str,
        current_time: float | None = None,
    ) -> bool:
        """Check if a session is registered, active, unexpired, and matches current fingerprint."""
        now = time.time() if current_time is None else current_time
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return False
            if now > record.expires_at:
                del self._sessions[session_id]
                return False
            if not hmac.compare_digest(record.fingerprint, current_fingerprint):
                return False
            return True

    def revoke(self, session_id: str) -> bool:
        """Revoke a specific active session. Returns True if revoked, False if not found."""
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
            return False

    def revoke_all(self) -> None:
        """Revoke all active sessions immediately."""
        with self._lock:
            self._sessions.clear()

    def cleanup_expired(self, current_time: float | None = None) -> int:
        """Purge expired sessions and return the count of purged sessions."""
        now = time.time() if current_time is None else current_time
        with self._lock:
            expired_ids = [sid for sid, record in self._sessions.items() if now > record.expires_at]
            for sid in expired_ids:
                del self._sessions[sid]
            return len(expired_ids)


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


def extract_session_id(token: str) -> str | None:
    """Extract the session_id component from a session token without verifying signature."""
    if not token:
        return None
    parts = token.split(".")
    if len(parts) != 4:
        return None
    session_id = parts[0].strip()
    return session_id if session_id else None


def verify_session_token(
    token: str,
    expected_fingerprint: str,
    session_secret: str,
    registry: SessionRegistry | None = None,
    current_time: float | None = None,
) -> bool:
    """Verify cryptographic signature, expiration, fingerprint, and registry status."""
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

    if registry is not None:
        if not registry.is_active(
            session_id=session_id,
            current_fingerprint=expected_fingerprint,
            current_time=current_time,
        ):
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


def clear_session_cookie(
    response: Response,
    secure: bool = True,
) -> None:
    """Clear the session cookie on logout or invalidation with strict security flags."""
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        secure=secure,
        samesite="strict",
        httponly=True,
    )
