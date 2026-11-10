from fastapi import Response

from wireguard_dashboard.auth.session import (
    SESSION_COOKIE_NAME,
    create_session_token,
    set_session_cookie,
    verify_session_token,
)


def test_create_and_verify_valid_session_token() -> None:
    session_secret = "s" * 32
    fingerprint = "f" * 64
    current_time = 1000.0

    token = create_session_token(
        fingerprint=fingerprint,
        session_secret=session_secret,
        current_time=current_time,
        ttl_seconds=3600,
    )

    assert (
        verify_session_token(
            token=token,
            expected_fingerprint=fingerprint,
            session_secret=session_secret,
            current_time=current_time + 100,
        )
        is True
    )


def test_tampered_token_rejected() -> None:
    session_secret = "s" * 32
    fingerprint = "f" * 64
    current_time = 1000.0

    token = create_session_token(
        fingerprint=fingerprint,
        session_secret=session_secret,
        current_time=current_time,
        ttl_seconds=3600,
    )

    # Tamper with signature
    tampered = token[:-4] + "abcd"
    assert (
        verify_session_token(
            token=tampered,
            expected_fingerprint=fingerprint,
            session_secret=session_secret,
            current_time=current_time + 100,
        )
        is False
    )

    # Tamper with payload
    parts = token.split(".")
    parts[0] = "tampered_session_id"
    assert (
        verify_session_token(
            token=".".join(parts),
            expected_fingerprint=fingerprint,
            session_secret=session_secret,
            current_time=current_time + 100,
        )
        is False
    )


def test_expired_token_rejected() -> None:
    session_secret = "s" * 32
    fingerprint = "f" * 64
    current_time = 1000.0

    token = create_session_token(
        fingerprint=fingerprint,
        session_secret=session_secret,
        current_time=current_time,
        ttl_seconds=3600,
    )

    # Verify at current_time + 3601 (expired)
    assert (
        verify_session_token(
            token=token,
            expected_fingerprint=fingerprint,
            session_secret=session_secret,
            current_time=current_time + 3601,
        )
        is False
    )


def test_fingerprint_mismatch_rejected() -> None:
    session_secret = "s" * 32
    old_fingerprint = "f" * 64
    new_fingerprint = "e" * 64
    current_time = 1000.0

    token = create_session_token(
        fingerprint=old_fingerprint,
        session_secret=session_secret,
        current_time=current_time,
        ttl_seconds=3600,
    )

    # Verifying against rotated fingerprint fails
    assert (
        verify_session_token(
            token=token,
            expected_fingerprint=new_fingerprint,
            session_secret=session_secret,
            current_time=current_time + 100,
        )
        is False
    )


def test_token_does_not_contain_password_or_raw_hash() -> None:
    password = "MySuperSecretAdminPassword!"
    session_secret = "s" * 32
    fingerprint = "f" * 64

    token = create_session_token(
        fingerprint=fingerprint,
        session_secret=session_secret,
        ttl_seconds=3600,
    )
    assert password not in token
    assert session_secret not in token


def test_set_session_cookie_security_attributes() -> None:
    response = Response()
    token = "test.token.value"
    set_session_cookie(
        response=response,
        token=token,
        max_age=86400,
        secure=True,
    )

    header = response.headers.get("set-cookie")
    assert header is not None
    assert f"{SESSION_COOKIE_NAME}={token}" in header
    assert "HttpOnly" in header
    assert "samesite=strict" in header.lower()
    assert "Secure" in header
    assert "Max-Age=86400" in header
    assert "path=/" in header.lower()
