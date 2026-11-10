from wireguard_dashboard.auth.csrf import (
    CSRF_COOKIE_NAME,
    clear_csrf_cookie,
    create_preauth_csrf_token,
    create_session_csrf_token,
    set_csrf_cookie,
    verify_csrf_double_submit,
)


def test_create_and_verify_valid_preauth_csrf_token() -> None:
    session_secret = "s" * 32
    token = create_preauth_csrf_token(session_secret)

    # Valid double submit with matching cookie and form/header token
    assert (
        verify_csrf_double_submit(
            cookie_token=token,
            submitted_token=token,
            session_secret=session_secret,
            expected_session_id=None,
        )
        is True
    )


def test_create_and_verify_valid_session_csrf_token() -> None:
    session_secret = "s" * 32
    session_id = "session-12345"
    token = create_session_csrf_token(session_id=session_id, session_secret=session_secret)

    # Valid session-bound double submit
    assert (
        verify_csrf_double_submit(
            cookie_token=token,
            submitted_token=token,
            session_secret=session_secret,
            expected_session_id=session_id,
        )
        is True
    )


def test_missing_cookie_or_submitted_token_rejected() -> None:
    session_secret = "s" * 32
    session_id = "session-12345"
    token = create_session_csrf_token(session_id=session_id, session_secret=session_secret)

    # Missing cookie token
    assert not verify_csrf_double_submit(
        cookie_token=None,
        submitted_token=token,
        session_secret=session_secret,
        expected_session_id=session_id,
    )
    # Missing submitted token
    assert not verify_csrf_double_submit(
        cookie_token=token,
        submitted_token=None,
        session_secret=session_secret,
        expected_session_id=session_id,
    )
    # Empty strings
    assert not verify_csrf_double_submit(
        cookie_token="",
        submitted_token=token,
        session_secret=session_secret,
        expected_session_id=session_id,
    )
    assert not verify_csrf_double_submit(
        cookie_token=token,
        submitted_token="",
        session_secret=session_secret,
        expected_session_id=session_id,
    )


def test_mismatched_cookie_and_submitted_token_rejected() -> None:
    session_secret = "s" * 32
    session_id = "session-12345"
    token1 = create_session_csrf_token(session_id=session_id, session_secret=session_secret)
    token2 = create_session_csrf_token(session_id=session_id, session_secret=session_secret)

    assert not verify_csrf_double_submit(
        cookie_token=token1,
        submitted_token=token2,
        session_secret=session_secret,
        expected_session_id=session_id,
    )


def test_tampered_csrf_token_rejected() -> None:
    session_secret = "s" * 32
    session_id = "session-12345"
    token = create_session_csrf_token(session_id=session_id, session_secret=session_secret)
    tampered = token[:-4] + "dead"

    assert not verify_csrf_double_submit(
        cookie_token=tampered,
        submitted_token=tampered,
        session_secret=session_secret,
        expected_session_id=session_id,
    )


def test_cross_session_csrf_token_reuse_rejected() -> None:
    session_secret = "s" * 32
    session_a = "session-user-a"
    session_b = "session-user-b"

    # Token generated for session A
    token_a = create_session_csrf_token(session_id=session_a, session_secret=session_secret)

    # Attempt to use Token A on a route authenticated as Session B
    assert not verify_csrf_double_submit(
        cookie_token=token_a,
        submitted_token=token_a,
        session_secret=session_secret,
        expected_session_id=session_b,
    )


def test_preauth_token_rejected_for_authenticated_route_and_vice_versa() -> None:
    session_secret = "s" * 32
    session_id = "session-123"

    preauth_token = create_preauth_csrf_token(session_secret)
    session_token = create_session_csrf_token(session_id, session_secret)

    # Preauth token used on authenticated route
    assert not verify_csrf_double_submit(
        cookie_token=preauth_token,
        submitted_token=preauth_token,
        session_secret=session_secret,
        expected_session_id=session_id,
    )

    # Session token used on pre-auth route
    assert not verify_csrf_double_submit(
        cookie_token=session_token,
        submitted_token=session_token,
        session_secret=session_secret,
        expected_session_id=None,
    )


def test_csrf_cookie_attributes_and_clearing() -> None:
    from starlette.responses import Response

    response = Response()
    token = "csrf.token.value"
    set_csrf_cookie(response=response, token=token, secure=True)

    header = response.headers.get("set-cookie")
    assert header is not None
    assert f"{CSRF_COOKIE_NAME}={token}" in header
    # Double-submit cookie is intentionally accessible by scripts/headers, not HttpOnly
    assert "samesite=strict" in header.lower()
    assert "Secure" in header
    assert "path=/" in header.lower()

    # Test clearing cookie
    clear_resp = Response()
    clear_csrf_cookie(response=clear_resp, secure=True)
    clear_header = clear_resp.headers.get("set-cookie")
    assert clear_header is not None
    assert f"{CSRF_COOKIE_NAME}=" in clear_header
    assert "max-age=0" in clear_header.lower() or "expires=" in clear_header.lower()
