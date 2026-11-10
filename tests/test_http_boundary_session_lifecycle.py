from fastapi.testclient import TestClient

from wireguard_dashboard.app import create_app
from wireguard_dashboard.auth.csrf import (
    CSRF_COOKIE_NAME,
    CSRF_FORM_FIELD,
    CSRF_HEADER_NAME,
)
from wireguard_dashboard.auth.session import (
    SESSION_COOKIE_NAME,
    create_session_token,
)
from wireguard_dashboard.config import Settings


def _get_preauth_csrf(client: TestClient) -> str:
    """Helper to visit /login and retrieve the pre-authentication CSRF token."""
    res = client.get("/login")
    token = res.cookies.get(CSRF_COOKIE_NAME)
    assert isinstance(token, str), "Expected CSRF cookie on /login"
    return token


def _login_client(client: TestClient, password: str = "test-admin-password-123") -> str:
    """Helper to perform full login with valid pre-auth CSRF and return session token."""
    csrf_token = _get_preauth_csrf(client)
    res = client.post(
        "/login",
        data={"password": password, CSRF_FORM_FIELD: csrf_token},
        follow_redirects=False,
    )
    assert res.status_code == 303, f"Login failed: {res.status_code} {res.text}"
    session_token = client.cookies.get(SESSION_COOKIE_NAME)
    assert isinstance(session_token, str)
    return session_token


def test_login_page_renders_csrf_token_and_sets_cookie(client: TestClient) -> None:
    res = client.get("/login")
    assert res.status_code == 200
    csrf_cookie = res.cookies.get(CSRF_COOKIE_NAME)
    assert csrf_cookie is not None
    assert f'name="{CSRF_FORM_FIELD}"' in res.text
    assert f'value="{csrf_cookie}"' in res.text


def test_login_post_without_csrf_returns_403(client: TestClient) -> None:
    res = client.post(
        "/login",
        data={"password": "test-admin-password-123"},
        follow_redirects=False,
    )
    assert res.status_code == 403


def test_login_post_with_mismatched_csrf_returns_403(client: TestClient) -> None:
    client.cookies.set(CSRF_COOKIE_NAME, "cookie-token-abc")
    res = client.post(
        "/login",
        data={"password": "test-admin-password-123", CSRF_FORM_FIELD: "different-token-xyz"},
        follow_redirects=False,
    )
    assert res.status_code == 403


def test_login_post_with_tampered_csrf_returns_403(client: TestClient) -> None:
    token = _get_preauth_csrf(client)
    tampered = token[:-4] + "dead"
    client.cookies.set(CSRF_COOKIE_NAME, tampered)
    res = client.post(
        "/login",
        data={"password": "test-admin-password-123", CSRF_FORM_FIELD: tampered},
        follow_redirects=False,
    )
    assert res.status_code == 403


def test_login_post_with_valid_csrf_succeeds_and_registers_session(client: TestClient) -> None:
    csrf_token = _get_preauth_csrf(client)
    res = client.post(
        "/login",
        data={"password": "test-admin-password-123", CSRF_FORM_FIELD: csrf_token},
        follow_redirects=False,
    )
    assert res.status_code == 303
    assert res.headers["location"] == "/"
    assert client.cookies.get(SESSION_COOKIE_NAME) is not None
    # Follow redirect and verify access to protected dashboard
    dash_res = client.get("/")
    assert dash_res.status_code == 200
    assert "WireGuard Companion" in dash_res.text


def test_session_token_without_active_registry_entry_is_rejected(client: TestClient) -> None:
    # Generate a cryptographically valid token not registered in active registry
    from wireguard_dashboard.auth.security import compute_credential_fingerprint

    secret = "s" * 32
    fp = compute_credential_fingerprint("test-admin-password-123", secret)
    unregistered_token = create_session_token(fingerprint=fp, session_secret=secret)

    client.cookies.set(SESSION_COOKIE_NAME, unregistered_token)
    res = client.get("/", follow_redirects=False)
    # Should be rejected because it is not in the in-memory active-session registry
    assert res.status_code == 303
    assert res.headers["location"] == "/login"


def test_unauthenticated_api_request_returns_401(client: TestClient) -> None:
    # API request (e.g. POST /logout without session)
    res = client.post("/logout", headers={"Accept": "application/json"})
    assert res.status_code == 401


def test_post_logout_without_csrf_returns_403(client: TestClient) -> None:
    _login_client(client)
    # Delete CSRF cookie to simulate missing CSRF
    client.cookies.delete(CSRF_COOKIE_NAME)
    res = client.post("/logout", follow_redirects=False)
    assert res.status_code == 403


def test_post_logout_with_invalid_csrf_returns_403(client: TestClient) -> None:
    _login_client(client)
    client.cookies.set(CSRF_COOKIE_NAME, "forged-csrf-token")
    res = client.post(
        "/logout",
        data={CSRF_FORM_FIELD: "forged-csrf-token"},
        follow_redirects=False,
    )
    assert res.status_code == 403


def test_post_logout_with_cross_session_csrf_returns_403() -> None:
    app = create_app()
    client_a = TestClient(app, base_url="https://testserver")
    client_b = TestClient(app, base_url="https://testserver")

    _login_client(client_a)
    _login_client(client_b)

    csrf_token_a = client_a.cookies.get(CSRF_COOKIE_NAME)
    assert csrf_token_a is not None

    # Client B attempts to use Client A's CSRF token
    client_b.cookies.set(CSRF_COOKIE_NAME, csrf_token_a)
    res = client_b.post(
        "/logout",
        data={CSRF_FORM_FIELD: csrf_token_a},
        follow_redirects=False,
    )
    assert res.status_code == 403


def test_post_logout_with_valid_csrf_revokes_session_and_clears_cookie(client: TestClient) -> None:
    _login_client(client)
    csrf_token = client.cookies.get(CSRF_COOKIE_NAME)
    assert csrf_token is not None

    # POST /logout with matching CSRF via form data
    res = client.post(
        "/logout",
        data={CSRF_FORM_FIELD: csrf_token},
        follow_redirects=False,
    )
    assert res.status_code == 303
    assert res.headers["location"] == "/login"

    # Verify cookies were cleared in response headers
    if hasattr(res.headers, "get_list"):
        set_cookie_headers = res.headers.get_list("set-cookie")
    else:
        set_cookie_headers = [res.headers.get("set-cookie", "")]
    combined_cookies = " ".join(set_cookie_headers)
    assert f"{SESSION_COOKIE_NAME}=" in combined_cookies
    assert f"{CSRF_COOKIE_NAME}=" in combined_cookies
    assert "max-age=0" in combined_cookies.lower() or "expires=" in combined_cookies.lower()


def test_post_logout_with_valid_csrf_via_header(client: TestClient) -> None:
    _login_client(client)
    csrf_token = client.cookies.get(CSRF_COOKIE_NAME)
    assert csrf_token is not None

    # POST /logout with matching CSRF via X-CSRF-Token header
    res = client.post(
        "/logout",
        headers={CSRF_HEADER_NAME: csrf_token},
        follow_redirects=False,
    )
    assert res.status_code == 303
    assert res.headers["location"] == "/login"


def test_reusing_logged_out_session_cookie_fails(client: TestClient) -> None:
    _login_client(client)
    csrf_token = client.cookies.get(CSRF_COOKIE_NAME)
    assert csrf_token is not None
    saved_session_cookie = client.cookies.get(SESSION_COOKIE_NAME)
    assert saved_session_cookie is not None

    # Logout
    logout_res = client.post("/logout", data={CSRF_FORM_FIELD: csrf_token}, follow_redirects=False)
    assert logout_res.status_code == 303

    # Attempt to access protected route with the saved session cookie
    client.cookies.set(SESSION_COOKIE_NAME, saved_session_cookie)
    res = client.get("/", follow_redirects=False)
    assert res.status_code == 303
    assert res.headers["location"] == "/login"


def test_logging_out_one_device_does_not_revoke_other_active_devices() -> None:
    app = create_app()
    device_a = TestClient(app, base_url="https://testserver")
    device_b = TestClient(app, base_url="https://testserver")

    _login_client(device_a)
    _login_client(device_b)

    # Both devices can access protected endpoint
    assert device_a.get("/").status_code == 200
    assert device_b.get("/").status_code == 200

    # Device A logs out
    csrf_a = device_a.cookies.get(CSRF_COOKIE_NAME)
    assert csrf_a is not None
    logout_a = device_a.post(
        "/logout",
        data={CSRF_FORM_FIELD: csrf_a},
        follow_redirects=False,
    )
    assert logout_a.status_code == 303

    # Device A is revoked
    assert device_a.get("/", follow_redirects=False).status_code == 303

    # Device B remains fully active
    assert device_b.get("/").status_code == 200


def test_restart_invalidation_across_independent_app_instances() -> None:
    settings = Settings(
        dashboard_password="master-password-123",
        session_secret="k" * 32,
    )

    # Instance A
    app_a = create_app(settings)
    client_a = TestClient(app_a, base_url="https://testserver")
    session_token = _login_client(client_a, password="master-password-123")
    assert client_a.get("/").status_code == 200

    # Instance B (simulating container restart with identical configuration)
    app_b = create_app(settings)
    client_b = TestClient(app_b, base_url="https://testserver")

    # Present Instance A's session token to Instance B
    client_b.cookies.set(SESSION_COOKIE_NAME, session_token)
    res = client_b.get("/", follow_redirects=False)
    # Must be rejected because Instance B has a clean in-memory active registry
    assert res.status_code == 303
    assert res.headers["location"] == "/login"


def test_credential_rotation_password_invalidates_all_active_sessions() -> None:
    settings_v1 = Settings(
        dashboard_password="old-password-123",
        session_secret="k" * 32,
    )
    app_v1 = create_app(settings_v1)
    client_v1 = TestClient(app_v1, base_url="https://testserver")
    session_token = _login_client(client_v1, password="old-password-123")
    assert client_v1.get("/").status_code == 200

    # Credential rotated: new password
    settings_v2 = Settings(
        dashboard_password="new-rotated-password-456",
        session_secret="k" * 32,
    )
    app_v2 = create_app(settings_v2)
    client_v2 = TestClient(app_v2, base_url="https://testserver")

    client_v2.cookies.set(SESSION_COOKIE_NAME, session_token)
    res = client_v2.get("/", follow_redirects=False)
    assert res.status_code == 303
    assert res.headers["location"] == "/login"


def test_credential_rotation_session_secret_invalidates_all_active_sessions() -> None:
    settings_v1 = Settings(
        dashboard_password="master-password-123",
        session_secret="1" * 32,
    )
    app_v1 = create_app(settings_v1)
    client_v1 = TestClient(app_v1, base_url="https://testserver")
    session_token = _login_client(client_v1, password="master-password-123")
    assert client_v1.get("/").status_code == 200

    # Secret rotated: new session secret
    settings_v2 = Settings(
        dashboard_password="master-password-123",
        session_secret="2" * 32,
    )
    app_v2 = create_app(settings_v2)
    client_v2 = TestClient(app_v2, base_url="https://testserver")

    client_v2.cookies.set(SESSION_COOKIE_NAME, session_token)
    res = client_v2.get("/", follow_redirects=False)
    assert res.status_code == 303
    assert res.headers["location"] == "/login"


def test_revoked_or_old_token_cannot_regain_validity_if_earlier_credential_restored() -> None:
    settings_orig = Settings(
        dashboard_password="original-password-123",
        session_secret="k" * 32,
    )
    app_orig = create_app(settings_orig)
    client_orig = TestClient(app_orig, base_url="https://testserver")
    token = _login_client(client_orig, password="original-password-123")
    csrf_token = client_orig.cookies.get(CSRF_COOKIE_NAME)
    assert csrf_token is not None

    # Explicitly logout (revoking session in in-memory registry)
    logout_res = client_orig.post(
        "/logout",
        data={CSRF_FORM_FIELD: csrf_token},
        follow_redirects=False,
    )
    assert logout_res.status_code == 303

    # Even with same app or restored credentials, token was revoked from active registry
    client_orig.cookies.set(SESSION_COOKIE_NAME, token)
    res = client_orig.get("/", follow_redirects=False)
    assert res.status_code == 303
    assert res.headers["location"] == "/login"
