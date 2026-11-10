import pytest
from fastapi.testclient import TestClient

from wireguard_dashboard.app import create_app
from wireguard_dashboard.auth.csrf import CSRF_COOKIE_NAME, CSRF_FORM_FIELD
from wireguard_dashboard.auth.session import SESSION_COOKIE_NAME
from wireguard_dashboard.config import Settings


def _fetch_csrf_token(client: TestClient) -> str:
    """Helper to load /login, acquire pre-auth CSRF token, and return it."""
    res = client.get("/login")
    token = res.cookies.get(CSRF_COOKIE_NAME)
    assert isinstance(token, str)
    return token


def test_login_page_renders_dark_mode_form(client: TestClient) -> None:
    response = client.get("/login")
    assert response.status_code == 200
    assert 'type="password"' in response.text
    assert 'name="password"' in response.text
    assert "WireGuard Companion" in response.text
    # Verify Content Security Policy is preserved
    assert "content-security-policy" in response.headers


def test_unauthenticated_protected_route_redirects_to_login(client: TestClient) -> None:
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_healthz_remains_unauthenticated(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_static_assets_remain_unauthenticated(client: TestClient) -> None:
    response = client.get("/static/style.css")
    assert response.status_code == 200


def test_successful_login_sets_cookie_and_redirects(client: TestClient) -> None:
    csrf = _fetch_csrf_token(client)
    response = client.post(
        "/login",
        data={"password": "test-admin-password-123", CSRF_FORM_FIELD: csrf},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/"

    cookie = response.cookies.get(SESSION_COOKIE_NAME)
    assert cookie is not None
    set_cookie_header = response.headers.get("set-cookie", "")
    assert "httponly" in set_cookie_header.lower()
    assert "samesite=strict" in set_cookie_header.lower()
    assert "secure" in set_cookie_header.lower()
    assert "test-admin-password" not in set_cookie_header


def test_successful_session_allows_access_to_protected_route(client: TestClient) -> None:
    # 1. Login
    csrf = _fetch_csrf_token(client)
    login_res = client.post(
        "/login",
        data={"password": "test-admin-password-123", CSRF_FORM_FIELD: csrf},
        follow_redirects=False,
    )
    assert login_res.status_code == 303

    # 2. Access protected endpoint with cookie
    response = client.get("/")
    assert response.status_code == 200
    assert "WireGuard Companion" in response.text


def test_invalid_password_returns_401_without_leaks(client: TestClient) -> None:
    csrf = _fetch_csrf_token(client)
    response = client.post(
        "/login",
        data={"password": "wrong-password", CSRF_FORM_FIELD: csrf},
        follow_redirects=False,
    )
    assert response.status_code == 401
    assert "Invalid credentials" in response.text
    assert "test-admin-password" not in response.text
    assert "$argon2id$" not in response.text


def test_failed_logins_trigger_429(client: TestClient) -> None:
    csrf = _fetch_csrf_token(client)
    # Attempt 5 wrong logins
    for _ in range(5):
        res = client.post(
            "/login",
            data={"password": "wrong", CSRF_FORM_FIELD: csrf},
            follow_redirects=False,
        )
        assert res.status_code == 401

    # 6th attempt should be rejected with 429
    res6 = client.post(
        "/login",
        data={"password": "wrong", CSRF_FORM_FIELD: csrf},
        follow_redirects=False,
    )
    assert res6.status_code == 429
    assert "Retry-After" in res6.headers or "retry-after" in res6.headers


def test_tampered_or_expired_cookie_redirects_to_login(client: TestClient) -> None:
    client.cookies.set(SESSION_COOKIE_NAME, "tampered.cookie.value.signature")
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_security_headers_present_on_login_and_redirects(client: TestClient) -> None:
    for path in ["/login", "/healthz"]:
        res = client.get(path)
        assert "content-security-policy" in res.headers
        assert res.headers["x-frame-options"] == "DENY"
        assert res.headers["x-content-type-options"] == "nosniff"


def test_auth_disabled_allows_direct_access_without_login() -> None:
    settings = Settings(
        port=8080,
        auth_disabled=True,
    )
    app = create_app(settings=settings)
    custom_client = TestClient(app)

    # Protected route is directly accessible
    res = custom_client.get("/")
    assert res.status_code == 200
    assert "WireGuard Companion" in res.text


def test_reverse_proxy_internal_http_still_issues_secure_cookie() -> None:
    settings = Settings(
        port=8080,
        dashboard_password="test-admin-password-123",
        session_secret="s" * 32,
        cookie_secure=True,
    )
    app = create_app(settings=settings)
    # Reverse proxy speaks HTTP internally to container
    proxy_client = TestClient(app, base_url="http://127.0.0.1:8080")
    csrf = _fetch_csrf_token(proxy_client)
    # Explicitly retain Secure cookie in TestClient over insecure http:// backend simulation
    proxy_client.cookies.set(CSRF_COOKIE_NAME, csrf)
    res = proxy_client.post(
        "/login",
        data={"password": "test-admin-password-123", CSRF_FORM_FIELD: csrf},
        headers={"x-forwarded-proto": "https"},
        follow_redirects=False,
    )
    assert res.status_code == 303
    set_cookie = res.headers.get("set-cookie", "")
    assert "secure" in set_cookie.lower()
    assert "httponly" in set_cookie.lower()
    assert "samesite=strict" in set_cookie.lower()


def test_untrusted_forwarded_proto_cannot_disable_secure_cookie() -> None:
    settings = Settings(
        port=8080,
        dashboard_password="test-admin-password-123",
        session_secret="s" * 32,
        cookie_secure=True,
    )
    app = create_app(settings=settings)
    client = TestClient(app, base_url="https://testserver")
    # Untrusted client sends spoofed header attempting to degrade security
    csrf = _fetch_csrf_token(client)
    res = client.post(
        "/login",
        data={"password": "test-admin-password-123", CSRF_FORM_FIELD: csrf},
        headers={"x-forwarded-proto": "http"},
        follow_redirects=False,
    )
    assert res.status_code == 303
    set_cookie = res.headers.get("set-cookie", "")
    assert "secure" in set_cookie.lower()


def test_explicit_insecure_dev_mode_disables_secure_flag_with_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    import logging

    settings = Settings(
        port=8080,
        dashboard_password="test-admin-password-123",
        session_secret="s" * 32,
        cookie_secure=False,
    )
    with caplog.at_level(logging.WARNING):
        app = create_app(settings=settings)
        assert any(
            "SECURITY WARNING" in record.message and "COOKIE_SECURE=false" in record.message
            for record in caplog.records
        )

    dev_client = TestClient(app, base_url="http://localhost:8080")
    csrf = _fetch_csrf_token(dev_client)
    res = dev_client.post(
        "/login",
        data={"password": "test-admin-password-123", CSRF_FORM_FIELD: csrf},
        follow_redirects=False,
    )
    assert res.status_code == 303
    set_cookie = res.headers.get("set-cookie", "")
    # Secure flag must NOT be present in explicit dev mode
    assert "secure" not in set_cookie.lower()
    # But HttpOnly and SameSite=Strict must remain intact
    assert "httponly" in set_cookie.lower()
    assert "samesite=strict" in set_cookie.lower()
