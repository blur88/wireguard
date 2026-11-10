from pathlib import Path

import pytest
from starlette.testclient import TestClient

from wireguard_dashboard.app import create_app
from wireguard_dashboard.auth.csrf import (
    CSRF_COOKIE_NAME,
    CSRF_FORM_FIELD,
    create_session_csrf_token,
)
from wireguard_dashboard.auth.session import SESSION_COOKIE_NAME
from wireguard_dashboard.config import Settings
from wireguard_dashboard.peers.backend import ReadOnlyFilesystemBackend


def _create_authenticated_client(
    config_dir: Path,
    password: str = "correct_password",
    session_secret: str = "a" * 32,
) -> tuple[TestClient, str]:
    settings = Settings(
        dashboard_password=password,
        session_secret=session_secret,
        auth_disabled=False,
        cookie_secure=True,
    )
    backend = ReadOnlyFilesystemBackend(config_dir=config_dir)
    app = create_app(settings=settings, peer_backend=backend)
    client = TestClient(app, base_url="https://testserver")

    # Log in through the standard flow to get valid session and CSRF cookies in the jar
    client.get("/login")
    login_csrf = client.cookies.get(CSRF_COOKIE_NAME)
    assert login_csrf is not None

    login_post = client.post(
        "/login",
        data={"password": password, CSRF_FORM_FIELD: login_csrf},
        follow_redirects=False,
    )
    assert login_post.status_code == 303

    session_cookie = client.cookies.get(SESSION_COOKIE_NAME)
    session_csrf = client.cookies.get(CSRF_COOKIE_NAME)
    assert session_cookie is not None
    assert session_csrf is not None

    return client, session_csrf


def test_dashboard_unauthenticated_redirects_to_login(tmp_path: Path) -> None:
    settings = Settings(
        dashboard_password="password123",
        session_secret="s" * 32,
        auth_disabled=False,
    )
    app = create_app(settings=settings, peer_backend=ReadOnlyFilesystemBackend(config_dir=tmp_path))
    client = TestClient(app, base_url="https://testserver")

    response = client.get("/", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_dashboard_renders_discovered_peer_cards_and_telemetry_unavailable(tmp_path: Path) -> None:
    p1 = tmp_path / "peer1"
    p1.mkdir()
    (p1 / "peer1.conf").write_text(
        "[Interface]\n"
        "Address = 10.13.13.2/32\n"
        "PrivateKey = SUPER_SECRET_CLIENT_PRIVATE_KEY_DO_NOT_EXPOSE==\n"
        "DNS = 1.1.1.1\n\n"
        "[Peer]\n"
        "PublicKey = SUPER_SECRET_SERVER_PUBLIC_KEY_DO_NOT_EXPOSE==\n"
        "PresharedKey = SUPER_SECRET_PRESHARED_KEY_DO_NOT_EXPOSE==\n"
        "Endpoint = vpn.example.com:51820\n"
    )

    client, _ = _create_authenticated_client(config_dir=tmp_path)
    response = client.get("/")

    assert response.status_code == 200
    html = response.text

    # Metadata present
    assert "peer1" in html
    assert "10.13.13.2/32" in html
    assert "1.1.1.1" in html
    assert "vpn.example.com:51820" in html

    # Telemetry badge
    assert "Unavailable" in html
    assert "Latest Handshake" in html
    assert "Transfer" in html
    assert "Rx: Unavailable / Tx: Unavailable" in html

    # Absolute guarantee: No secrets leaked in HTML
    assert "SUPER_SECRET" not in html
    assert "PrivateKey" not in html
    assert "PresharedKey" not in html
    assert "DO_NOT_EXPOSE" not in html


def test_dashboard_escapes_malicious_peer_content(tmp_path: Path) -> None:
    p_xss = tmp_path / "peer_xss"
    p_xss.mkdir()
    (p_xss / "peer_xss.conf").write_text(
        "[Interface]\nAddress = <script>alert('xss')</script>\nDNS = <img src=x onerror=alert(1)>\n"
    )

    client, _ = _create_authenticated_client(config_dir=tmp_path)
    response = client.get("/")

    assert response.status_code == 200
    html = response.text

    # Malicious scripts must be escaped
    assert "<script>alert('xss')</script>" not in html
    assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;" in html or "&lt;script&gt;" in html
    assert "<img src=x" not in html


def test_dashboard_empty_state_shows_guidance_and_rescan(tmp_path: Path) -> None:
    # Empty directory
    client, csrf_token = _create_authenticated_client(config_dir=tmp_path)
    response = client.get("/")

    assert response.status_code == 200
    html = response.text

    assert "No Peers Found" in html
    assert "PEERS" in html  # Guidance regarding LinuxServer PEERS configuration
    assert 'action="/rescan"' in html
    assert csrf_token in html


def test_rescan_requires_authentication(tmp_path: Path) -> None:
    settings = Settings(
        dashboard_password="password123",
        session_secret="s" * 32,
        auth_disabled=False,
    )
    app = create_app(settings=settings, peer_backend=ReadOnlyFilesystemBackend(config_dir=tmp_path))
    client = TestClient(app, base_url="https://testserver")

    response = client.post("/rescan", data={"csrf_token": "some-token"}, follow_redirects=False)
    assert response.status_code == 401


def test_rescan_requires_valid_csrf(tmp_path: Path) -> None:
    # 1. Missing CSRF (no cookie and no form token)
    client_missing, _ = _create_authenticated_client(config_dir=tmp_path)
    client_missing.cookies.delete(CSRF_COOKIE_NAME)
    res_missing = client_missing.post("/rescan")
    assert res_missing.status_code == 403

    # 2. Tampered CSRF
    client_tampered, _ = _create_authenticated_client(config_dir=tmp_path)
    res_tampered = client_tampered.post(
        "/rescan",
        data={"csrf_token": "tampered_token"},
    )
    assert res_tampered.status_code == 403

    # 3. Cross-session CSRF
    other_session_csrf = create_session_csrf_token(
        session_id="other_session_id",
        session_secret="a" * 32,
    )
    client_cross, _ = _create_authenticated_client(config_dir=tmp_path)
    res_cross = client_cross.post(
        "/rescan",
        data={"csrf_token": other_session_csrf},
    )
    assert res_cross.status_code == 403

    # 4. Valid CSRF
    client_valid, csrf_token = _create_authenticated_client(config_dir=tmp_path)
    res_valid = client_valid.post(
        "/rescan",
        data={"csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert res_valid.status_code == 303
    assert res_valid.headers["location"] == "/"


def test_rescan_reflects_newly_added_peer_without_modifying_files(tmp_path: Path) -> None:
    client, csrf_token = _create_authenticated_client(config_dir=tmp_path)

    # Initially empty
    res1 = client.get("/")
    assert "No Peers Found" in res1.text
    assert "peer1" not in res1.text

    # Add peer1
    p1 = tmp_path / "peer1"
    p1.mkdir()
    conf = p1 / "peer1.conf"
    conf.write_text("[Interface]\nAddress = 10.13.13.2/32\n")
    mtime_before = conf.stat().st_mtime_ns
    content_before = conf.read_bytes()

    # Trigger rescan
    res_post = client.post(
        "/rescan",
        data={"csrf_token": csrf_token},
        follow_redirects=False,
    )
    assert res_post.status_code == 303

    # Now peer1 appears
    res2 = client.get("/")
    assert "peer1" in res2.text
    assert "10.13.13.2/32" in res2.text
    assert "No Peers Found" not in res2.text

    # Verify filesystem was strictly read-only and untouched
    assert conf.stat().st_mtime_ns == mtime_before
    assert conf.read_bytes() == content_before


def test_rescan_json_api_response(tmp_path: Path) -> None:
    p1 = tmp_path / "peer1"
    p1.mkdir()
    (p1 / "peer1.conf").write_text(
        "[Interface]\n"
        "Address = 10.13.13.2/32\n"
        "PrivateKey = SECRET_CLIENT_PRIVATE_KEY_NEVER_LEAK==\n"
        "[Peer]\n"
        "PublicKey = SECRET_SERVER_PUBLIC_KEY_NEVER_LEAK==\n"
        "PresharedKey = SECRET_PRESHARED_KEY_NEVER_LEAK==\n"
        "Endpoint = vpn.example.com:51820\n"
    )

    client, csrf_token = _create_authenticated_client(config_dir=tmp_path)
    response = client.post(
        "/rescan",
        headers={"Accept": "application/json", "X-CSRF-Token": csrf_token},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "peers" in data
    assert len(data["peers"]) == 1
    peer_data = data["peers"][0]
    assert peer_data["peer_id"] == "peer1"
    assert peer_data["friendly_name"] == "peer1"
    assert peer_data["address"] == "10.13.13.2/32"
    assert peer_data["endpoint"] == "vpn.example.com:51820"

    # Strict check: No sensitive secrets leaked in JSON
    raw_json = response.text
    assert "SECRET" not in raw_json
    assert "PrivateKey" not in raw_json
    assert "PublicKey" not in raw_json
    assert "PresharedKey" not in raw_json


def test_auth_disabled_dashboard_and_rescan(tmp_path: Path) -> None:
    p1 = tmp_path / "peer1"
    p1.mkdir()
    (p1 / "peer1.conf").write_text("[Interface]\nAddress = 10.13.13.2/32\n")

    settings = Settings(auth_disabled=True)
    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
    app = create_app(settings=settings, peer_backend=backend)
    client = TestClient(app, base_url="https://testserver")

    # Direct access to dashboard without login
    res = client.get("/")
    assert res.status_code == 200
    assert "peer1" in res.text
    assert 'action="/rescan"' in res.text  # Rescan button renders even when auth is disabled

    # Rescan works in auth-disabled mode
    res_post = client.post("/rescan", follow_redirects=False)
    assert res_post.status_code == 303
    assert res_post.headers["location"] == "/"


def test_peer_conf_endpoint_requires_authentication(tmp_path: Path) -> None:
    settings = Settings(
        dashboard_password="password123",
        session_secret="s" * 32,
        auth_disabled=False,
    )
    app = create_app(settings=settings, peer_backend=ReadOnlyFilesystemBackend(config_dir=tmp_path))
    client = TestClient(app, base_url="https://testserver")

    # API / fetch call without credentials -> 401 Unauthorized
    api_resp = client.get("/peers/peer1/conf", headers={"Accept": "text/plain"})
    assert api_resp.status_code == 401
    assert api_resp.json() == {"detail": "Unauthorized"}

    # Browser navigation without credentials -> 303 Redirect to /login
    nav_resp = client.get(
        "/peers/peer1/conf",
        headers={"Accept": "text/html"},
        follow_redirects=False,
    )
    assert nav_resp.status_code == 303
    assert nav_resp.headers["location"] == "/login"


def test_peer_conf_endpoint_rejects_revoked_or_tampered_session(tmp_path: Path) -> None:
    peer_dir = tmp_path / "peer1"
    peer_dir.mkdir()
    (peer_dir / "peer1.conf").write_text("[Interface]\nAddress = 10.0.0.1\n")

    client, csrf_token = _create_authenticated_client(config_dir=tmp_path)

    # 1. Tampered session
    client.cookies.set(SESSION_COOKIE_NAME, "tampered_session_cookie")
    res_tampered = client.get("/peers/peer1/conf", headers={"Accept": "text/plain"})
    assert res_tampered.status_code == 401

    # 2. Re-login and logout (revoking session)
    client2, csrf_token2 = _create_authenticated_client(config_dir=tmp_path)
    res_logout = client2.post("/logout", data={"csrf_token": csrf_token2}, follow_redirects=False)
    assert res_logout.status_code == 303

    res_revoked = client2.get("/peers/peer1/conf", headers={"Accept": "text/plain"})
    assert res_revoked.status_code == 401


def test_peer_conf_endpoint_returns_exact_conf_and_headers(tmp_path: Path) -> None:
    peer_dir = tmp_path / "peer1"
    peer_dir.mkdir()
    conf_content = (
        "[Interface]\n"
        "Address = 10.13.13.2/32\n"
        "PrivateKey = SENSITIVE_CLIENT_PRIVATE_KEY_CONF_ENDPOINT=\n"
        "DNS = 1.1.1.1\n\n"
        "[Peer]\n"
        "PublicKey = SENSITIVE_SERVER_PUBLIC_KEY=\n"
        "Endpoint = vpn.example.com:51820\n"
    )
    (peer_dir / "peer1.conf").write_text(conf_content)

    client, _ = _create_authenticated_client(config_dir=tmp_path)
    response = client.get("/peers/peer1/conf")

    assert response.status_code == 200
    assert response.text == conf_content
    # Strict headers
    assert response.headers["Content-Disposition"] == 'attachment; filename="peer1.conf"'
    assert "no-store" in response.headers["Cache-Control"]
    assert "text/plain" in response.headers["Content-Type"]


def test_peer_conf_endpoint_returns_404_for_unknown_or_malicious_peers(tmp_path: Path) -> None:
    server_dir = tmp_path / "server"
    server_dir.mkdir()
    (server_dir / "server.conf").write_text("[Interface]\nPrivateKey = SERVER_ROOT_SECRET\n")

    client, _ = _create_authenticated_client(config_dir=tmp_path)

    # Non-existent peer
    res_missing = client.get("/peers/peer99/conf")
    assert res_missing.status_code == 404
    assert res_missing.json() == {"detail": "Peer not found"}

    # Excluded server directory
    res_server = client.get("/peers/server/conf")
    assert res_server.status_code == 404

    # Traversal attempts
    res_traversal = client.get("/peers/..%2Fserver/conf")
    assert res_traversal.status_code == 404


def test_peer_conf_endpoint_never_logs_secrets_or_response_bodies(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    peer_dir = tmp_path / "peer1"
    peer_dir.mkdir()
    secret_key = "HIGHLY_CONFIDENTIAL_PRIVATE_KEY_VAL="
    conf_content = f"[Interface]\nAddress = 10.13.13.2/32\nPrivateKey = {secret_key}\n"
    (peer_dir / "peer1.conf").write_text(conf_content)

    client, _ = _create_authenticated_client(config_dir=tmp_path)

    with caplog.at_level(logging.DEBUG):
        response = client.get("/peers/peer1/conf")
        assert response.status_code == 200

    # Ensure secrets are never logged
    for record in caplog.records:
        assert secret_key not in record.getMessage()
        assert "PrivateKey" not in record.getMessage()


def test_peer_conf_endpoint_with_auth_disabled(tmp_path: Path) -> None:
    peer_dir = tmp_path / "peer1"
    peer_dir.mkdir()
    (peer_dir / "peer1.conf").write_text("[Interface]\nAddress = 10.0.0.1\n")

    settings = Settings(auth_disabled=True)
    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
    app = create_app(settings=settings, peer_backend=backend)
    client = TestClient(app, base_url="http://testserver")

    response = client.get("/peers/peer1/conf")
    assert response.status_code == 200
    assert response.headers["Content-Disposition"] == 'attachment; filename="peer1.conf"'
    assert "no-store" in response.headers["Cache-Control"]


def test_dashboard_template_renders_search_and_masked_actions_no_leak(
    tmp_path: Path,
) -> None:
    peer_dir = tmp_path / "peer1"
    peer_dir.mkdir()
    conf_content = (
        "[Interface]\n"
        "Address = 10.13.13.2/32\n"
        "PrivateKey = CLASSIFIED_CLIENT_PRIVATE_KEY_NEVER_LEAK_IN_HTML==\n"
        "DNS = 1.1.1.1\n\n"
        "[Peer]\n"
        "PublicKey = CLASSIFIED_SERVER_PUBLIC_KEY==\n"
        "PresharedKey = CLASSIFIED_PRESHARED_KEY==\n"
        "Endpoint = vpn.example.com:51820\n"
    )
    (peer_dir / "peer1.conf").write_text(conf_content)

    client, _ = _create_authenticated_client(config_dir=tmp_path)
    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    # 1. Search input is present with proper accessibility attributes
    assert 'id="peer-search"' in html
    assert 'type="search"' in html or 'type="text"' in html
    assert "placeholder=" in html

    # 2. Peer card has data attributes for client-side filtering
    assert 'data-peer-name="peer1"' in html
    assert 'data-peer-ip="10.13.13.2/32"' in html
    assert 'data-peer-id="peer1"' in html

    # 3. Masked preview structure and security warning
    assert "Sensitive Configuration" in html or "warning" in html.lower()
    assert "conf-masked-placeholder" in html
    assert "••••" in html
    assert 'class="btn-action btn-reveal"' in html or "btn-reveal" in html
    assert "btn-copy" in html
    assert "btn-download" in html or "download" in html
    assert 'href="/peers/peer1/conf"' in html

    # 4. Strict check: No inline scripts, JS is loaded via local static script
    assert '<script src="/static/dashboard.js"' in html
    assert "<script>" not in html

    # 5. ABSOLUTE SECURITY GUARANTEE: No secret keys or configuration content in initial HTML
    assert "CLASSIFIED" not in html
    assert "PrivateKey" not in html
    assert "PresharedKey" not in html
    assert "AllowedIPs" not in html
