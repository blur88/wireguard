from pathlib import Path

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
) -> tuple[TestClient, dict[str, str], str]:
    settings = Settings(
        dashboard_password=password,
        session_secret=session_secret,
        auth_disabled=False,
        cookie_secure=True,
    )
    backend = ReadOnlyFilesystemBackend(config_dir=config_dir)
    app = create_app(settings=settings, peer_backend=backend)
    client = TestClient(app, base_url="https://testserver")

    # Log in through the standard flow to get valid session and CSRF cookies
    login_get = client.get("/login")
    login_csrf = login_get.cookies.get(CSRF_COOKIE_NAME)
    assert login_csrf is not None

    login_post = client.post(
        "/login",
        data={"password": password, CSRF_FORM_FIELD: login_csrf},
        cookies={CSRF_COOKIE_NAME: login_csrf},
        follow_redirects=False,
    )
    assert login_post.status_code == 303

    session_cookie = login_post.cookies.get(SESSION_COOKIE_NAME)
    session_csrf = login_post.cookies.get(CSRF_COOKIE_NAME)
    assert session_cookie is not None
    assert session_csrf is not None

    cookies = {
        SESSION_COOKIE_NAME: session_cookie,
        CSRF_COOKIE_NAME: session_csrf,
    }
    return client, cookies, session_csrf


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

    client, cookies, _ = _create_authenticated_client(config_dir=tmp_path)
    response = client.get("/", cookies=cookies)

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

    client, cookies, _ = _create_authenticated_client(config_dir=tmp_path)
    response = client.get("/", cookies=cookies)

    assert response.status_code == 200
    html = response.text

    # Malicious scripts must be escaped
    assert "<script>alert('xss')</script>" not in html
    assert "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;" in html or "&lt;script&gt;" in html
    assert "<img src=x" not in html


def test_dashboard_empty_state_shows_guidance_and_rescan(tmp_path: Path) -> None:
    # Empty directory
    client, cookies, csrf_token = _create_authenticated_client(config_dir=tmp_path)
    response = client.get("/", cookies=cookies)

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
    client, cookies, csrf_token = _create_authenticated_client(config_dir=tmp_path)

    # 1. Missing CSRF
    res_missing = client.post("/rescan", cookies=cookies)
    assert res_missing.status_code == 403

    # 2. Tampered CSRF
    res_tampered = client.post(
        "/rescan",
        data={"csrf_token": "tampered_token"},
        cookies=cookies,
    )
    assert res_tampered.status_code == 403

    # 3. Cross-session CSRF
    other_session_csrf = create_session_csrf_token(
        session_id="other_session_id",
        session_secret="a" * 32,
    )
    res_cross = client.post(
        "/rescan",
        data={"csrf_token": other_session_csrf},
        cookies=cookies,
    )
    assert res_cross.status_code == 403

    # 4. Valid CSRF
    res_valid = client.post(
        "/rescan",
        data={"csrf_token": csrf_token},
        cookies=cookies,
        follow_redirects=False,
    )
    assert res_valid.status_code == 303
    assert res_valid.headers["location"] == "/"


def test_rescan_reflects_newly_added_peer_without_modifying_files(tmp_path: Path) -> None:
    client, cookies, csrf_token = _create_authenticated_client(config_dir=tmp_path)

    # Initially empty
    res1 = client.get("/", cookies=cookies)
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
        cookies=cookies,
        follow_redirects=False,
    )
    assert res_post.status_code == 303

    # Now peer1 appears
    res2 = client.get("/", cookies=cookies)
    assert "peer1" in res2.text
    assert "10.13.13.2/32" in res2.text
    assert "No Peers Found" not in res2.text

    # Verify filesystem was strictly read-only and untouched
    assert conf.stat().st_mtime_ns == mtime_before
    assert conf.read_bytes() == content_before


def test_rescan_json_api_response(tmp_path: Path) -> None:
    p1 = tmp_path / "peer1"
    p1.mkdir()
    (p1 / "peer1.conf").write_text("[Interface]\nAddress = 10.13.13.2/32\n")

    client, cookies, csrf_token = _create_authenticated_client(config_dir=tmp_path)
    response = client.post(
        "/rescan",
        headers={"Accept": "application/json", "X-CSRF-Token": csrf_token},
        cookies=cookies,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "peers" in data
    assert len(data["peers"]) == 1
    assert data["peers"][0]["peer_id"] == "peer1"


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
