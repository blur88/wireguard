import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from tests.helpers import assert_security_headers
from wireguard_dashboard.app import create_app


def test_root_renders_dark_mode_html_shell(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]

    html = response.text
    # Check for dark mode root indicator and title
    assert "<!DOCTYPE html>" in html or "<!doctype html>" in html
    assert "dark" in html
    assert "WireGuard" in html


def test_html_shell_has_no_external_cdn_or_third_party_dependencies(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200

    html = response.text

    # Search for external script sources
    external_scripts = re.findall(
        r'<script[^>]+src=["\'](https?://[^"\']+)["\']', html, re.IGNORECASE
    )
    assert external_scripts == [], f"Found external scripts: {external_scripts}"

    # Search for external stylesheet sources
    external_styles = re.findall(
        r'<link[^>]+href=["\'](https?://[^"\']+)["\']', html, re.IGNORECASE
    )
    assert external_styles == [], f"Found external stylesheets: {external_styles}"


def test_static_stylesheet_served_locally(client: TestClient) -> None:
    response = client.get("/static/style.css")
    assert response.status_code == 200
    assert "text/css" in response.headers["content-type"]
    assert "--bg-canvas" in response.text


def test_missing_static_dir_fails_fast_at_initialization(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    non_existent = tmp_path / "non_existent_static_dir"
    monkeypatch.setattr("wireguard_dashboard.app.STATIC_DIR", non_existent)

    with pytest.raises(RuntimeError, match="Static assets directory not found"):
        create_app()


def test_html_shell_includes_hardened_security_headers(
    client: TestClient, security_headers: dict[str, str]
) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert_security_headers(response.headers, security_headers)
