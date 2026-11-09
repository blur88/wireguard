import re
from typing import Dict
from fastapi.testclient import TestClient
import pytest
from tests.helpers import assert_security_headers


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
    external_scripts = re.findall(r'<script[^>]+src=["\'](https?://[^"\']+)["\']', html, re.IGNORECASE)
    assert external_scripts == [], f"Found external scripts: {external_scripts}"

    # Search for external stylesheet sources
    external_styles = re.findall(r'<link[^>]+href=["\'](https?://[^"\']+)["\']', html, re.IGNORECASE)
    assert external_styles == [], f"Found external stylesheets: {external_styles}"


def test_static_stylesheet_served_locally(client: TestClient) -> None:
    response = client.get("/static/style.css")
    assert response.status_code == 200
    assert "text/css" in response.headers["content-type"]
    assert "--bg-canvas" in response.text


def test_html_shell_includes_hardened_security_headers(
    client: TestClient, security_headers: Dict[str, str]
) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert_security_headers(response.headers, security_headers)
