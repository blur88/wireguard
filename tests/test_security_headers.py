from typing import Dict
from fastapi.testclient import TestClient
import pytest


def test_security_headers_present_on_200(
    client: TestClient, security_headers: Dict[str, str]
) -> None:
    response = client.get("/healthz")
    assert response.status_code == 200

    for header_name, expected_value in security_headers.items():
        assert header_name in response.headers, f"Missing header: {header_name}"
        assert response.headers[header_name] == expected_value


def test_security_headers_present_on_404(
    client: TestClient, security_headers: Dict[str, str]
) -> None:
    response = client.get("/non-existent-endpoint-xyz")
    assert response.status_code == 404

    for header_name, expected_value in security_headers.items():
        assert header_name in response.headers, f"Missing header on 404: {header_name}"
        assert response.headers[header_name] == expected_value


def test_security_headers_present_on_405(
    client: TestClient, security_headers: Dict[str, str]
) -> None:
    # /healthz only supports GET, so POST should produce 405 Method Not Allowed
    response = client.post("/healthz")
    assert response.status_code == 405

    for header_name, expected_value in security_headers.items():
        assert header_name in response.headers, f"Missing header on 405: {header_name}"
        assert response.headers[header_name] == expected_value


def test_error_responses_expose_no_stacktraces_or_paths(client: TestClient) -> None:
    response = client.get("/non-existent-endpoint-xyz")
    assert response.status_code == 404

    body = response.text.lower()
    for sensitive_word in ("traceback", "file \"/", "site-packages", "internal server error"):
        assert sensitive_word not in body
