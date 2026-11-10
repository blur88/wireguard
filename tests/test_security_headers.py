from typing import Any, Dict
from fastapi.testclient import TestClient
import pytest
from tests.helpers import assert_security_headers
from wireguard_dashboard.app import create_app


@pytest.mark.parametrize(
    "method,path,expected_status",
    [
        ("GET", "/healthz", 200),
        ("GET", "/non-existent-endpoint-xyz", 404),
        ("POST", "/healthz", 405),
    ],
)
def test_security_headers_across_standard_status_codes(
    client: TestClient,
    security_headers: Dict[str, str],
    method: str,
    path: str,
    expected_status: int,
) -> None:
    response = client.request(method, path)
    assert response.status_code == expected_status
    assert_security_headers(response.headers, security_headers)


def test_security_headers_present_on_unhandled_500(security_headers: Dict[str, str]) -> None:
    app: Any = create_app()

    @app.get("/_test/unhandled-crash")
    def crash_route() -> None:
        raise RuntimeError("Simulated unhandled runtime failure in application")

    client = TestClient(app, raise_server_exceptions=False)
    response = client.get("/_test/unhandled-crash")

    assert response.status_code == 500
    assert_security_headers(response.headers, security_headers)

    body = response.text.lower()
    for sensitive_word in ("traceback", "runtimeerror", "simulated unhandled", "file \"/", "site-packages"):
        assert sensitive_word not in body


def test_error_responses_expose_no_stacktraces_or_paths(client: TestClient) -> None:
    response = client.get("/non-existent-endpoint-xyz")
    assert response.status_code == 404

    body = response.text.lower()
    for sensitive_word in ("traceback", "file \"/", "site-packages", "internal server error"):
        assert sensitive_word not in body
