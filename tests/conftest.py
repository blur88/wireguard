import pytest
from fastapi.testclient import TestClient

from tests.helpers import EXPECTED_SECURITY_HEADERS
from wireguard_dashboard.app import create_app


@pytest.fixture(autouse=True)
def default_test_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set default test credentials for test isolation unless explicitly cleared."""
    monkeypatch.setenv("DASHBOARD_PASSWORD", "test-admin-password-123")
    monkeypatch.setenv("SESSION_SECRET", "s" * 32)


@pytest.fixture
def client() -> TestClient:
    app = create_app()
    return TestClient(app, base_url="https://testserver")


@pytest.fixture
def security_headers() -> dict[str, str]:
    return EXPECTED_SECURITY_HEADERS
