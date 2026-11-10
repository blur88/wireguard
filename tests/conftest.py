import pytest
from fastapi.testclient import TestClient

from tests.helpers import EXPECTED_SECURITY_HEADERS
from wireguard_dashboard.app import create_app


@pytest.fixture
def client() -> TestClient:
    app = create_app()
    return TestClient(app)


@pytest.fixture
def security_headers() -> dict[str, str]:
    return EXPECTED_SECURITY_HEADERS
