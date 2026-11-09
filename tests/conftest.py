from typing import Dict
from fastapi.testclient import TestClient
import pytest
from wireguard_dashboard.app import create_app

EXPECTED_SECURITY_HEADERS: Dict[str, str] = {
    "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store, no-cache, must-revalidate, private",
}


@pytest.fixture
def client() -> TestClient:
    app = create_app()
    return TestClient(app)


@pytest.fixture
def security_headers() -> Dict[str, str]:
    return EXPECTED_SECURITY_HEADERS
