from fastapi.testclient import TestClient

from wireguard_dashboard.app import create_app


def test_healthz_returns_ok_status(client: TestClient) -> None:
    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {"status": "ok"}


def test_healthz_exposes_no_sensitive_diagnostics(client: TestClient) -> None:
    response = client.get("/healthz")
    data = response.json()

    # The payload must strictly contain only {"status": "ok"}
    assert set(data.keys()) == {"status"}
    assert data["status"] == "ok"

    # Verify no environment, filesystem, or debug keys leaked in body
    text = response.text.lower()
    for sensitive_word in ("path", "secret", "password", "token", "env", "config", "traceback"):
        assert sensitive_word not in text


def test_asgi_lifespan_lifecycle_supported() -> None:
    app = create_app()
    with TestClient(app) as client:
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}
