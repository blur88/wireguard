from pathlib import Path
from typing import Any, Dict
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from wireguard_dashboard.middleware import SecurityHeadersMiddleware

PACKAGE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = PACKAGE_DIR / "templates"
STATIC_DIR = PACKAGE_DIR / "static"


def create_app() -> FastAPI:
    """Create and configure the FastAPI companion application."""
    app = FastAPI(
        title="WireGuard Companion Dashboard",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    app.add_middleware(SecurityHeadersMiddleware)

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/healthz")
    def healthz() -> Dict[str, Any]:
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request,
            name="base.html",
            context={},
        )

    return app
