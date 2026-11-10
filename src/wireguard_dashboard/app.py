from pathlib import Path
from typing import Any, Dict
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.types import ASGIApp
from wireguard_dashboard.middleware import SecurityHeadersMiddleware

PACKAGE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = PACKAGE_DIR / "templates"
STATIC_DIR = PACKAGE_DIR / "static"


class WireGuardDashboardApp(FastAPI):
    """FastAPI application that cleanly wraps the outermost ASGI middleware stack."""

    def build_middleware_stack(self) -> ASGIApp:
        inner_stack = super().build_middleware_stack()
        return SecurityHeadersMiddleware(inner_stack)


def create_app() -> FastAPI:
    """Create and configure the FastAPI companion application."""
    if not STATIC_DIR.is_dir():
        raise RuntimeError(f"Static assets directory not found: {STATIC_DIR}")

    app = WireGuardDashboardApp(
        title="WireGuard Companion Dashboard",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> Response:
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal Server Error"},
        )

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
