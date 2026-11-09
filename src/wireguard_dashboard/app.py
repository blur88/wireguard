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


def create_app() -> FastAPI:
    """Create and configure the FastAPI companion application."""
    app = FastAPI(
        title="WireGuard Companion Dashboard",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    if STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> Response:
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal Server Error"},
        )

    # Wrap the outermost ASGI stack so security headers are guaranteed even on unhandled 500s
    original_build_middleware_stack = app.build_middleware_stack

    def custom_build_middleware_stack() -> ASGIApp:
        stack = original_build_middleware_stack()
        return SecurityHeadersMiddleware(stack)

    app.build_middleware_stack = custom_build_middleware_stack  # type: ignore[method-assign]

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
