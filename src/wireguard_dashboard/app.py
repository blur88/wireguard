import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.types import ASGIApp

from wireguard_dashboard.auth.rate_limit import LoginRateLimiter, get_client_ip
from wireguard_dashboard.auth.security import (
    compute_credential_fingerprint,
    hash_password,
    verify_password,
)
from wireguard_dashboard.auth.session import (
    SESSION_COOKIE_NAME,
    create_session_token,
    set_session_cookie,
    verify_session_token,
)
from wireguard_dashboard.config import Settings, get_settings
from wireguard_dashboard.middleware import SecurityHeadersMiddleware

logger = logging.getLogger("wireguard_dashboard")

PACKAGE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = PACKAGE_DIR / "templates"
STATIC_DIR = PACKAGE_DIR / "static"


def create_app(settings: Settings | None = None) -> ASGIApp:
    """Create, configure, and return the companion application composed with security headers."""
    if not STATIC_DIR.is_dir():
        raise RuntimeError(f"Static assets directory not found: {STATIC_DIR}")

    resolved_settings = settings if settings is not None else get_settings()

    if resolved_settings.auth_disabled:
        logger.warning(
            "SECURITY WARNING: AUTH_DISABLED=true is active. Authentication is completely "
            "disabled. Do not expose this service directly to public networks."
        )

    stored_password_hash: str | None = None
    credential_fingerprint: str | None = None
    rate_limiter = LoginRateLimiter(max_attempts=5, window_seconds=60.0)

    if not resolved_settings.auth_disabled:
        assert resolved_settings.dashboard_password is not None
        assert resolved_settings.session_secret is not None

        if resolved_settings.dashboard_password.startswith("$argon2id$"):
            stored_password_hash = resolved_settings.dashboard_password
        else:
            stored_password_hash = hash_password(resolved_settings.dashboard_password)

        credential_fingerprint = compute_credential_fingerprint(
            credential=resolved_settings.dashboard_password,
            session_secret=resolved_settings.session_secret,
        )

    fastapi_app = FastAPI(
        title="WireGuard Companion Dashboard",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    fastapi_app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    def is_authenticated(request: Request) -> bool:
        if resolved_settings.auth_disabled:
            return True
        token = request.cookies.get(SESSION_COOKIE_NAME)
        if not token:
            return False
        assert credential_fingerprint is not None
        assert resolved_settings.session_secret is not None
        return verify_session_token(
            token=token,
            expected_fingerprint=credential_fingerprint,
            session_secret=resolved_settings.session_secret,
        )

    @fastapi_app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> Response:
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal Server Error"},
        )

    @fastapi_app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {"status": "ok"}

    @fastapi_app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request) -> Response:
        if is_authenticated(request):
            return RedirectResponse(url="/", status_code=303)
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={},
        )

    @fastapi_app.post("/login", response_class=HTMLResponse)
    async def login_action(request: Request) -> Response:
        if resolved_settings.auth_disabled:
            return RedirectResponse(url="/", status_code=303)

        client_ip = get_client_ip(request)

        if not rate_limiter.is_allowed(client_ip):
            retry_after = rate_limiter.retry_after_seconds(client_ip)
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"error": "Too many failed login attempts. Please try again later."},
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )

        form = await request.form()
        raw_password = form.get("password")

        # Guard against oversized payloads or non-string forms
        if not raw_password or not isinstance(raw_password, str) or len(raw_password) > 4096:
            rate_limiter.record_failure(client_ip)
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"error": "Invalid credentials."},
                status_code=401,
            )

        assert stored_password_hash is not None
        if not verify_password(raw_password, stored_password_hash):
            rate_limiter.record_failure(client_ip)
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"error": "Invalid credentials."},
                status_code=401,
            )

        rate_limiter.record_success(client_ip)
        assert credential_fingerprint is not None
        assert resolved_settings.session_secret is not None

        token = create_session_token(
            fingerprint=credential_fingerprint,
            session_secret=resolved_settings.session_secret,
        )

        response = RedirectResponse(url="/", status_code=303)
        is_secure = (
            request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
        )
        set_session_cookie(response=response, token=token, secure=is_secure)
        return response

    @fastapi_app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> Response:
        if not is_authenticated(request):
            return RedirectResponse(url="/login", status_code=303)

        return templates.TemplateResponse(
            request=request,
            name="base.html",
            context={},
        )

    # Wrap the completed FastAPI application with outermost ASGI security middleware
    return SecurityHeadersMiddleware(fastapi_app)
