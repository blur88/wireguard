import logging
import time
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.types import ASGIApp

from wireguard_dashboard.auth.csrf import (
    CSRF_COOKIE_NAME,
    CSRF_FORM_FIELD,
    CSRF_HEADER_NAME,
    clear_csrf_cookie,
    create_preauth_csrf_token,
    create_session_csrf_token,
    set_csrf_cookie,
    verify_csrf_double_submit,
)
from wireguard_dashboard.auth.rate_limit import LoginRateLimiter, get_client_ip
from wireguard_dashboard.auth.security import (
    compute_credential_fingerprint,
    hash_password,
    verify_password,
)
from wireguard_dashboard.auth.session import (
    DEFAULT_SESSION_TTL_SECONDS,
    SESSION_COOKIE_NAME,
    SessionRegistry,
    clear_session_cookie,
    create_session_token,
    extract_session_id,
    set_session_cookie,
    verify_session_token,
)
from wireguard_dashboard.config import Settings, get_settings
from wireguard_dashboard.middleware import SecurityHeadersMiddleware
from wireguard_dashboard.peers.backend import PeerBackend, ReadOnlyFilesystemBackend
from wireguard_dashboard.telemetry.provider import NoOpTelemetryProvider, TelemetryProvider

logger = logging.getLogger("wireguard_dashboard")

PACKAGE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = PACKAGE_DIR / "templates"
STATIC_DIR = PACKAGE_DIR / "static"


class UnauthenticatedError(Exception):
    """Raised when an unauthenticated request attempts to access a protected route."""


def create_app(
    settings: Settings | None = None,
    peer_backend: PeerBackend | None = None,
    telemetry_provider: TelemetryProvider | None = None,
) -> ASGIApp:
    """Create, configure, and return the companion application composed with security headers."""
    if not STATIC_DIR.is_dir():
        raise RuntimeError(f"Static assets directory not found: {STATIC_DIR}")

    resolved_settings = settings if settings is not None else get_settings()
    active_peer_backend: PeerBackend = (
        peer_backend
        if peer_backend is not None
        else ReadOnlyFilesystemBackend(config_dir=resolved_settings.config_dir)
    )
    active_telemetry: TelemetryProvider = (
        telemetry_provider if telemetry_provider is not None else NoOpTelemetryProvider()
    )

    if resolved_settings.auth_disabled:
        logger.warning(
            "SECURITY WARNING: AUTH_DISABLED=true is active. Authentication is completely "
            "disabled. Do not expose this service directly to public networks."
        )

    if not resolved_settings.cookie_secure:
        logger.warning(
            "SECURITY WARNING: COOKIE_SECURE=false is active. Session cookies are being issued "
            "without the Secure attribute. Never use this in production or over public networks."
        )

    stored_password_hash: str | None = None
    credential_fingerprint: str | None = None
    rate_limiter = LoginRateLimiter(max_attempts=5, window_seconds=60.0)
    session_registry = SessionRegistry()

    if not resolved_settings.auth_disabled:
        assert resolved_settings.dashboard_password is not None
        assert resolved_settings.session_secret is not None

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

    def get_authenticated_session_id(request: Request) -> str | None:
        if resolved_settings.auth_disabled:
            return "auth_disabled"
        token = request.cookies.get(SESSION_COOKIE_NAME)
        if not token:
            return None
        assert credential_fingerprint is not None
        assert resolved_settings.session_secret is not None
        if not verify_session_token(
            token=token,
            expected_fingerprint=credential_fingerprint,
            session_secret=resolved_settings.session_secret,
            registry=session_registry,
        ):
            return None
        return extract_session_id(token)

    def is_authenticated(request: Request) -> bool:
        return get_authenticated_session_id(request) is not None

    def require_authenticated(request: Request) -> None:
        """FastAPI dependency to protect endpoints against unauthenticated access."""
        if not is_authenticated(request):
            raise UnauthenticatedError()

    @fastapi_app.exception_handler(UnauthenticatedError)
    async def unauthenticated_exception_handler(
        request: Request, exc: UnauthenticatedError
    ) -> Response:
        accept_header = request.headers.get("accept", "").lower()
        if request.method == "GET" and (
            "text/html" in accept_header or not accept_header or "*/*" in accept_header
        ):
            response = RedirectResponse(url="/login", status_code=303)
            clear_session_cookie(response, secure=resolved_settings.cookie_secure)
            clear_csrf_cookie(response, secure=resolved_settings.cookie_secure)
            return response
        return JSONResponse(
            status_code=401,
            content={"detail": "Unauthorized"},
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

    def _get_or_create_csrf_token(
        request: Request,
        session_id: str | None = None,
    ) -> str | None:
        if resolved_settings.auth_disabled:
            return None
        assert resolved_settings.session_secret is not None
        existing_cookie = request.cookies.get(CSRF_COOKIE_NAME)
        expected_session = session_id if (session_id and session_id != "auth_disabled") else None
        if existing_cookie and verify_csrf_double_submit(
            cookie_token=existing_cookie,
            submitted_token=existing_cookie,
            session_secret=resolved_settings.session_secret,
            expected_session_id=expected_session,
        ):
            return existing_cookie
        if session_id and session_id != "auth_disabled":
            return create_session_csrf_token(
                session_id=session_id,
                session_secret=resolved_settings.session_secret,
            )
        return create_preauth_csrf_token(resolved_settings.session_secret)

    async def _validate_csrf_request(
        request: Request,
        expected_session_id: str | None = None,
    ) -> bool:
        if resolved_settings.auth_disabled:
            return True
        assert resolved_settings.session_secret is not None
        cookie_csrf = request.cookies.get(CSRF_COOKIE_NAME)
        form_csrf: str | None = None
        try:
            form = await request.form()
            raw_form_csrf = form.get(CSRF_FORM_FIELD)
            if isinstance(raw_form_csrf, str) and raw_form_csrf:
                form_csrf = raw_form_csrf
        except Exception:
            pass

        header_csrf = request.headers.get(CSRF_HEADER_NAME)
        submitted_csrf = form_csrf if form_csrf else header_csrf
        expected_session = (
            expected_session_id
            if (expected_session_id and expected_session_id != "auth_disabled")
            else None
        )

        return verify_csrf_double_submit(
            cookie_token=cookie_csrf,
            submitted_token=submitted_csrf,
            session_secret=resolved_settings.session_secret,
            expected_session_id=expected_session,
        )

    @fastapi_app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request) -> Response:
        if is_authenticated(request):
            return RedirectResponse(url="/", status_code=303)

        csrf_token = _get_or_create_csrf_token(request, session_id=None)
        response = templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"csrf_token": csrf_token},
        )
        if csrf_token is not None:
            set_csrf_cookie(
                response=response,
                token=csrf_token,
                secure=resolved_settings.cookie_secure,
            )
        return response

    @fastapi_app.post("/login", response_class=HTMLResponse)
    async def login_action(request: Request) -> Response:
        if resolved_settings.auth_disabled:
            return RedirectResponse(url="/", status_code=303)

        assert resolved_settings.session_secret is not None
        assert stored_password_hash is not None
        assert credential_fingerprint is not None

        # CSRF check: Double-submit validation
        if not await _validate_csrf_request(request, expected_session_id=None):
            return Response(
                status_code=403,
                content="Forbidden: CSRF validation failed",
                media_type="text/plain",
            )

        form = await request.form()
        cookie_csrf = request.cookies.get(CSRF_COOKIE_NAME)
        client_ip = get_client_ip(request)

        if not rate_limiter.is_allowed(client_ip):
            retry_after = rate_limiter.retry_after_seconds(client_ip)
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={
                    "error": "Too many failed login attempts. Please try again later.",
                    "csrf_token": cookie_csrf,
                },
                status_code=429,
                headers={"Retry-After": str(retry_after)},
            )

        def fail_login() -> Response:
            rate_limiter.record_failure(client_ip)
            return templates.TemplateResponse(
                request=request,
                name="login.html",
                context={
                    "error": "Invalid credentials.",
                    "csrf_token": cookie_csrf,
                },
                status_code=401,
            )

        raw_password = form.get("password")

        # Guard against oversized payloads or non-string forms
        if not raw_password or not isinstance(raw_password, str) or len(raw_password) > 4096:
            return fail_login()

        if not verify_password(raw_password, stored_password_hash):
            return fail_login()

        rate_limiter.record_success(client_ip)

        now = time.time()
        token = create_session_token(
            fingerprint=credential_fingerprint,
            session_secret=resolved_settings.session_secret,
            current_time=now,
            ttl_seconds=DEFAULT_SESSION_TTL_SECONDS,
        )
        session_id = extract_session_id(token)
        assert session_id is not None
        session_registry.register(
            session_id=session_id,
            fingerprint=credential_fingerprint,
            expires_at=now + DEFAULT_SESSION_TTL_SECONDS,
        )

        session_csrf = create_session_csrf_token(
            session_id=session_id,
            session_secret=resolved_settings.session_secret,
        )

        response = RedirectResponse(url="/", status_code=303)
        set_session_cookie(
            response=response,
            token=token,
            secure=resolved_settings.cookie_secure,
        )
        set_csrf_cookie(
            response=response,
            token=session_csrf,
            secure=resolved_settings.cookie_secure,
        )
        return response

    @fastapi_app.post("/logout")
    async def logout_action(request: Request) -> Response:
        if resolved_settings.auth_disabled:
            return RedirectResponse(url="/login", status_code=303)

        session_id = get_authenticated_session_id(request)
        if not session_id:
            raise UnauthenticatedError()

        if not await _validate_csrf_request(request, expected_session_id=session_id):
            return Response(
                status_code=403,
                content="Forbidden: CSRF validation failed",
                media_type="text/plain",
            )

        session_registry.revoke(session_id)

        response = RedirectResponse(url="/login", status_code=303)
        clear_session_cookie(response, secure=resolved_settings.cookie_secure)
        clear_csrf_cookie(response, secure=resolved_settings.cookie_secure)
        return response

    @fastapi_app.post("/rescan")
    async def rescan_action(request: Request) -> Response:
        session_id = get_authenticated_session_id(request)
        if not session_id:
            raise UnauthenticatedError()

        if not await _validate_csrf_request(request, expected_session_id=session_id):
            return Response(
                status_code=403,
                content="Forbidden: CSRF validation failed",
                media_type="text/plain",
            )

        fresh_peers = active_peer_backend.rescan()

        accept_header = request.headers.get("accept", "").lower()
        if "application/json" in accept_header:
            return JSONResponse(
                status_code=200,
                content={
                    "status": "ok",
                    "peers": [
                        {
                            "peer_id": p.peer_id,
                            "friendly_name": p.friendly_name,
                            "address": p.address,
                            "dns": p.dns,
                            "endpoint": p.endpoint,
                        }
                        for p in fresh_peers
                    ],
                },
            )

        return RedirectResponse(url="/", status_code=303)

    @fastapi_app.get(
        "/",
        response_class=HTMLResponse,
        dependencies=[Depends(require_authenticated)],
    )
    def index(request: Request) -> Response:
        session_id = get_authenticated_session_id(request)
        csrf_token = _get_or_create_csrf_token(request, session_id=session_id)

        discovered = active_peer_backend.list_peers()
        peer_items = [
            {
                "meta": p,
                "telemetry": active_telemetry.get_peer_telemetry(p.peer_id),
            }
            for p in discovered
        ]

        response = templates.TemplateResponse(
            request=request,
            name="base.html",
            context={
                "csrf_token": csrf_token,
                "peers": peer_items,
            },
        )
        if csrf_token is not None:
            set_csrf_cookie(
                response=response,
                token=csrf_token,
                secure=resolved_settings.cookie_secure,
            )
        return response

    # Wrap the completed FastAPI application with outermost ASGI security middleware
    return SecurityHeadersMiddleware(fastapi_app)
