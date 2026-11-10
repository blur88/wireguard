from typing import Any, List, Tuple
from starlette.types import ASGIApp, Message, Receive, Scope, Send

HARDENED_SECURITY_HEADERS: List[Tuple[bytes, bytes]] = [
    (b"content-security-policy", b"default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"),
    (b"x-frame-options", b"DENY"),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"cache-control", b"no-store, no-cache, must-revalidate, private"),
]

OVERRIDDEN_SECURITY_HEADER_NAMES: frozenset[bytes] = frozenset(
    header[0].lower() for header in HARDENED_SECURITY_HEADERS
)


class SecurityHeadersMiddleware:
    """Outermost ASGI middleware enforcing hardened HTTP security headers on all responses."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_security_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                raw_headers: List[Tuple[bytes, bytes]] = list(message.get("headers", []))
                filtered_headers = [
                    (name, value)
                    for name, value in raw_headers
                    if name.lower() not in OVERRIDDEN_SECURITY_HEADER_NAMES
                ]
                filtered_headers.extend(HARDENED_SECURITY_HEADERS)
                message["headers"] = filtered_headers
            await send(message)

        await self.app(scope, receive, send_with_security_headers)

    def __getattr__(self, name: str) -> Any:
        return getattr(self.app, name)
