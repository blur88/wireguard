from typing import List, Tuple
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
    """Pure ASGI middleware enforcing hardened HTTP security headers on all responses."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers_started = False

        async def send_with_security_headers(message: Message) -> None:
            nonlocal headers_started
            if message["type"] == "http.response.start":
                headers_started = True
                raw_headers: List[Tuple[bytes, bytes]] = list(message.get("headers", []))
                filtered_headers = [
                    (name, value)
                    for name, value in raw_headers
                    if name.lower() not in OVERRIDDEN_SECURITY_HEADER_NAMES
                ]
                filtered_headers.extend(HARDENED_SECURITY_HEADERS)
                message["headers"] = filtered_headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_security_headers)
        except Exception:
            if not headers_started:
                fallback_headers: List[Tuple[bytes, bytes]] = [
                    (b"content-type", b"application/json"),
                    (b"content-length", b"36"),
                ]
                filtered = [
                    (name, value)
                    for name, value in fallback_headers
                    if name.lower() not in OVERRIDDEN_SECURITY_HEADER_NAMES
                ]
                filtered.extend(HARDENED_SECURITY_HEADERS)
                await send({
                    "type": "http.response.start",
                    "status": 500,
                    "headers": filtered,
                })
                await send({
                    "type": "http.response.body",
                    "body": b'{"detail":"Internal Server Error"}',
                    "more_body": False,
                })
            else:
                raise
