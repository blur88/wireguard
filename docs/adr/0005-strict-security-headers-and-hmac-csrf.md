# Strict Security Headers and HMAC Double-Submit CSRF Without Database

The dashboard serves private cryptographic keys and network configurations over HTTP, making it a critical target for cross-site request forgery and clickjacking. We decided to enforce strict security headers (`Content-Security-Policy: default-src 'self'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store`) across all sensitive routes, paired with session-bound HMAC double-submit CSRF tokens on state-changing operations like POST `/logout`. This provides robust browser defense-in-depth without external security middleware or database storage.

## Outermost ASGI Composition for Security Middleware

Security middleware imposing response-wide headers (and preventing diagnostic leakage) must wrap the fully configured FastAPI application as an outer ASGI callable (`SecurityHeadersMiddleware(fastapi_app)`). Because framework error handlers (such as Starlette's `ServerErrorMiddleware`) generate HTTP 500 responses outside standard inner route middleware, only an outermost ASGI wrapper intercepts all responses across successful routes (200), client errors (404, 405), and unhandled server errors (500).

Explicitly discouraged patterns:
- **Instance monkey-patching**: Mutating `app.build_middleware_stack` on a live instance couples application behavior to Starlette internal lifecycle mechanics.
- **Overriding `build_middleware_stack()`**: Subclassing framework classes to inject outer middleware overrides internal wiring and risks breaking across framework upgrades.
- **Framework-internal ordering assumptions**: Do not rely on internal middleware registration order to catch errors handled by outer framework error middlewares. Wrap the completed application directly.
