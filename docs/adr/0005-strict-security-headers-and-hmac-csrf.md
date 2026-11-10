# Strict Security Headers and HMAC Double-Submit CSRF Without Database

The dashboard serves private cryptographic keys and network configurations over HTTP, making it a critical target for cross-site request forgery and clickjacking. We decided to enforce strict security headers (`Content-Security-Policy: default-src 'self'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store`) across all sensitive routes, paired with session-bound HMAC double-submit CSRF tokens on state-changing operations like POST `/logout`. This provides robust browser defense-in-depth without external security middleware or database storage.

## Outermost ASGI Composition for Security Middleware

Security middleware imposing response-wide headers (and preventing diagnostic leakage) must wrap the fully configured FastAPI application as an outer ASGI callable (`SecurityHeadersMiddleware(fastapi_app)`). Because framework error handlers (such as Starlette's `ServerErrorMiddleware`) generate HTTP 500 responses outside standard inner route middleware, only an outermost ASGI wrapper intercepts all responses across successful routes (200), client errors (404, 405), and unhandled server errors (500).

Explicitly discouraged patterns:
- **Instance monkey-patching**: Mutating `app.build_middleware_stack` on a live instance couples application behavior to Starlette internal lifecycle mechanics.
- **Overriding `build_middleware_stack()`**: Subclassing framework classes to inject outer middleware overrides internal wiring and risks breaking across framework upgrades.
- **Framework-internal ordering assumptions**: Do not rely on internal middleware registration order to catch errors handled by outer framework error middlewares. Wrap the completed application directly.

## Security Header Provenance and Reverse-Proxy Trust

Security-sensitive decisions must never rely on untrusted reverse-proxy forwarding headers:
- Do not trust `X-Forwarded-For`, `X-Forwarded-Proto`, or equivalent forwarding headers unless the immediate proxy is explicitly configured and verified as trusted.
- Do not permit untrusted headers to weaken authentication, rate limiting, transport security, or cookie protection.
- Production session cookies must remain `Secure` by default.
- Reverse-proxy TLS termination must use explicitly trusted proxy configuration rather than blind header inheritance.
- Development-only insecure cookie settings must require explicit opt-in (e.g., `COOKIE_SECURE=false`) and must never become the default production behavior.

## Centralized CSRF Request Validation Reuse

New state-changing HTTP endpoints (POST, PUT, DELETE, PATCH) must reuse the application's centralized CSRF validation mechanism (`_validate_csrf_request()`) rather than duplicating cookie, form, header, and HMAC verification logic:
- **Separation of Tokens**: Maintain strict separation between pre-authentication CSRF tokens (bound to pre-auth nonces) and authenticated session-bound CSRF tokens (bound to active session IDs).
- **Double-Submit Enforcement**: Validate that submitted form (`csrf_token`) or header (`X-CSRF-Token`) tokens match the active `wg_dashboard_csrf` cookie and satisfy HMAC signature checks.
- **Fail Closed**: Missing, mismatched, tampered, or cross-session CSRF tokens must return HTTP 403 Forbidden.
- **AUTH_DISABLED Policy**: Maintain consistent bypass behavior under `AUTH_DISABLED=true` without weakening CSRF protections when authentication is enabled.
- **Read-Only Exemption**: Safe, idempotent read-only GET endpoints must not require CSRF tokens.


