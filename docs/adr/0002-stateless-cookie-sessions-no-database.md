# Database-Free In-Memory Active-Session Registry with Full Restart & Rotation Invalidation

A single-admin dashboard requires secure session management, immediate logout revocation, and credential rotation without the operational overhead and state corruption risks of an external database like SQLite, Postgres, or Redis. We decided to implement signed HttpOnly SameSite=Strict session cookies validated against a single-worker, database-free in-memory active-session registry. Sessions are bound to a cryptographic fingerprint derived from the master credential and session secret; any application restart, container recreation, credential rotation, or session secret rotation immediately invalidates all active sessions. This eliminates the risk of resurrected tokens upon restart, guarantees instant logout revocation, and maintains zero database dependencies.

## Implementation Boundary: Issue #3 vs. Issue #4

To resolve the circular dependency between issuing signed session cookies in Issue #3 and session lifecycle management in Issue #4:

- **Issue #3 (Single-Admin Authentication & Secure Login)**:
  - Minimal secure session signing-secret loading and validation via `SESSION_SECRET` and `SESSION_SECRET_FILE` (failing closed if missing, empty, or below cryptographic minimum of 32 bytes when authentication is enabled).
  - Signed cookie creation, signature verification, tampering detection, expiration validation, and master credential fingerprint matching.
  - Hardened cookie flags (`HttpOnly`, `SameSite=Strict`, `Secure` when HTTPS/TLS or configurable for local test).
  - Prevention of password, hash, or secret exposure in cookies, responses, or logs.
  - *Notice*: Issue #3 establishes cryptographically signed tokens bound to credential fingerprints, but the application is not production-ready until Issue #4 introduces the in-memory active session registry and full lifecycle revocation.

- **Issue #4 (Session Lifecycle, Credential Rotation, CSRF & Logout)**:
  - In-memory active-session registry tracking for concurrent revocation and replay prevention.
  - Full application restart / container recreation invalidation (preventing resurrected tokens).
  - Complete credential rotation lifecycle invalidating all devices across rotations.
  - Session-bound HMAC double-submit CSRF protection on state-changing endpoints (such as `POST /logout`).
  - Explicit `POST /logout` endpoint with instantaneous session registry removal.

## Operational Model for Credential Rotation

Credential configuration (`DASHBOARD_PASSWORD`, `SESSION_SECRET`, and their Docker secret `_FILE` alternatives) is evaluated and validated during application startup.

In containerized deployments, credential and secret rotation takes effect when the container or application process restarts (e.g., via `docker compose restart` or pod recreation). The companion container intentionally avoids background filesystem watchers or polling daemons to remain lean, predictable, and fully unprivileged.

When the application starts with rotated credentials, the server-derived `credential_fingerprint` changes and the in-memory registry initializes empty, immediately and irreversibly invalidating all active sessions across all devices.

## In-Memory Session Lifecycle and Deterministic Memory Reclamation

To prevent memory retention of expired session records without introducing background timer threads or external schedulers, the registry enforces deterministic lazy reclamation:
- During any session verification (`is_active`), expired entries accessed by incoming requests are purged immediately.
- During registration of any new session (`register`), all expired entries in the registry are reclaimed in-band under the registry lock.
- Explicit logout (`revoke`) instantly purges the specific active session and prevents token resurrection.


