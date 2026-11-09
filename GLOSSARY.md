# WireGuard Dashboard

A lightweight, dark-mode companion dashboard for LinuxServer WireGuard Docker deployments.

## Language

**Companion Container**:
An unprivileged Docker container running alongside the LinuxServer WireGuard service with read-only access to `/config`.
_Avoid_: Sidecar with Docker socket, All-in-one container

**Peer**:
A client device configured to connect to the WireGuard VPN server.
_Avoid_: Client, User, Account

**Peer Directory**:
A subdirectory under `/config` strictly matching `peer<id>` (e.g., `peer1`) or `peer_<name>` (e.g., `peer_phone`) containing a matching `.conf` file.
_Avoid_: Arbitrary folder, Config dir

**Peer Identifier**:
A sanitized, stable string identifying a peer (e.g., `peer1`, `peer_phone`) without exposing filesystem paths across routes.
_Avoid_: File path, Path slug

**Peer Configuration**:
The client-side `.conf` file containing interface parameters, assigned IP addresses, and cryptographic keys required for a peer to connect.
_Avoid_: Profile, WG file, Connection settings

**Peer Metadata**:
Non-sensitive configuration details parsed from a peer's configuration (such as assigned IP, DNS, endpoint, and public key).
_Avoid_: Peer secrets, Full configuration dump

**Session**:
A secure, cryptographically signed authentication state maintained via an HttpOnly cookie and bound to a credential fingerprint.
_Avoid_: Token table, Database session

**Credential Fingerprint**:
A server-derived cryptographic hash of the active admin credential used to immediately invalidate all sessions when credentials rotate.
_Avoid_: Plaintext hash, Cookie secret

**CSRF Token**:
A session-bound, HMAC-signed token required on all state-changing HTTP requests to prevent cross-site request forgery.
_Avoid_: Bearer token, Static form token

**Telemetry Provider**:
A decoupled component responsible for querying runtime connection status and traffic statistics.
_Avoid_: WireGuard CLI runner, Live socket reader
