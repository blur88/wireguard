# Strict Peer Directory Discovery and Exclusion Rules

Arbitrarily parsing every `.conf` file inside `/config` risks exposing server private keys, templates, and internal server configurations (e.g. `wg0.conf`). We decided that the discovery engine will strictly match subdirectories following LinuxServer WireGuard naming conventions (`peer<id>/peer<id>.conf` and `peer_<name>/peer_<name>.conf`), explicitly excluding `server`, `templates`, and `wg_confs`, while enforcing symlink and path traversal rejection. This guarantees that only valid peer configurations are discovered and served.

## Dynamic TOCTOU Race Protection Standard

Filesystem security implementations claiming TOCTOU protection must provide deterministic automated tests covering path replacement races between directory enumeration/validation and secure opening:
- **Replacement Scope**: Tests must verify race behavior for both peer directory and configuration file symlink replacement.
- **Boundary Containment**: Opening operations must never escape the permitted base directory boundary, and external sensitive file contents must never be returned or exposed in logs.
- **Deterministic Testing**: Static symlink rejection tests alone are insufficient to establish race protection. Tests must use deterministic test-controlled replacement (such as monkeypatching an appropriate filesystem enumeration hook) rather than timing-dependent loops or arbitrary sleeps.
- **Descriptor-Relative Enforcement**: Implementations must maintain descriptor-relative access (`dir_fd` with `O_NOFOLLOW | os.O_CLOEXEC`) so that any dynamic replacement of path components with symlinks fails closed at the kernel level.
