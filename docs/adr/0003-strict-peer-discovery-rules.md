# Strict Peer Directory Discovery and Exclusion Rules

Arbitrarily parsing every `.conf` file inside `/config` risks exposing server private keys, templates, and internal server configurations (e.g. `wg0.conf`). We decided that the discovery engine will strictly match subdirectories following LinuxServer WireGuard naming conventions (`peer<id>/peer<id>.conf` and `peer_<name>/peer_<name>.conf`), explicitly excluding `server`, `templates`, and `wg_confs`, while enforcing symlink and path traversal rejection. This guarantees that only valid client peer configurations are discovered and served.
