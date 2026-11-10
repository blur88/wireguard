import logging
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

logger = logging.getLogger("wireguard_dashboard.peers")

MAX_CONF_SIZE_BYTES = 64 * 1024  # 64 KB limit for WireGuard peer configuration files
EXCLUDED_NAMES = frozenset({"server", "templates", "wg_confs", "wg0.conf"})
PEER_PATTERN = re.compile(r"^(peer\d+|peer_[a-zA-Z0-9_-]+)$")


@dataclass(frozen=True)
class PeerMetadata:
    """Sanitized metadata extracted from a WireGuard peer configuration."""

    peer_id: str
    friendly_name: str
    address: str | None = None
    dns: str | None = None
    endpoint: str | None = None


@runtime_checkable
class PeerBackend(Protocol):
    """Protocol for peer discovery and configuration access."""

    def list_peers(self) -> list[PeerMetadata]:
        """Discover and return all valid peers sorted naturally."""
        ...

    def rescan(self) -> list[PeerMetadata]:
        """Perform a fresh discovery of all valid peers."""
        ...

    def get_peer_metadata(self, peer_id: str) -> PeerMetadata | None:
        """Retrieve metadata for a specific peer identifier."""
        ...

    def get_peer_conf(self, peer_id: str) -> str | None:
        """Retrieve the raw configuration content for a specific peer on demand."""
        ...


def _natural_sort_key(s: str) -> list[int | str]:
    """Sort key for natural alphanumeric ordering (e.g. peer2 before peer10)."""
    return [int(text) if text.isdigit() else text.lower() for text in re.split(r"(\d+)", s)]


def _parse_sanitized_conf(content: str) -> tuple[str | None, str | None, str | None]:
    """Parse a WireGuard peer configuration and extract only non-sensitive metadata.

    Returns:
        (address, dns, endpoint)
    """
    current_section: str | None = None
    address: str | None = None
    dns: str | None = None
    endpoint: str | None = None

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue

        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].strip().lower()
            continue

        if "=" not in line:
            continue

        key, _, value = line.partition("=")
        key = key.strip().lower()
        val = value.strip()

        # Strip any inline comments
        if "#" in val:
            val = val.split("#", 1)[0].strip()
        if ";" in val:
            val = val.split(";", 1)[0].strip()

        # Strict security filter: Never extract or store cryptographic keys
        if key in ("privatekey", "presharedkey", "publickey"):
            continue

        if current_section == "interface":
            if key == "address":
                address = f"{address}, {val}" if address else val
            elif key == "dns":
                dns = f"{dns}, {val}" if dns else val
        elif current_section == "peer":
            if key == "endpoint" and not endpoint:
                endpoint = val

    return address, dns, endpoint


class ReadOnlyFilesystemBackend:
    """Strict, descriptor-relative filesystem discovery backend for LinuxServer WireGuard peers."""

    def __init__(self, config_dir: Path) -> None:
        self.config_dir = config_dir

    def list_peers(self) -> list[PeerMetadata]:
        """Discover and return all recognized, sanitized peers under config_dir."""
        if not self.config_dir.is_dir():
            return []

        base_fd: int | None = None
        try:
            # Open the base config directory with O_DIRECTORY and O_CLOEXEC
            base_fd = os.open(str(self.config_dir), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        except OSError as err:
            logger.warning(
                "Failed to open base configuration directory %s: %s",
                self.config_dir,
                err,
            )
            return []

        peers: list[PeerMetadata] = []
        try:
            entries = os.listdir(base_fd)
            for entry in entries:
                # 1. Name validation and explicit exclusion check
                if entry in EXCLUDED_NAMES or not PEER_PATTERN.match(entry):
                    continue

                sub_fd: int | None = None
                try:
                    # 2. Descriptor-relative open of candidate peer directory
                    # O_NOFOLLOW guarantees that symlinked directories are rejected
                    sub_fd = os.open(
                        entry,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=base_fd,
                    )
                except OSError:
                    continue

                try:
                    st = os.fstat(sub_fd)
                    if not stat.S_ISDIR(st.st_mode):
                        continue

                    # 3. Descriptor-relative open of matching <peer>.conf file
                    conf_filename = f"{entry}.conf"
                    conf_fd: int | None = None
                    try:
                        # O_NOFOLLOW ensures symlinked configuration files are rejected
                        conf_fd = os.open(
                            conf_filename,
                            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=sub_fd,
                        )
                    except OSError:
                        continue

                    try:
                        c_st = os.fstat(conf_fd)
                        if not stat.S_ISREG(c_st.st_mode):
                            continue

                        address: str | None = None
                        dns: str | None = None
                        endpoint: str | None = None

                        if c_st.st_size <= MAX_CONF_SIZE_BYTES:
                            raw_bytes = os.read(conf_fd, MAX_CONF_SIZE_BYTES)
                            content = raw_bytes.decode("utf-8", errors="replace")
                            address, dns, endpoint = _parse_sanitized_conf(content)
                        else:
                            logger.warning(
                                "Configuration for peer '%s' exceeds limit (%d bytes); skipping",
                                entry,
                                c_st.st_size,
                            )

                        friendly_name = entry[5:] if entry.startswith("peer_") else entry
                        peers.append(
                            PeerMetadata(
                                peer_id=entry,
                                friendly_name=friendly_name,
                                address=address,
                                dns=dns,
                                endpoint=endpoint,
                            )
                        )
                    finally:
                        if conf_fd is not None:
                            os.close(conf_fd)
                finally:
                    if sub_fd is not None:
                        os.close(sub_fd)
        finally:
            if base_fd is not None:
                os.close(base_fd)

        peers.sort(key=lambda p: _natural_sort_key(p.peer_id))
        return peers

    def rescan(self) -> list[PeerMetadata]:
        """Perform a fresh discovery of all valid peers."""
        return self.list_peers()

    def get_peer_metadata(self, peer_id: str) -> PeerMetadata | None:
        """Retrieve metadata for a single peer without exposing secrets."""
        for peer in self.list_peers():
            if peer.peer_id == peer_id:
                return peer
        return None

    def get_peer_conf(self, peer_id: str) -> str | None:
        """Retrieve raw configuration content for a peer on demand descriptor-relatively."""
        if not peer_id or peer_id in EXCLUDED_NAMES or not PEER_PATTERN.match(peer_id):
            return None

        if not self.config_dir.is_dir():
            return None

        base_fd: int | None = None
        try:
            base_fd = os.open(str(self.config_dir), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        except OSError as err:
            logger.warning(
                "Failed to open base configuration directory %s: %s",
                self.config_dir,
                err,
            )
            return None

        try:
            sub_fd: int | None = None
            try:
                sub_fd = os.open(
                    peer_id,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=base_fd,
                )
            except OSError:
                return None

            try:
                st = os.fstat(sub_fd)
                if not stat.S_ISDIR(st.st_mode):
                    return None

                conf_filename = f"{peer_id}.conf"
                conf_fd: int | None = None
                try:
                    conf_fd = os.open(
                        conf_filename,
                        os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=sub_fd,
                    )
                except OSError:
                    return None

                try:
                    c_st = os.fstat(conf_fd)
                    if not stat.S_ISREG(c_st.st_mode):
                        return None

                    if c_st.st_size > MAX_CONF_SIZE_BYTES:
                        logger.warning(
                            "Configuration for peer '%s' exceeds limit (%d bytes); rejecting",
                            peer_id,
                            c_st.st_size,
                        )
                        return None

                    raw_bytes = os.read(conf_fd, MAX_CONF_SIZE_BYTES)
                    return raw_bytes.decode("utf-8", errors="replace")
                finally:
                    if conf_fd is not None:
                        os.close(conf_fd)
            finally:
                if sub_fd is not None:
                    os.close(sub_fd)
        finally:
            if base_fd is not None:
                os.close(base_fd)
