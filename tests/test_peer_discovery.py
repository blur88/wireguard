import os
from dataclasses import fields
from pathlib import Path

import pytest

from wireguard_dashboard.peers.backend import (
    PeerBackend,
    PeerMetadata,
    ReadOnlyFilesystemBackend,
)


def test_peer_backend_protocol_conformance(tmp_path: Path) -> None:
    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
    assert isinstance(backend, PeerBackend)
    assert hasattr(backend, "get_peer_conf")


def test_get_peer_conf_retrieves_exact_content_for_valid_peer(tmp_path: Path) -> None:
    peer1_dir = tmp_path / "peer1"
    peer1_dir.mkdir()
    conf_content = (
        "[Interface]\n"
        "Address = 10.13.13.2/32\n"
        "PrivateKey = SENSITIVE_CLIENT_PRIVATE_KEY_111111111=\n"
        "DNS = 1.1.1.1\n\n"
        "[Peer]\n"
        "PublicKey = SENSITIVE_SERVER_PUBLIC_KEY_AAAAAA=\n"
        "Endpoint = vpn.example.com:51820\n"
        "AllowedIPs = 0.0.0.0/0\n"
    )
    conf_file = peer1_dir / "peer1.conf"
    conf_file.write_text(conf_content)

    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
    result = backend.get_peer_conf("peer1")
    assert result == conf_content

    # Verify source file is untouched
    assert conf_file.read_text() == conf_content


def test_get_peer_conf_returns_none_for_missing_or_invalid_peer_id(tmp_path: Path) -> None:
    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
    assert backend.get_peer_conf("peer_nonexistent") is None
    assert backend.get_peer_conf("peer1") is None
    assert backend.get_peer_conf("../peer1") is None
    assert backend.get_peer_conf("peer1/foo") is None
    assert backend.get_peer_conf("../../etc/shadow") is None
    assert backend.get_peer_conf("peer_invalid$name") is None
    assert backend.get_peer_conf("peer1\n") is None
    assert backend.get_peer_conf("peer_phone\n") is None
    assert backend.get_peer_conf("") is None


def test_get_peer_conf_rejects_excluded_names_and_server_configs(tmp_path: Path) -> None:
    server_dir = tmp_path / "server"
    server_dir.mkdir()
    (server_dir / "server.conf").write_text("[Interface]\nPrivateKey = SERVER_SECRET\n")

    wg_confs = tmp_path / "wg_confs"
    wg_confs.mkdir()
    (wg_confs / "wg0.conf").write_text("[Interface]\nPrivateKey = WG0_SECRET\n")

    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
    assert backend.get_peer_conf("server") is None
    assert backend.get_peer_conf("wg_confs") is None
    assert backend.get_peer_conf("wg0.conf") is None
    assert backend.get_peer_conf("templates") is None


def test_get_peer_conf_rejects_symlinked_directory_and_file(tmp_path: Path) -> None:
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside_secret = outside_dir / "secret.conf"
    outside_secret.write_text("[Interface]\nPrivateKey = OUTSIDE_SECRET\n")

    # 1. Symlinked directory
    symlinked_peer = tmp_path / "peer1"
    symlinked_peer.symlink_to(outside_dir)

    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
    assert backend.get_peer_conf("peer1") is None

    symlinked_peer.unlink()

    # 2. Real directory, symlinked conf file
    real_peer_dir = tmp_path / "peer1"
    real_peer_dir.mkdir()
    symlinked_conf = real_peer_dir / "peer1.conf"
    symlinked_conf.symlink_to(outside_secret)

    assert backend.get_peer_conf("peer1") is None


def test_get_peer_conf_rejects_oversized_configuration(tmp_path: Path) -> None:
    peer_dir = tmp_path / "peer1"
    peer_dir.mkdir()
    oversized = "A" * (65 * 1024)
    (peer_dir / "peer1.conf").write_text(oversized)

    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
    assert backend.get_peer_conf("peer1") is None


def test_get_peer_conf_toctou_symlink_replacement_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    peer_dir = tmp_path / "peer1"
    peer_dir.mkdir()
    real_conf = peer_dir / "peer1.conf"
    real_conf.write_text("[Interface]\nAddress = 10.0.0.1\n")

    secret_dir = tmp_path / "secret"
    secret_dir.mkdir()
    (secret_dir / "peer1.conf").write_text("[Interface]\nPrivateKey = EXPLOIT\n")

    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)

    # 1. Directory symlink replacement race
    orig_open = os.open

    def race_open_dir(
        path: os.PathLike[str] | str | bytes,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == "peer1" and (flags & os.O_NOFOLLOW):
            # Dynamic race replacement before opening candidate peer dir
            real_conf.unlink()
            peer_dir.rmdir()
            peer_dir.symlink_to(secret_dir)
        return orig_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", race_open_dir)
    assert backend.get_peer_conf("peer1") is None


def test_get_peer_conf_toctou_conf_file_symlink_replacement_race(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    peer_dir = tmp_path / "peer1"
    peer_dir.mkdir()
    real_conf = peer_dir / "peer1.conf"
    real_conf.write_text("[Interface]\nAddress = 10.0.0.1\n")

    secret_file = tmp_path / "secret_file.conf"
    secret_file.write_text("[Interface]\nPrivateKey = FILE_EXPLOIT\n")

    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)

    orig_open = os.open

    def race_open_file(
        path: os.PathLike[str] | str | bytes,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path == "peer1.conf" and (flags & os.O_NOFOLLOW):
            # Dynamic race replacement before opening candidate peer conf file
            real_conf.unlink()
            real_conf.symlink_to(secret_file)
        return orig_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", race_open_file)
    assert backend.get_peer_conf("peer1") is None


def test_peer_metadata_does_not_have_secret_fields() -> None:
    field_names = {f.name.lower() for f in fields(PeerMetadata)}
    forbidden = {
        "private_key",
        "privatekey",
        "preshared_key",
        "presharedkey",
        "public_key",
        "publickey",
        "secret",
        "raw_conf",
    }
    assert field_names.isdisjoint(forbidden), (
        f"PeerMetadata exposes forbidden fields: {field_names & forbidden}"
    )


def test_discovery_numbered_and_named_peers(tmp_path: Path) -> None:
    # Setup valid numbered and named peers
    peer1_dir = tmp_path / "peer1"
    peer1_dir.mkdir()
    (peer1_dir / "peer1.conf").write_text(
        "[Interface]\n"
        "Address = 10.13.13.2/32\n"
        "PrivateKey = SENSITIVE_CLIENT_PRIVATE_KEY_111111111=\n"
        "DNS = 1.1.1.1\n\n"
        "[Peer]\n"
        "PublicKey = SENSITIVE_SERVER_PUBLIC_KEY_AAAAAA=\n"
        "Endpoint = vpn.example.com:51820\n"
        "AllowedIPs = 0.0.0.0/0\n"
    )

    peer_phone_dir = tmp_path / "peer_phone"
    peer_phone_dir.mkdir()
    (peer_phone_dir / "peer_phone.conf").write_text(
        "[Interface]\n"
        "Address = 10.13.13.3/32, fd42:42:42::3/128\n"
        "PrivateKey = SENSITIVE_CLIENT_PRIVATE_KEY_222222222=\n"
        "DNS = 1.1.1.1, 8.8.8.8\n\n"
        "[Peer]\n"
        "PublicKey = SENSITIVE_SERVER_PUBLIC_KEY_BBBBBB=\n"
        "PresharedKey = SENSITIVE_PRESHARED_KEY_CCCCCC=\n"
        "Endpoint = vpn.example.com:51820\n"
    )

    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
    peers = backend.list_peers()

    assert len(peers) == 2
    peer_ids = [p.peer_id for p in peers]
    assert peer_ids == ["peer1", "peer_phone"]

    # Check sanitized metadata
    p1 = next(p for p in peers if p.peer_id == "peer1")
    assert p1.friendly_name == "peer1"
    assert p1.address == "10.13.13.2/32"
    assert p1.dns == "1.1.1.1"
    assert p1.endpoint == "vpn.example.com:51820"

    p_phone = next(p for p in peers if p.peer_id == "peer_phone")
    assert p_phone.friendly_name == "phone"
    assert p_phone.address == "10.13.13.3/32, fd42:42:42::3/128"
    assert p_phone.dns == "1.1.1.1, 8.8.8.8"
    assert p_phone.endpoint == "vpn.example.com:51820"

    # Verify secrets are never in metadata string representations
    for p in peers:
        meta_repr = repr(p)
        assert "SENSITIVE" not in meta_repr


def test_discovery_natural_sorting(tmp_path: Path) -> None:
    # peer1, peer2, peer10, peer_alpha, peer_zebra
    for name in ["peer10", "peer2", "peer1", "peer_zebra", "peer_alpha"]:
        d = tmp_path / name
        d.mkdir()
        (d / f"{name}.conf").write_text("[Interface]\nAddress = 10.0.0.1\n")

    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
    peers = backend.list_peers()
    assert [p.peer_id for p in peers] == ["peer1", "peer2", "peer10", "peer_alpha", "peer_zebra"]


def test_discovery_explicitly_excludes_server_and_unrelated_directories(tmp_path: Path) -> None:
    # Excluded server configs
    for excluded_dir in ["server", "templates", "wg_confs", "other_dir", "peer", "peers"]:
        d = tmp_path / excluded_dir
        d.mkdir()
        (d / f"{excluded_dir}.conf").write_text("[Interface]\nAddress = 10.0.0.1\n")

    # Server config file at root
    (tmp_path / "wg0.conf").write_text("[Interface]\nPrivateKey = ROOT_KEY\n")
    (tmp_path / "peer1.conf").write_text("[Interface]\nAddress = 10.0.0.1\n")  # Not in peer1/

    # Valid peer
    valid_dir = tmp_path / "peer1"
    valid_dir.mkdir()
    (valid_dir / "peer1.conf").write_text("[Interface]\nAddress = 10.13.13.2/32\n")

    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
    peers = backend.list_peers()
    assert len(peers) == 1
    assert peers[0].peer_id == "peer1"


def test_discovery_and_conf_reject_peer_with_trailing_newline(tmp_path: Path) -> None:
    # Directory with trailing newline
    newline_dir = tmp_path / "peer1\n"
    newline_dir.mkdir()
    (newline_dir / "peer1\n.conf").write_text("[Interface]\nAddress = 10.13.13.2/32\n")

    # Valid peer directory alongside
    valid_dir = tmp_path / "peer1"
    valid_dir.mkdir()
    (valid_dir / "peer1.conf").write_text("[Interface]\nAddress = 10.13.13.3/32\n")

    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
    peers = backend.list_peers()

    # Discovery must reject directory with trailing newline and only list valid peer
    assert len(peers) == 1
    assert peers[0].peer_id == "peer1"

    # get_peer_conf must reject trailing newline peer_ids
    assert backend.get_peer_conf("peer1\n") is None
    assert backend.get_peer_conf("peer_phone\n") is None
    # Valid peer configuration is still retrievable
    assert backend.get_peer_conf("peer1") == "[Interface]\nAddress = 10.13.13.3/32\n"


def test_discovery_rejects_symlink_peer_directory(tmp_path: Path) -> None:
    real_target = tmp_path / "target_peer"
    real_target.mkdir()
    (real_target / "peer1.conf").write_text("[Interface]\nAddress = 10.13.13.2/32\n")

    # Symlink as peer1
    symlink_dir = tmp_path / "peer1"
    symlink_dir.symlink_to(real_target)

    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
    peers = backend.list_peers()
    assert len(peers) == 0


def test_discovery_rejects_symlink_conf_file(tmp_path: Path) -> None:
    peer_dir = tmp_path / "peer1"
    peer_dir.mkdir()

    outside_file = tmp_path / "external_secret.txt"
    outside_file.write_text("[Interface]\nAddress = 10.13.13.2/32\n")

    conf_symlink = peer_dir / "peer1.conf"
    conf_symlink.symlink_to(outside_file)

    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
    peers = backend.list_peers()
    assert len(peers) == 0


def test_discovery_rejects_non_regular_file(tmp_path: Path) -> None:
    peer_dir = tmp_path / "peer1"
    peer_dir.mkdir()

    # peer1.conf is a directory instead of a regular file
    conf_dir = peer_dir / "peer1.conf"
    conf_dir.mkdir()

    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
    peers = backend.list_peers()
    assert len(peers) == 0


def test_discovery_handles_empty_or_malformed_config_gracefully(tmp_path: Path) -> None:
    # Empty conf
    p1 = tmp_path / "peer1"
    p1.mkdir()
    (p1 / "peer1.conf").write_text("")

    # Corrupted / binary conf
    p2 = tmp_path / "peer2"
    p2.mkdir()
    (p2 / "peer2.conf").write_bytes(b"\x00\xff\xfe\x01\x02malformed\nwithout sections")

    # Valid peer
    p3 = tmp_path / "peer3"
    p3.mkdir()
    (p3 / "peer3.conf").write_text("[Interface]\nAddress = 10.13.13.5/32\n")

    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
    peers = backend.list_peers()

    # p1 and p2 should still be listed or safely handled without crashing
    assert len(peers) == 3
    peer_ids = [p.peer_id for p in peers]
    assert peer_ids == ["peer1", "peer2", "peer3"]

    p1_meta = next(p for p in peers if p.peer_id == "peer1")
    assert p1_meta.address is None

    p2_meta = next(p for p in peers if p.peer_id == "peer2")
    assert p2_meta.address is None

    p3_meta = next(p for p in peers if p.peer_id == "peer3")
    assert p3_meta.address == "10.13.13.5/32"


def test_discovery_rejects_oversized_config(tmp_path: Path) -> None:
    peer_dir = tmp_path / "peer1"
    peer_dir.mkdir()

    # Create a 200KB configuration (exceeds max size limit e.g. 64KB)
    oversized_content = "[Interface]\nAddress = 10.13.13.2/32\n" + ("# comment\n" * 15000)
    (peer_dir / "peer1.conf").write_text(oversized_content)

    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
    peers = backend.list_peers()
    # Handled safely, does not read or parse oversized content
    p1_meta = peers[0]
    assert p1_meta.address is None


def test_rescan_reflects_filesystem_changes(tmp_path: Path) -> None:
    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
    assert len(backend.list_peers()) == 0

    p1 = tmp_path / "peer1"
    p1.mkdir()
    (p1 / "peer1.conf").write_text("[Interface]\nAddress = 10.13.13.2/32\n")

    # Rescan reflects added peer
    updated = backend.rescan()
    assert len(updated) == 1
    assert updated[0].peer_id == "peer1"

    # Remove peer
    (p1 / "peer1.conf").unlink()
    p1.rmdir()

    assert len(backend.rescan()) == 0


def test_missing_or_non_directory_config_dir(tmp_path: Path) -> None:
    non_existent = tmp_path / "does_not_exist"
    backend = ReadOnlyFilesystemBackend(config_dir=non_existent)
    assert backend.list_peers() == []


def test_adversarial_traversal_directory_names(tmp_path: Path) -> None:
    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
    # Even if entries with dots or separators existed on disk somehow
    # The regex and descriptor-relative open rejects any ../ traversal
    assert backend.get_peer_metadata("../peer1") is None
    assert backend.get_peer_metadata("..") is None
    assert backend.get_peer_metadata("peer_../../etc") is None


def test_unreadable_file_or_dir_handled_gracefully(tmp_path: Path) -> None:
    peer_dir = tmp_path / "peer1"
    peer_dir.mkdir()
    conf_file = peer_dir / "peer1.conf"
    conf_file.write_text("[Interface]\nAddress = 10.13.13.2/32\n")

    # Set conf file unreadable (000)
    conf_file.chmod(0)
    try:
        backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
        # Should not crash; returns empty or skips unreadable
        peers = backend.list_peers()
        assert isinstance(peers, list)
    finally:
        conf_file.chmod(0o644)


def test_discovery_strips_inline_comments(tmp_path: Path) -> None:
    peer_dir = tmp_path / "peer1"
    peer_dir.mkdir()
    (peer_dir / "peer1.conf").write_text(
        "[Interface]\n"
        "Address = 10.13.13.2/32 # primary client address\n"
        "DNS = 1.1.1.1 ; fallback dns\n\n"
        "[Peer]\n"
        "Endpoint = vpn.example.com:51820 # remote endpoint\n"
    )

    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
    peers = backend.list_peers()
    assert len(peers) == 1
    p = peers[0]
    assert p.address == "10.13.13.2/32"
    assert p.dns == "1.1.1.1"
    assert p.endpoint == "vpn.example.com:51820"


def test_toctou_symlink_race_protection(tmp_path: Path) -> None:
    # Verify descriptor-relative opening with O_NOFOLLOW prevents escapes
    # even when paths are modified or linked dynamically
    secret_dir = tmp_path / "secret_server"
    secret_dir.mkdir()
    (secret_dir / "server.conf").write_text("[Interface]\nPrivateKey = ROOT_PRIVATE_KEY\n")

    peer_dir = tmp_path / "peer1"
    peer_dir.mkdir()
    conf_file = peer_dir / "peer1.conf"
    conf_file.write_text("[Interface]\nAddress = 10.13.13.2/32\n")

    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)

    # Replace peer1.conf with symlink to secret
    conf_file.unlink()
    conf_file.symlink_to(secret_dir / "server.conf")

    peers = backend.list_peers()
    assert len(peers) == 0  # Symlink escape rejected via O_NOFOLLOW


def test_toctou_conf_file_race_between_enumeration_and_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret_file = tmp_path / "secret.conf"
    secret_file.write_text("[Interface]\nPrivateKey = SENSITIVE_ROOT_KEY\n")

    peer_dir = tmp_path / "peer1"
    peer_dir.mkdir()
    conf_file = peer_dir / "peer1.conf"
    conf_file.write_text("[Interface]\nAddress = 10.13.13.2/32\n")

    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
    orig_listdir = os.listdir

    def race_listdir(fd: int) -> list[str]:
        entries = orig_listdir(fd)
        # Emulate race condition: swap file with a symlink right after listdir enumeration
        conf_file.unlink()
        conf_file.symlink_to(secret_file)
        return entries

    monkeypatch.setattr(os, "listdir", race_listdir)

    peers = backend.list_peers()
    assert len(peers) == 0


def test_toctou_directory_race_between_enumeration_and_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret_dir = tmp_path / "secret_server"
    secret_dir.mkdir()
    (secret_dir / "peer1.conf").write_text("[Interface]\nPrivateKey = SENSITIVE_ROOT_KEY\n")

    peer_dir = tmp_path / "peer1"
    peer_dir.mkdir()
    (peer_dir / "peer1.conf").write_text("[Interface]\nAddress = 10.13.13.2/32\n")

    backend = ReadOnlyFilesystemBackend(config_dir=tmp_path)
    orig_listdir = os.listdir

    def race_listdir(fd: int) -> list[str]:
        entries = orig_listdir(fd)
        # Emulate race condition: swap directory with a symlink right after listdir enumeration
        (peer_dir / "peer1.conf").unlink()
        peer_dir.rmdir()
        peer_dir.symlink_to(secret_dir)
        return entries

    monkeypatch.setattr(os, "listdir", race_listdir)

    peers = backend.list_peers()
    assert len(peers) == 0
