from wireguard_dashboard.auth.session import SessionRegistry


def test_session_registration_and_active_lookup() -> None:
    registry = SessionRegistry()
    session_id = "test-session-1"
    fingerprint = "fp-abc"
    expires_at = 1000.0

    registry.register(session_id=session_id, fingerprint=fingerprint, expires_at=expires_at)
    assert registry.is_active(
        session_id=session_id,
        current_fingerprint=fingerprint,
        current_time=500.0,
    )


def test_unknown_session_id_is_rejected() -> None:
    registry = SessionRegistry()
    assert not registry.is_active(
        session_id="non-existent-session-id",
        current_fingerprint="fp-abc",
        current_time=500.0,
    )


def test_expired_session_rejection_and_cleanup() -> None:
    registry = SessionRegistry()
    registry.register("session-1", "fp-123", expires_at=100.0)
    registry.register("session-2", "fp-123", expires_at=200.0)

    # At time 150: session-1 is expired, session-2 is still valid
    assert not registry.is_active("session-1", "fp-123", current_time=150.0)
    assert registry.is_active("session-2", "fp-123", current_time=150.0)

    # Calling cleanup_expired removes expired sessions
    cleaned = registry.cleanup_expired(current_time=150.0)
    assert cleaned == 1

    # At time 250: session-2 is also expired
    assert not registry.is_active("session-2", "fp-123", current_time=250.0)
    assert registry.cleanup_expired(current_time=250.0) == 1


def test_immediate_single_session_revocation() -> None:
    registry = SessionRegistry()
    registry.register("session-1", "fp-123", expires_at=1000.0)
    registry.register("session-2", "fp-123", expires_at=1000.0)

    assert registry.revoke("session-1") is True
    # Revoking already revoked session returns False
    assert registry.revoke("session-1") is False

    # session-1 is revoked immediately
    assert not registry.is_active("session-1", "fp-123", current_time=500.0)
    # session-2 remains active
    assert registry.is_active("session-2", "fp-123", current_time=500.0)


def test_revoke_all_invalidates_every_session() -> None:
    registry = SessionRegistry()
    registry.register("session-1", "fp-123", expires_at=1000.0)
    registry.register("session-2", "fp-123", expires_at=1000.0)
    registry.register("session-3", "fp-456", expires_at=1000.0)

    registry.revoke_all()

    assert not registry.is_active("session-1", "fp-123", current_time=500.0)
    assert not registry.is_active("session-2", "fp-123", current_time=500.0)
    assert not registry.is_active("session-3", "fp-456", current_time=500.0)


def test_credential_fingerprint_mismatch_is_rejected() -> None:
    registry = SessionRegistry()
    registry.register("session-1", "fp-original", expires_at=1000.0)

    # When fingerprint matches
    assert registry.is_active("session-1", "fp-original", current_time=500.0)
    # When password or secret rotated, resulting in different fingerprint
    assert not registry.is_active("session-1", "fp-rotated", current_time=500.0)


def test_multiple_concurrently_active_sessions() -> None:
    registry = SessionRegistry()
    registry.register("session-device-a", "fp-shared", expires_at=1000.0)
    registry.register("session-device-b", "fp-shared", expires_at=1000.0)
    registry.register("session-device-c", "fp-shared", expires_at=1000.0)

    # All three active simultaneously
    assert registry.is_active("session-device-a", "fp-shared", current_time=500.0)
    assert registry.is_active("session-device-b", "fp-shared", current_time=500.0)
    assert registry.is_active("session-device-c", "fp-shared", current_time=500.0)

    # Revoking device-b does not affect device-a or device-c
    registry.revoke("session-device-b")
    assert registry.is_active("session-device-a", "fp-shared", current_time=500.0)
    assert not registry.is_active("session-device-b", "fp-shared", current_time=500.0)
    assert registry.is_active("session-device-c", "fp-shared", current_time=500.0)


def test_revoked_session_cannot_be_resurrected() -> None:
    registry = SessionRegistry()
    registry.register("session-1", "fp-123", expires_at=1000.0)
    assert registry.is_active("session-1", "fp-123", current_time=500.0)

    registry.revoke("session-1")
    assert not registry.is_active("session-1", "fp-123", current_time=500.0)

    # Even if credentials change or stay same or time moves forward, revoked session is gone
    assert not registry.is_active("session-1", "fp-123", current_time=600.0)
    assert not registry.is_active("session-1", "fp-new", current_time=600.0)


def test_registry_isolation_between_instances() -> None:
    registry_a = SessionRegistry()
    registry_b = SessionRegistry()

    registry_a.register("session-app-a", "fp-123", expires_at=1000.0)

    # Active in A
    assert registry_a.is_active("session-app-a", "fp-123", current_time=500.0)
    # Not active in B (instance isolation)
    assert not registry_b.is_active("session-app-a", "fp-123", current_time=500.0)
