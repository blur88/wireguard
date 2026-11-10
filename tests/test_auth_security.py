import pytest

from wireguard_dashboard.auth.security import (
    compute_credential_fingerprint,
    hash_password,
    verify_password,
)


def test_hash_and_verify_valid_password() -> None:
    password = "super-secure-admin-pass"
    hashed = hash_password(password)
    assert hashed.startswith("$argon2id$")
    assert verify_password(password, hashed) is True


def test_verify_invalid_password_returns_false() -> None:
    password = "super-secure-admin-pass"
    hashed = hash_password(password)
    assert verify_password("wrong-password", hashed) is False


def test_different_argon2id_salts_verify_successfully() -> None:
    password = "consistent-password-123"
    hash1 = hash_password(password)
    hash2 = hash_password(password)

    # Different random salts produce different encoded hash strings
    assert hash1 != hash2
    # But both verify successfully
    assert verify_password(password, hash1) is True
    assert verify_password(password, hash2) is True


@pytest.mark.parametrize("corrupt_hash", ["not-a-hash", "$argon2id$invalid", ""])
def test_tampered_hash_fails_safely(corrupt_hash: str) -> None:
    assert verify_password("some-password", corrupt_hash) is False


def test_fingerprint_deterministic_for_same_inputs() -> None:
    password = "admin-password"
    secret = "s" * 32
    fp1 = compute_credential_fingerprint(password, secret)
    fp2 = compute_credential_fingerprint(password, secret)
    assert fp1 == fp2
    assert len(fp1) == 64


def test_fingerprint_changes_when_password_changes() -> None:
    secret = "s" * 32
    fp1 = compute_credential_fingerprint("password_v1", secret)
    fp2 = compute_credential_fingerprint("password_v2", secret)
    assert fp1 != fp2


def test_fingerprint_changes_when_secret_changes() -> None:
    password = "same-password"
    fp1 = compute_credential_fingerprint(password, "s" * 32)
    fp2 = compute_credential_fingerprint(password, "t" * 32)
    assert fp1 != fp2
