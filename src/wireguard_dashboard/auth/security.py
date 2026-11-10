import hashlib
import hmac

import argon2
import argon2.exceptions

_hasher = argon2.PasswordHasher(type=argon2.Type.ID)


def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2id with a unique random salt."""
    return _hasher.hash(password)


def verify_password(plain_password: str, hash_string: str) -> bool:
    """Verify a plaintext password against an Argon2id hash safely.

    Returns False on password mismatch, malformed hash, or verification failure.
    """
    if not hash_string or not plain_password:
        return False
    try:
        return bool(_hasher.verify(hash_string, plain_password))
    except (argon2.exceptions.VerificationError, argon2.exceptions.InvalidHashError):
        return False


def compute_credential_fingerprint(credential: str, session_secret: str) -> str:
    """Derive a deterministic, server-secret-keyed cryptographic credential fingerprint.

    Uses HMAC-SHA256 keyed with session_secret.
    """
    return hmac.new(
        session_secret.encode("utf-8"),
        credential.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
