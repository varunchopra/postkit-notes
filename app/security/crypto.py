"""Cryptographic utilities for authentication."""

import hashlib
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_ph = PasswordHasher()

# Pre-computed hash for timing-attack prevention on login
# Used when user doesn't exist to ensure constant-time response
DUMMY_HASH = _ph.hash("dummy-password-for-timing-attack-prevention")

# Token prefixes - makes tokens identifiable (like GitHub's gh_, Stripe's sk_)
API_KEY_PREFIX = "pk_"
REFRESH_TOKEN_PREFIX = "pk_ref_"


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        _ph.verify(stored_hash, password)
        return True
    except VerifyMismatchError:
        return False


def create_token(prefix: str = "") -> tuple[str, str]:
    """Returns (raw_token, hashed_token) - store hash, give raw to user."""
    raw = prefix + secrets.token_urlsafe(32)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
