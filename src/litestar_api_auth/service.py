"""API key generation and validation service.

This module provides secure API key generation, hashing, and verification
utilities using industry-standard cryptographic practices.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from litestar_api_auth.exceptions import InvalidAPIKeyError

__all__ = [
    "generate_api_key",
    "hash_api_key",
    "verify_api_key",
    "extract_key_id",
]


def generate_api_key(prefix: str = "pyorg_") -> tuple[str, str]:
    """Generate a new API key with secure random data.

    This function generates a cryptographically secure API key consisting of
    a prefix and base64url-encoded random bytes. The function returns both
    the raw key (to show to the user once) and the hashed key (to store).

    Args:
        prefix: The prefix to prepend to the key (default: "pyorg_").
                Should be alphanumeric and end with underscore for readability.

    Returns:
        A tuple of (raw_key, hashed_key):
            - raw_key: The complete API key to provide to the user (shown once).
            - hashed_key: SHA-256 hash of the raw key for secure storage.

    Example:
        >>> raw_key, hashed_key = generate_api_key(prefix="myapp_")
        >>> print(f"Raw key: {raw_key[:15]}...")  # Only show prefix for security
        Raw key: myapp_AbCdEfGh...
        >>> print(f"Hash length: {len(hashed_key)}")
        Hash length: 64

    Note:
        The raw key should only be displayed once at creation time.
        Only the hashed_key should be stored in the database.
        The raw key cannot be recovered from the hash.

    Security:
        - Uses secrets.token_bytes() for cryptographically secure randomness
        - Generates 32 bytes (256 bits) of random data
        - Uses base64url encoding (URL-safe, no padding)
        - Hashes with SHA-256 for secure storage
    """
    # Generate 32 bytes (256 bits) of cryptographically secure random data
    random_bytes = secrets.token_bytes(32)

    # Encode as base64url (URL-safe, no padding)
    encoded = base64.urlsafe_b64encode(random_bytes).decode("ascii").rstrip("=")

    # Create the complete API key
    raw_key = f"{prefix}{encoded}"

    # Hash the key for storage
    hashed_key = hash_api_key(raw_key)

    return raw_key, hashed_key


def hash_api_key(key: str) -> str:
    """Hash an API key using SHA-256.

    This function creates a SHA-256 hash of the provided API key for
    secure storage. The hash is deterministic and irreversible.

    Args:
        key: The raw API key to hash.

    Returns:
        Hexadecimal string representation of the SHA-256 hash.

    Example:
        >>> key_hash = hash_api_key("myapp_AbCdEfGh123456")
        >>> len(key_hash)
        64
        >>> key_hash == hash_api_key("myapp_AbCdEfGh123456")
        True

    Note:
        SHA-256 produces a 256-bit (32-byte) hash, represented as 64 hex characters.
        The same input will always produce the same hash (deterministic).

    Security:
        - Uses SHA-256 cryptographic hash function
        - Produces a 256-bit hash digest
        - One-way function (cannot reverse to get original key)
        - Collision-resistant
    """
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def verify_api_key(raw_key: str, hashed_key: str) -> bool:
    """Verify an API key against its stored hash.

    This function uses constant-time comparison to prevent timing attacks
    when verifying API keys against their stored hashes.

    Args:
        raw_key: The API key provided by the user.
        hashed_key: The stored hash to verify against.

    Returns:
        True if the raw_key hashes to the same value as hashed_key.

    Example:
        >>> raw, hashed = generate_api_key()
        >>> verify_api_key(raw, hashed)
        True
        >>> verify_api_key("wrong_key", hashed)
        False

    Security:
        - Uses hmac.compare_digest() for constant-time comparison
        - Prevents timing attacks that could leak information about the hash
        - Even if the key is wrong, comparison takes the same time
    """
    computed_hash = hash_api_key(raw_key)
    return hmac.compare_digest(computed_hash, hashed_key)


def extract_key_id(raw_key: str) -> str | None:
    """Extract a unique identifier from a prefixed API key.

    This function extracts the first 8 characters of the random portion
    of an API key to use as a short identifier. This can be useful for
    logging and user interfaces without exposing the full key.

    Args:
        raw_key: The complete API key with prefix.

    Returns:
        The first 8 characters of the key after the prefix, or None if
        the key format is invalid.

    Example:
        >>> raw_key = "pyorg_AbCdEfGh123456789012345678901234567890"
        >>> extract_key_id(raw_key)
        'AbCdEfGh'
        >>> extract_key_id("invalid")
        None

    Note:
        This assumes the prefix ends with an underscore. Keys without
        an underscore will return None.

        The key_id is not cryptographically significant - it's just a
        convenient short identifier for display purposes.

    Raises:
        InvalidAPIKeyError: If the key format is invalid or too short.
    """
    if "_" not in raw_key:
        return None

    # Split on the first underscore to separate prefix from key
    parts = raw_key.split("_", 1)
    if len(parts) != 2:
        return None

    key_portion = parts[1]

    # Return first 8 characters as the key ID
    if len(key_portion) < 8:
        raise InvalidAPIKeyError(
            reason="Key is too short",
            detail=f"Expected at least 8 characters after prefix, got {len(key_portion)}",
        )

    return key_portion[:8]
