"""API key generation and validation service.

This module provides secure API key generation, hashing, and verification
utilities using industry-standard cryptographic practices.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from litestar_api_auth.exceptions import InvalidAPIKeyError
from litestar_api_auth.types import APIKeyInfo

if TYPE_CHECKING:
    from litestar_api_auth.backends.base import APIKeyBackend

__all__ = [
    "generate_api_key",
    "hash_api_key",
    "mint_api_key",
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
        >>> prefix = "myapp_"
        >>> raw_key, hashed_key = generate_api_key(prefix=prefix)
        >>> print(f"Raw key: {prefix}...")  # Show only the known prefix, never the secret
        Raw key: myapp_...
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


async def mint_api_key(
    backend: APIKeyBackend,
    *,
    name: str,
    scopes: list[str],
    prefix: str,
    expires_at: datetime | None = None,
    metadata: dict[str, Any] | None = None,
) -> tuple[str, APIKeyInfo]:
    """Generate an API key, persist it to a backend, and return both halves.

    This is the one call a "mint an API key" flow needs: it generates the key
    with :func:`generate_api_key`, builds the :class:`APIKeyInfo` record
    (including a fresh ``key_id``), writes it through ``backend.create()``,
    and hands back the plaintext key together with the stored record. Host
    applications should not assemble the hash or the struct by hand -- doing
    so is how a caller ends up hashing with a different scheme than the
    middleware verifies against.

    Args:
        backend: The storage backend to persist the key in.
        name: Human-readable name for the key.
        scopes: Permission scopes to grant the key.
        prefix: Prefix for the generated key (e.g. ``"pyorg_"``). Typically
            ``APIAuthConfig.key_prefix``.
        expires_at: Optional expiration timestamp. None means no expiration.
        metadata: Optional additional metadata to store with the key.

    Returns:
        A tuple of ``(plaintext_key, info)``:
            - ``plaintext_key``: the full key, to be shown to the user exactly
              once. It cannot be recovered afterwards.
            - ``info``: the record as returned by the backend (its ``key_hash``
              is the stored verifier, so treat it as sensitive -- do not return
              it to an HTTP client without redacting that field).

    Example:
        >>> plaintext, info = await mint_api_key(
        ...     backend,
        ...     name="Reporting job",
        ...     scopes=["reports:read"],
        ...     prefix="pycon_",
        ... )

    Security:
        The plaintext key is only ever returned here; only ``info.key_hash``
        is persisted. If ``backend.create()`` raises, the plaintext key and
        its hash are scrubbed from this frame first, so a monitoring tool
        that captures frame locals on unhandled exceptions (e.g. Sentry's
        ``include_local_variables``) cannot recover them from the traceback --
        mirroring ``APIKeyController.create_api_key``.
    """
    plaintext_key, key_hash = generate_api_key(prefix)

    info = APIKeyInfo(
        key_id=secrets.token_urlsafe(16),
        name=name,
        scopes=list(scopes),
        key_hash=key_hash,
        prefix=prefix,
        is_active=True,
        created_at=datetime.now(timezone.utc),
        expires_at=expires_at,
        last_used_at=None,
        metadata=metadata,
    )

    try:
        created = await backend.create(key_hash, info)
    except BaseException:
        plaintext_key = key_hash = ""
        info = None  # type: ignore[assignment]
        raise

    # A backend is allowed to return its own record from create() (with
    # backend-generated fields populated); fall back to the record we built
    # if it returns nothing useful.
    if created is None:
        return plaintext_key, info

    # ``prefix`` is informational and the bundled persistent backends have no
    # column/field for it, so their returned record drops it. Restore it so
    # the caller always gets back the prefix it asked for, whichever backend
    # is in use.
    if created.prefix is None:
        created.prefix = info.prefix

    return plaintext_key, created


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

    This function derives a short identifier from a SHA-256 hash of the key
    (the same hash produced by :func:`hash_api_key`) rather than slicing the
    key's own characters, so the identifier is safe to log or display without
    exposing any of the key's secret material.

    Args:
        raw_key: The complete API key with prefix.

    Returns:
        The first 8 hex characters of the key's SHA-256 hash, or None if
        the key format is invalid.

    Example:
        >>> raw_key = "pyorg_AbCdEfGh123456789012345678901234567890"
        >>> extract_key_id(raw_key)
        '2c9359b5'
        >>> extract_key_id("invalid")
        None

    Note:
        This assumes the prefix ends with an underscore. Keys without
        an underscore will return None.

        The key_id is not cryptographically significant and is not
        guaranteed to be collision-free - it's a short, convenient
        identifier for display and log correlation, not a unique or
        secret value. Because it is hash-derived rather than a substring
        of the key, it never reveals any of the key's own characters,
        making it safe to log for the high-entropy keys produced by
        :func:`generate_api_key`.

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

    if len(key_portion) < 8:
        raise InvalidAPIKeyError(
            reason="Key is too short",
            detail=f"Expected at least 8 characters after prefix, got {len(key_portion)}",
        )

    # Derive the ID from a hash of the full key instead of slicing the raw
    # secret, so the identifier never exposes actual key material.
    return hash_api_key(raw_key)[:8]
