"""Backend protocol for API key storage.

This module defines the protocol that all storage backends must implement,
following the pattern from litestar-storages.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Protocol, runtime_checkable

import msgspec

__all__ = ("APIKeyBackend", "APIKeyInfo")


class APIKeyInfo(msgspec.Struct):
    """Information about an API key stored in the backend.

    This is a lightweight data structure containing only the metadata
    about an API key, not the raw key itself.

    Attributes:
        key_id: Unique identifier for the key (UUID)
        key_hash: Hashed version of the API key
        name: Human-readable name for the key
        scopes: List of permission scopes (e.g., ["read", "write"])
        is_active: Whether the key is currently active
        created_at: When the key was created
        expires_at: When the key expires (None if no expiration)
        last_used_at: When the key was last used (None if never used)
        metadata: Additional custom metadata as key-value pairs
    """

    key_id: str
    key_hash: str
    name: str
    scopes: list[str]
    is_active: bool = True
    created_at: datetime | None = None
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    metadata: dict[str, Any] | None = None

    @property
    def is_expired(self) -> bool:
        """Check if the API key has expired.

        Returns:
            True if the key has an expiration date that has passed, False otherwise.
        """
        if self.expires_at is None:
            return False
        now = datetime.now(timezone.utc)
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return now > expires

    @property
    def has_valid_types(self) -> bool:
        """Whether ``is_active`` and ``scopes`` actually match the types this class declares.

        ``msgspec.Struct`` does not enforce field types when a struct is built
        directly in Python (only decoding via ``msgspec.json.decode``/
        ``msgspec.convert`` does), so a custom/legacy backend, migrated or
        corrupted serialized data, or direct programmatic seeding can produce
        a record whose ``is_active`` is a truthy non-``bool`` (e.g. the string
        ``"false"``) or whose ``scopes`` is a ``str`` instead of a
        ``list[str]``. Both would silently fail open for a caller that trusts
        this record without checking this property first: ``not "false"`` is
        ``False``, so the "is the key active" checks in
        ``APIKeyMiddleware._validate_api_key`` and ``guards.get_api_key_info``
        would both pass, and ``"admin" in "api_keys:admin"`` is a substring
        match rather than a membership check, so ``has_scope``/``has_scopes``
        would too.

        Returns:
            True if ``is_active`` is actually a ``bool`` and ``scopes`` is
            actually a ``list`` of ``str``, False otherwise.
        """
        return (
            isinstance(self.is_active, bool)
            and isinstance(self.scopes, list)
            and all(isinstance(s, str) for s in self.scopes)
        )

    def has_scope(self, scope: str) -> bool:
        """Check if the API key has a specific scope.

        Args:
            scope: The scope to check for.

        Returns:
            True if the key has the scope, False otherwise.
        """
        return scope in self.scopes

    def has_scopes(self, scopes: list[str], *, requirement: str = "all") -> bool:
        """Check if the API key has the required scopes.

        Args:
            scopes: List of scopes to check for.
            requirement: Either "all" (must have all scopes) or "any" (must have at least one).

        Returns:
            True if the scope requirement is satisfied, False otherwise.

        Raises:
            ValueError: If requirement is not "all" or "any".
        """
        if requirement == "all":
            return all(s in self.scopes for s in scopes)
        if requirement == "any":
            return any(s in self.scopes for s in scopes)
        msg = f"Invalid requirement: {requirement!r}. Must be 'all' or 'any'"
        raise ValueError(msg)


@runtime_checkable
class APIKeyBackend(Protocol):
    """Protocol defining the interface for API key storage backends.

    All storage backends (SQLAlchemy, Redis, in-memory, etc.) must implement
    this protocol to be compatible with the API auth system.

    This follows the same pattern as litestar-storages, using Protocol with
    @runtime_checkable for structural typing and duck typing support.
    """

    async def create(self, key_hash: str, info: APIKeyInfo) -> APIKeyInfo:
        """Create a new API key in storage.

        Args:
            key_hash: SHA-256 hash of the API key
            info: Metadata about the API key

        Returns:
            The created APIKeyInfo with any backend-generated fields populated

        Raises:
            Exception: If a key with the same hash or ID already exists
        """
        ...

    async def get(self, key_hash: str) -> APIKeyInfo | None:
        """Retrieve an API key by its hash.

        Args:
            key_hash: SHA-256 hash of the API key

        Returns:
            The APIKeyInfo if found, None otherwise
        """
        ...

    async def get_by_id(self, key_id: str) -> APIKeyInfo | None:
        """Retrieve an API key by its unique ID.

        Args:
            key_id: Unique identifier (UUID) of the key

        Returns:
            The APIKeyInfo if found, None otherwise
        """
        ...

    async def update(self, key_hash: str, **updates: Any) -> APIKeyInfo | None:
        """Update an API key's metadata.

        Args:
            key_hash: SHA-256 hash of the API key
            **updates: Fields to update (name, scopes, is_active, etc.)

        Returns:
            The updated APIKeyInfo if found, None otherwise
        """
        ...

    async def delete(self, key_hash: str) -> bool:
        """Delete an API key from storage.

        Args:
            key_hash: SHA-256 hash of the API key

        Returns:
            True if the key was deleted, False if not found
        """
        ...

    async def list(
        self,
        *,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[APIKeyInfo]:
        """List API keys with pagination.

        Args:
            limit: Maximum number of keys to return (None for all)
            offset: Number of keys to skip

        Returns:
            List of APIKeyInfo objects
        """
        ...

    async def revoke(self, key_hash: str) -> bool:
        """Revoke an API key (mark as inactive).

        This is a soft delete that sets is_active to False rather than
        removing the key from storage.

        Args:
            key_hash: SHA-256 hash of the API key

        Returns:
            True if the key was revoked, False if not found
        """
        ...

    async def update_last_used(self, key_hash: str) -> APIKeyInfo | None:
        """Update the last_used_at timestamp for a key.

        This is called automatically when a key is used for authentication.

        Returns the freshly written record when the key still exists, so a
        caller (see ``APIKeyMiddleware.__call__``) can detect a revoke() or
        an expiry shortened by an in-place update() that landed in the
        narrow window between an earlier ``get()`` and this call, closing
        that race for backends that support it. Returning ``None`` is
        ambiguous by design -- it covers both "nothing further to report"
        (e.g. a backend predating this return value) *and* "the record was
        deleted concurrently" -- so callers must not treat a ``None`` return
        as proof of deletion; a concurrent delete() in that same window is
        not distinguishable this way and remains uncaught.

        Args:
            key_hash: SHA-256 hash of the API key

        Returns:
            The updated APIKeyInfo if the backend can provide one, None otherwise.
        """
        ...

    async def close(self) -> None:
        """Close the backend and release any resources.

        This should be called when shutting down the application to ensure
        proper cleanup of database connections, Redis clients, etc.
        """
        ...
