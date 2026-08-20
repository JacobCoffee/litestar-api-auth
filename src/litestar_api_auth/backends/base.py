"""Backend protocol for API key storage.

This module defines the protocol that all storage backends must implement,
following the pattern from litestar-storages.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

# ``APIKeyInfo`` used to be defined here as a second, near-duplicate struct
# alongside ``types.APIKeyInfo`` (this one carried ``key_hash``, that one
# carried ``prefix``), which meant backends/middleware/guards and the
# publicly documented type were different classes that only agreed by duck
# typing. There is now a single canonical struct in
# ``litestar_api_auth.types``; it is re-exported here so that
# ``from litestar_api_auth.backends.base import APIKeyInfo`` -- used by the
# bundled backends, the middleware, the guards, and any third-party backend
# written against this module -- keeps working unchanged.
from litestar_api_auth.types import APIKeyInfo

__all__ = ("APIKeyBackend", "APIKeyInfo")


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
