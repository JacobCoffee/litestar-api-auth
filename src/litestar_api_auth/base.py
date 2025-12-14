"""Base backend protocol and abstract implementation."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Sequence

    from litestar_api_auth.types import APIKeyData, Scope

__all__ = ["APIKeyBackend", "BaseAPIKeyBackend"]


@runtime_checkable
class APIKeyBackend(Protocol):
    """Protocol for API key storage backends.

    All storage backends must implement this protocol to ensure
    consistent behavior across different storage providers (SQLAlchemy,
    Redis, in-memory, etc.).

    This protocol defines the core interface for API key CRUD operations
    and validation.
    """

    async def create(
        self,
        *,
        key_hash: str,
        prefix: str,
        owner_id: str,
        name: str,
        scopes: Sequence[Scope] | None = None,
        expires_at: datetime | None = None,
        metadata: dict[str, str] | None = None,
    ) -> APIKeyData:
        """Create a new API key record.

        Args:
            key_hash: The SHA-256 hash of the full API key.
            prefix: The visible prefix of the key (e.g., 'myapp_abc12').
            owner_id: The identifier of the key owner.
            name: Human-readable name for the key.
            scopes: Optional list of permission scopes.
            expires_at: Optional expiration datetime.
            metadata: Optional additional metadata.

        Returns:
            APIKeyData with the created key's metadata.

        Raises:
            BackendError: If the creation fails.
        """
        ...

    async def get_by_prefix(self, prefix: str) -> APIKeyData | None:
        """Retrieve an API key by its prefix.

        Args:
            prefix: The visible prefix of the key.

        Returns:
            APIKeyData if found, None otherwise.

        Raises:
            BackendError: If the lookup fails.
        """
        ...

    async def get_by_hash(self, key_hash: str) -> APIKeyData | None:
        """Retrieve an API key by its hash.

        Args:
            key_hash: The SHA-256 hash of the full API key.

        Returns:
            APIKeyData if found, None otherwise.

        Raises:
            BackendError: If the lookup fails.
        """
        ...

    async def validate(self, key_hash: str) -> APIKeyData | None:
        """Validate an API key and return its data if valid.

        This method should check:
        - Key exists
        - Key is not revoked
        - Key is not expired

        Args:
            key_hash: The SHA-256 hash of the full API key.

        Returns:
            APIKeyData if the key is valid, None otherwise.

        Raises:
            BackendError: If the validation fails.
        """
        ...

    async def update_last_used(self, prefix: str) -> None:
        """Update the last_used_at timestamp for a key.

        Args:
            prefix: The visible prefix of the key.

        Raises:
            BackendError: If the update fails.
        """
        ...

    async def revoke(self, prefix: str) -> bool:
        """Revoke an API key.

        Args:
            prefix: The visible prefix of the key to revoke.

        Returns:
            True if the key was revoked, False if not found.

        Raises:
            BackendError: If the revocation fails.
        """
        ...

    async def delete(self, prefix: str) -> bool:
        """Permanently delete an API key.

        Args:
            prefix: The visible prefix of the key to delete.

        Returns:
            True if the key was deleted, False if not found.

        Raises:
            BackendError: If the deletion fails.
        """
        ...

    async def list_by_owner(
        self,
        owner_id: str,
        *,
        include_revoked: bool = False,
    ) -> list[APIKeyData]:
        """List all API keys for an owner.

        Args:
            owner_id: The identifier of the key owner.
            include_revoked: Whether to include revoked keys.

        Returns:
            List of APIKeyData for the owner's keys.

        Raises:
            BackendError: If the listing fails.
        """
        ...

    async def close(self) -> None:
        """Close the backend and release resources.

        This method should be called when the backend is no longer needed.
        """
        ...


class BaseAPIKeyBackend(ABC):
    """Abstract base class providing common functionality for backends.

    Backends can inherit from this to get default implementations of
    convenience methods while only implementing core abstract operations.
    """

    @abstractmethod
    async def create(
        self,
        *,
        key_hash: str,
        prefix: str,
        owner_id: str,
        name: str,
        scopes: Sequence[Scope] | None = None,
        expires_at: datetime | None = None,
        metadata: dict[str, str] | None = None,
    ) -> APIKeyData:
        """Create a new API key record. Must be implemented by subclasses."""

    @abstractmethod
    async def get_by_prefix(self, prefix: str) -> APIKeyData | None:
        """Get key by prefix. Must be implemented by subclasses."""

    @abstractmethod
    async def get_by_hash(self, key_hash: str) -> APIKeyData | None:
        """Get key by hash. Must be implemented by subclasses."""

    @abstractmethod
    async def update_last_used(self, prefix: str) -> None:
        """Update last_used_at. Must be implemented by subclasses."""

    @abstractmethod
    async def revoke(self, prefix: str) -> bool:
        """Revoke a key. Must be implemented by subclasses."""

    @abstractmethod
    async def delete(self, prefix: str) -> bool:
        """Delete a key. Must be implemented by subclasses."""

    @abstractmethod
    async def list_by_owner(
        self,
        owner_id: str,
        *,
        include_revoked: bool = False,
    ) -> list[APIKeyData]:
        """List keys by owner. Must be implemented by subclasses."""

    async def validate(self, key_hash: str) -> APIKeyData | None:
        """Default implementation: get by hash and check validity.

        Args:
            key_hash: The SHA-256 hash of the full API key.

        Returns:
            APIKeyData if the key is valid, None otherwise.
        """
        key_data = await self.get_by_hash(key_hash)
        if key_data is None:
            return None
        if not key_data.is_valid:
            return None
        return key_data

    async def close(self) -> None:  # noqa: B027
        """Default implementation: no-op.

        Subclasses that manage resources should override this method.
        """
