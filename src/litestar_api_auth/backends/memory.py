"""In-memory storage backend for API keys.

This backend stores API keys in memory and is intended for testing and
development purposes only. All data is lost when the application restarts.
"""

from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from litestar_api_auth.backends.base import APIKeyBackend, APIKeyInfo

__all__ = ("MemoryBackend", "MemoryConfig")


@dataclass
class MemoryConfig:
    """Configuration for the in-memory backend.

    Attributes:
        name: Optional name for this backend instance (useful for debugging)
    """

    name: str = "memory"


class MemoryBackend(APIKeyBackend):
    """In-memory storage backend for API keys.

    This implementation stores all API keys in a Python dictionary and uses
    asyncio.Lock for thread-safe access. It's suitable for testing and
    development but should not be used in production as:

    - Data is not persisted across restarts
    - Data is not shared across multiple processes
    - Memory usage grows unbounded

    Example:
        ```python
        from litestar_api_auth.backends.memory import MemoryBackend, MemoryConfig

        backend = MemoryBackend(config=MemoryConfig(name="test"))

        # Create a key
        info = APIKeyInfo(
            key_id="123e4567-e89b-12d3-a456-426614174000",
            key_hash="abc123...",
            name="Test Key",
            scopes=["read"],
        )
        await backend.create(info.key_hash, info)

        # Retrieve it
        retrieved = await backend.get(info.key_hash)
        ```
    """

    def __init__(self, config: MemoryConfig | None = None) -> None:
        """Initialize the in-memory backend.

        Args:
            config: Configuration for the backend
        """
        self.config = config or MemoryConfig()
        self._store: dict[str, APIKeyInfo] = {}
        self._id_index: dict[str, str] = {}  # Maps key_id -> key_hash
        self._lock = asyncio.Lock()

    async def create(self, key_hash: str, info: APIKeyInfo) -> APIKeyInfo:
        """Create a new API key in memory.

        Args:
            key_hash: SHA-256 hash of the API key
            info: Metadata about the API key

        Returns:
            The created APIKeyInfo

        Raises:
            ValueError: If a key with the same hash or ID already exists
        """
        async with self._lock:
            if key_hash in self._store:
                msg = f"API key with hash {key_hash} already exists"
                raise ValueError(msg)

            if info.key_id in self._id_index:
                msg = f"API key with ID {info.key_id} already exists"
                raise ValueError(msg)

            # Set created_at if not provided
            if info.created_at is None:
                info = APIKeyInfo(
                    key_id=info.key_id,
                    key_hash=info.key_hash,
                    name=info.name,
                    scopes=info.scopes,
                    is_active=info.is_active,
                    created_at=datetime.now(timezone.utc),
                    expires_at=info.expires_at,
                    last_used_at=info.last_used_at,
                    metadata=info.metadata,
                )

            # Store deep copy to prevent external mutations
            self._store[key_hash] = deepcopy(info)
            self._id_index[info.key_id] = key_hash

            return deepcopy(info)

    async def get(self, key_hash: str) -> APIKeyInfo | None:
        """Retrieve an API key by its hash.

        Args:
            key_hash: SHA-256 hash of the API key

        Returns:
            The APIKeyInfo if found, None otherwise
        """
        async with self._lock:
            info = self._store.get(key_hash)
            return deepcopy(info) if info else None

    async def get_by_id(self, key_id: str) -> APIKeyInfo | None:
        """Retrieve an API key by its unique ID.

        Args:
            key_id: Unique identifier (UUID) of the key

        Returns:
            The APIKeyInfo if found, None otherwise
        """
        async with self._lock:
            key_hash = self._id_index.get(key_id)
            if not key_hash:
                return None

            info = self._store.get(key_hash)
            return deepcopy(info) if info else None

    async def update(self, key_hash: str, **updates: Any) -> APIKeyInfo | None:
        """Update an API key's metadata.

        Args:
            key_hash: SHA-256 hash of the API key
            **updates: Fields to update (name, scopes, is_active, etc.)

        Returns:
            The updated APIKeyInfo if found, None otherwise
        """
        async with self._lock:
            info = self._store.get(key_hash)
            if not info:
                return None

            # Create updated info with new values
            updated_info = APIKeyInfo(
                key_id=info.key_id,
                key_hash=info.key_hash,
                name=updates.get("name", info.name),  # type: ignore[arg-type]
                scopes=updates.get("scopes", info.scopes),  # type: ignore[arg-type]
                is_active=updates.get("is_active", info.is_active),  # type: ignore[arg-type]
                created_at=info.created_at,
                expires_at=updates.get("expires_at", info.expires_at),  # type: ignore[arg-type]
                last_used_at=updates.get("last_used_at", info.last_used_at),  # type: ignore[arg-type]
                metadata=updates.get("metadata", info.metadata),  # type: ignore[arg-type]
            )
            self._store[key_hash] = deepcopy(updated_info)

            return deepcopy(updated_info)

    async def delete(self, key_hash: str) -> bool:
        """Delete an API key from storage.

        Args:
            key_hash: SHA-256 hash of the API key

        Returns:
            True if the key was deleted, False if not found
        """
        async with self._lock:
            info = self._store.get(key_hash)
            if not info:
                return False

            del self._store[key_hash]
            del self._id_index[info.key_id]

            return True

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
            List of APIKeyInfo objects sorted by creation date (newest first)
        """
        async with self._lock:
            # Sort by created_at descending (newest first), then by key_id descending for stability
            # when timestamps are identical (common on Windows due to lower timer resolution)
            sorted_keys = sorted(
                self._store.values(),
                key=lambda k: (k.created_at or datetime.min.replace(tzinfo=timezone.utc), k.key_id),
                reverse=True,
            )

            # Apply pagination
            start = offset
            end = (offset + limit) if limit is not None else None
            paginated = sorted_keys[start:end]

            return [deepcopy(info) for info in paginated]

    async def revoke(self, key_hash: str) -> bool:
        """Revoke an API key (mark as inactive).

        Args:
            key_hash: SHA-256 hash of the API key

        Returns:
            True if the key was revoked, False if not found
        """
        result = await self.update(key_hash, is_active=False)
        return result is not None

    async def update_last_used(self, key_hash: str) -> None:
        """Update the last_used_at timestamp for a key.

        Args:
            key_hash: SHA-256 hash of the API key
        """
        await self.update(
            key_hash,
            last_used_at=datetime.now(timezone.utc),
        )

    async def close(self) -> None:
        """Close the backend and release any resources.

        For the in-memory backend, this clears the internal storage.
        """
        async with self._lock:
            self._store.clear()
            self._id_index.clear()

    def __repr__(self) -> str:
        """Return a string representation of the backend."""
        return f"MemoryBackend(name={self.config.name!r}, keys={len(self._store)})"
