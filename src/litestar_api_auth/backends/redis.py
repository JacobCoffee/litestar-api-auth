"""Redis storage backend for API keys.

This backend stores API keys in Redis, suitable for distributed systems
and high-performance applications that require fast key lookups.

Note:
    This module requires the `redis` optional dependency:
    `pip install litestar-api-auth[redis]`
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from litestar_api_auth.backends.base import APIKeyInfo

if TYPE_CHECKING:
    from redis.asyncio import Redis

__all__ = ("RedisBackend", "RedisConfig")


@dataclass
class RedisConfig:
    """Configuration for the Redis backend.

    Attributes:
        client: An async Redis client instance.
        key_prefix: Prefix for all Redis keys (for namespacing).
        ttl: Optional TTL in seconds for stored keys (None for no expiration).
    """

    client: Redis | None = None
    key_prefix: str = "api_key:"
    ttl: int | None = None


class RedisBackend:
    """Redis storage backend for API keys.

    This implementation stores API keys in Redis using hashes for efficient
    storage and retrieval. It's suitable for distributed systems where:

    - Fast key lookups are required
    - Multiple application instances share the same key store
    - High availability and scalability are important

    Features:
        - Async operations using redis-py's async client
        - Configurable key prefix for namespacing
        - Optional TTL for automatic key expiration
        - Efficient hash-based storage

    Example:
        ```python
        from redis.asyncio import Redis
        from litestar_api_auth.backends.redis import RedisBackend, RedisConfig

        redis_client = Redis.from_url("redis://localhost:6379")
        backend = RedisBackend(
            config=RedisConfig(
                client=redis_client,
                key_prefix="myapp:api_keys:",
            )
        )
        ```

    Note:
        This backend requires the `redis` optional dependency.
        Install with: `pip install litestar-api-auth[redis]`
    """

    def __init__(self, config: RedisConfig | None = None) -> None:
        """Initialize the Redis backend.

        Args:
            config: Configuration for the backend.

        Raises:
            ImportError: If redis-py is not installed.
        """
        try:
            from redis.asyncio import Redis
        except ImportError as exc:
            msg = "redis-py is required for RedisBackend. Install it with: pip install litestar-api-auth[redis]"
            raise ImportError(msg) from exc

        self.config = config or RedisConfig()
        self._client = self.config.client

    def _make_key(self, key_hash: str) -> str:
        """Create a Redis key from the API key hash.

        Args:
            key_hash: SHA-256 hash of the API key.

        Returns:
            Prefixed Redis key.
        """
        return f"{self.config.key_prefix}hash:{key_hash}"

    def _make_id_key(self, key_id: str) -> str:
        """Create a Redis key from the API key ID.

        Args:
            key_id: Unique identifier of the API key.

        Returns:
            Prefixed Redis key for ID lookup.
        """
        return f"{self.config.key_prefix}id:{key_id}"

    def _serialize_info(self, info: APIKeyInfo) -> str:
        """Serialize APIKeyInfo to JSON for storage.

        Args:
            info: The API key info to serialize.

        Returns:
            JSON string representation.
        """
        data = {
            "key_id": info.key_id,
            "key_hash": info.key_hash,
            "name": info.name,
            "scopes": info.scopes,
            "is_active": info.is_active,
            "created_at": info.created_at.isoformat() if info.created_at else None,
            "expires_at": info.expires_at.isoformat() if info.expires_at else None,
            "last_used_at": info.last_used_at.isoformat() if info.last_used_at else None,
            "metadata": info.metadata,
        }
        return json.dumps(data)

    def _deserialize_info(self, data: str) -> APIKeyInfo:
        """Deserialize JSON to APIKeyInfo.

        Args:
            data: JSON string to deserialize.

        Returns:
            Deserialized APIKeyInfo.
        """
        parsed = json.loads(data)
        return APIKeyInfo(
            key_id=parsed["key_id"],
            key_hash=parsed["key_hash"],
            name=parsed["name"],
            scopes=parsed["scopes"],
            is_active=parsed["is_active"],
            created_at=datetime.fromisoformat(parsed["created_at"]) if parsed.get("created_at") else None,
            expires_at=datetime.fromisoformat(parsed["expires_at"]) if parsed.get("expires_at") else None,
            last_used_at=datetime.fromisoformat(parsed["last_used_at"]) if parsed.get("last_used_at") else None,
            metadata=parsed.get("metadata"),
        )

    async def create(self, key_hash: str, info: APIKeyInfo) -> APIKeyInfo:
        """Create a new API key in Redis.

        Args:
            key_hash: SHA-256 hash of the API key.
            info: Metadata about the API key.

        Returns:
            The created APIKeyInfo with any backend-generated fields populated.

        Raises:
            ValueError: If a key with the same hash already exists.
        """
        if self._client is None:
            msg = "Redis client is not configured"
            raise RuntimeError(msg)

        # TODO: Implement Redis SET with NX (only if not exists)
        raise NotImplementedError("Redis backend is not yet implemented")

    async def get(self, key_hash: str) -> APIKeyInfo | None:
        """Retrieve an API key by its hash.

        Args:
            key_hash: SHA-256 hash of the API key.

        Returns:
            The APIKeyInfo if found, None otherwise.
        """
        if self._client is None:
            msg = "Redis client is not configured"
            raise RuntimeError(msg)

        # TODO: Implement Redis GET
        raise NotImplementedError("Redis backend is not yet implemented")

    async def get_by_id(self, key_id: str) -> APIKeyInfo | None:
        """Retrieve an API key by its unique ID.

        Args:
            key_id: Unique identifier (UUID) of the key.

        Returns:
            The APIKeyInfo if found, None otherwise.
        """
        if self._client is None:
            msg = "Redis client is not configured"
            raise RuntimeError(msg)

        # TODO: Implement ID lookup via secondary index
        raise NotImplementedError("Redis backend is not yet implemented")

    async def update(self, key_hash: str, **updates: Any) -> APIKeyInfo | None:
        """Update an API key's metadata.

        Args:
            key_hash: SHA-256 hash of the API key.
            **updates: Fields to update (name, scopes, is_active, etc.).

        Returns:
            The updated APIKeyInfo if found, None otherwise.
        """
        if self._client is None:
            msg = "Redis client is not configured"
            raise RuntimeError(msg)

        # TODO: Implement Redis GET + SET
        raise NotImplementedError("Redis backend is not yet implemented")

    async def delete(self, key_hash: str) -> bool:
        """Delete an API key from Redis.

        Args:
            key_hash: SHA-256 hash of the API key.

        Returns:
            True if the key was deleted, False if not found.
        """
        if self._client is None:
            msg = "Redis client is not configured"
            raise RuntimeError(msg)

        # TODO: Implement Redis DEL
        raise NotImplementedError("Redis backend is not yet implemented")

    async def list(
        self,
        *,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[APIKeyInfo]:
        """List API keys with pagination.

        Args:
            limit: Maximum number of keys to return (None for all).
            offset: Number of keys to skip.

        Returns:
            List of APIKeyInfo objects.

        Note:
            Redis does not natively support sorted pagination efficiently.
            This implementation uses SCAN which may not guarantee order.
        """
        if self._client is None:
            msg = "Redis client is not configured"
            raise RuntimeError(msg)

        # TODO: Implement using SCAN + pagination
        raise NotImplementedError("Redis backend is not yet implemented")

    async def revoke(self, key_hash: str) -> bool:
        """Revoke an API key (mark as inactive).

        Args:
            key_hash: SHA-256 hash of the API key.

        Returns:
            True if the key was revoked, False if not found.
        """
        result = await self.update(key_hash, is_active=False)
        return result is not None

    async def update_last_used(self, key_hash: str) -> None:
        """Update the last_used_at timestamp for a key.

        Args:
            key_hash: SHA-256 hash of the API key.
        """
        await self.update(key_hash, last_used_at=datetime.now(timezone.utc))

    async def close(self) -> None:
        """Close the backend and release Redis connections.

        Closes the Redis client connection pool.
        """
        if self._client is not None:
            await self._client.aclose()

    def __repr__(self) -> str:
        """Return a string representation of the backend."""
        return f"RedisBackend(prefix={self.config.key_prefix!r})"
