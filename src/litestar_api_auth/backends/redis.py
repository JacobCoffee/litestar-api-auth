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

    @property
    def _all_keys_key(self) -> str:
        """Redis key for the set tracking all stored key hashes.

        Returns:
            Prefixed Redis key for the all_keys set.
        """
        return f"{self.config.key_prefix}all_keys"

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

        Uses SET with NX (only-if-not-exists) to prevent overwriting existing keys.
        Also creates a secondary index from key_id to key_hash for ID-based lookups,
        and adds the key_hash to the all_keys set for efficient listing.

        Args:
            key_hash: SHA-256 hash of the API key.
            info: Metadata about the API key.

        Returns:
            The created APIKeyInfo with any backend-generated fields populated.

        Raises:
            RuntimeError: If the Redis client is not configured.
            ValueError: If a key with the same hash or ID already exists.
        """
        if self._client is None:
            msg = "Redis client is not configured"
            raise RuntimeError(msg)

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

        redis_key = self._make_key(key_hash)
        id_key = self._make_id_key(info.key_id)
        serialized = self._serialize_info(info)

        # Use WATCH/MULTI for atomic uniqueness checks and writes across
        # both key_hash and key_id indexes.
        from redis.exceptions import WatchError

        max_retries = 5
        for _ in range(max_retries):
            pipeline = self._client.pipeline(transaction=True)
            try:
                await pipeline.watch(redis_key, id_key)
                hash_exists = await self._client.exists(redis_key)
                if hash_exists:
                    msg = f"API key with hash {key_hash} already exists"
                    raise ValueError(msg)

                id_exists = await self._client.exists(id_key)
                if id_exists:
                    msg = f"API key with ID {info.key_id} already exists"
                    raise ValueError(msg)

                pipeline.multi()
                pipeline.set(redis_key, serialized)
                pipeline.set(id_key, key_hash)
                pipeline.sadd(self._all_keys_key, key_hash)
                if self.config.ttl is not None:
                    pipeline.expire(redis_key, self.config.ttl)
                    pipeline.expire(id_key, self.config.ttl)
                await pipeline.execute()
                break
            except WatchError:
                continue
            finally:
                await pipeline.reset()
        else:
            msg = "Failed to create API key due to concurrent writes"
            raise RuntimeError(msg)

        return info

    async def get(self, key_hash: str) -> APIKeyInfo | None:
        """Retrieve an API key by its hash.

        Args:
            key_hash: SHA-256 hash of the API key.

        Returns:
            The APIKeyInfo if found, None otherwise.

        Raises:
            RuntimeError: If the Redis client is not configured.
        """
        if self._client is None:
            msg = "Redis client is not configured"
            raise RuntimeError(msg)

        redis_key = self._make_key(key_hash)
        data = await self._client.get(redis_key)
        if data is None:
            return None

        return self._deserialize_info(data if isinstance(data, str) else data.decode())

    async def get_by_id(self, key_id: str) -> APIKeyInfo | None:
        """Retrieve an API key by its unique ID.

        Uses the secondary index (id -> hash) to resolve the key_hash,
        then fetches the full APIKeyInfo from the primary hash key.

        Args:
            key_id: Unique identifier (UUID) of the key.

        Returns:
            The APIKeyInfo if found, None otherwise.

        Raises:
            RuntimeError: If the Redis client is not configured.
        """
        if self._client is None:
            msg = "Redis client is not configured"
            raise RuntimeError(msg)

        id_key = self._make_id_key(key_id)
        key_hash_raw = await self._client.get(id_key)
        if key_hash_raw is None:
            return None

        key_hash = key_hash_raw if isinstance(key_hash_raw, str) else key_hash_raw.decode()
        return await self.get(key_hash)

    async def update(self, key_hash: str, **updates: Any) -> APIKeyInfo | None:
        """Update an API key's metadata.

        Fetches the existing key, merges the provided updates, and writes
        the updated record back to Redis.

        Args:
            key_hash: SHA-256 hash of the API key.
            **updates: Fields to update (name, scopes, is_active, etc.).

        Returns:
            The updated APIKeyInfo if found, None otherwise.

        Raises:
            RuntimeError: If the Redis client is not configured.
        """
        if self._client is None:
            msg = "Redis client is not configured"
            raise RuntimeError(msg)

        info = await self.get(key_hash)
        if info is None:
            return None

        # Create updated info with new values, mirroring the memory backend pattern
        updated_info = APIKeyInfo(
            key_id=info.key_id,
            key_hash=info.key_hash,
            name=updates.get("name", info.name),
            scopes=updates.get("scopes", info.scopes),
            is_active=updates.get("is_active", info.is_active),
            created_at=info.created_at,
            expires_at=updates.get("expires_at", info.expires_at),
            last_used_at=updates.get("last_used_at", info.last_used_at),
            metadata=updates.get("metadata", info.metadata),
        )

        redis_key = self._make_key(key_hash)
        serialized = self._serialize_info(updated_info)
        await self._client.set(redis_key, serialized)

        # Re-apply TTL if configured (SET overwrites TTL)
        if self.config.ttl is not None:
            await self._client.expire(redis_key, self.config.ttl)
            await self._client.expire(self._make_id_key(info.key_id), self.config.ttl)

        return updated_info

    async def delete(self, key_hash: str) -> bool:
        """Delete an API key from Redis.

        Removes the primary hash key, the secondary ID index key, and
        the entry from the all_keys set.

        Args:
            key_hash: SHA-256 hash of the API key.

        Returns:
            True if the key was deleted, False if not found.

        Raises:
            RuntimeError: If the Redis client is not configured.
        """
        if self._client is None:
            msg = "Redis client is not configured"
            raise RuntimeError(msg)

        # First fetch the info so we can clean up the ID index
        info = await self.get(key_hash)
        if info is None:
            return False

        redis_key = self._make_key(key_hash)
        id_key = self._make_id_key(info.key_id)

        # Delete the primary key, the ID index, and remove from the all_keys set
        await self._client.delete(redis_key, id_key)
        await self._client.srem(self._all_keys_key, key_hash)

        return True

    async def list(
        self,
        *,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[APIKeyInfo]:
        """List API keys with pagination.

        Retrieves all key hashes from the all_keys set, fetches each record,
        sorts by created_at descending (newest first) then by key_id descending
        for stable ordering, and applies offset/limit pagination.

        Args:
            limit: Maximum number of keys to return (None for all).
            offset: Number of keys to skip.

        Returns:
            List of APIKeyInfo objects sorted by creation date (newest first).

        Raises:
            RuntimeError: If the Redis client is not configured.
        """
        if self._client is None:
            msg = "Redis client is not configured"
            raise RuntimeError(msg)

        # Get all key hashes from the tracking set
        members = await self._client.smembers(self._all_keys_key)
        if not members:
            return []

        # Fetch all records using MGET for efficiency
        redis_keys = [self._make_key(m if isinstance(m, str) else m.decode()) for m in members]
        raw_values = await self._client.mget(redis_keys)

        # Deserialize non-None results, filtering out expired/deleted entries
        results: list[APIKeyInfo] = []
        stale_hashes: list[str] = []
        for member, raw in zip(members, raw_values, strict=False):
            if raw is None:
                # Key expired or was deleted outside of our API; clean up the set
                stale_hashes.append(member if isinstance(member, str) else member.decode())
                continue
            data = raw if isinstance(raw, str) else raw.decode()
            results.append(self._deserialize_info(data))

        # Clean up stale entries from the tracking set
        if stale_hashes:
            await self._client.srem(self._all_keys_key, *stale_hashes)

        # Sort by created_at descending (newest first), then by key_id descending for stability
        results.sort(
            key=lambda k: (k.created_at or datetime.min.replace(tzinfo=timezone.utc), k.key_id),
            reverse=True,
        )

        # Apply pagination
        start = offset
        end = (offset + limit) if limit is not None else None
        return results[start:end]

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
