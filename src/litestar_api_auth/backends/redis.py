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
            This is a hard cutoff measured from creation, not a sliding
            inactivity timeout: metadata updates (including update_last_used())
            preserve the existing TTL via SET ... KEEPTTL rather than
            extending it. KEEPTTL requires Redis server 6.0+ -- older servers
            will reject the command.
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

        if info.key_hash != key_hash:
            # The record must be retrievable by the same hash it is stored
            # under: get_by_id() returns info.key_hash verbatim, and callers
            # (e.g. revoke/delete) use that value to look the record back
            # up. A mismatch here would create a key that authenticates via
            # key_hash but can never be revoked or deleted through
            # info.key_hash.
            msg = "key_hash argument does not match info.key_hash"
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

        redis_key = self._make_key(key_hash)
        id_key = self._make_id_key(info.key_id)
        serialized = self._serialize_info(info)

        # Use WATCH/MULTI for atomic uniqueness checks and writes across
        # both key_hash and key_id indexes.
        from redis.exceptions import ResponseError, WatchError

        max_retries = 5
        for _ in range(max_retries):
            pipeline = self._client.pipeline(transaction=True)
            try:
                await pipeline.watch(redis_key, id_key)
                hash_exists = await self._client.exists(redis_key)
                if hash_exists:
                    # Do not interpolate key_hash into the message: it's the exact
                    # stored verifier used for backend lookups, and this
                    # exception can surface in debug-mode responses and logs.
                    msg = "API key with this hash already exists"
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
            except ResponseError:
                # redis-py annotates a pipeline ResponseError with the full
                # failed command (see Pipeline.annotate_exception), which for
                # the SET/SADD calls above embeds redis_key/key_hash -- the
                # exact stored verifier -- directly in exception.args. Raise a
                # sanitized RuntimeError instead of re-raising it, with `from
                # None` so the annotated original (and the key_hash inside it)
                # doesn't surface via __context__ in debug-mode responses,
                # logs, or error reporters.
                msg = "Failed to create API key due to a Redis error"
                raise RuntimeError(msg) from None
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
        info = await self.get(key_hash)

        # These two reads are not atomic: between resolving key_hash from
        # the id index and fetching the record at that hash, the hash key
        # could have been deleted and recreated (via a direct create() call
        # bound to a different key_id) for an unrelated key. Verify the
        # record we got back actually claims this key_id before returning
        # it, so a caller never attributes someone else's record to the
        # requested id.
        if info is not None and info.key_id != key_id:
            return None

        return info

    async def update(self, key_hash: str, **updates: Any) -> APIKeyInfo | None:
        """Update an API key's metadata.

        Fetches the existing key, merges the provided updates, and writes
        the updated record back to Redis.

        Uses WATCH/MULTI so the read-modify-write is atomic: if another
        client (e.g. a concurrent revoke, delete, or update_last_used call)
        touches the record between our read and write, the transaction
        aborts and we retry against the fresh value instead of blindly
        overwriting it with a stale copy.

        Args:
            key_hash: SHA-256 hash of the API key.
            **updates: Fields to update (name, scopes, is_active, etc.).

        Returns:
            The updated APIKeyInfo if found, None otherwise.

        Raises:
            RuntimeError: If the Redis client is not configured, or if the
                update could not be applied due to persistent concurrent writes.
        """
        if self._client is None:
            msg = "Redis client is not configured"
            raise RuntimeError(msg)

        redis_key = self._make_key(key_hash)

        # Use WATCH/MULTI so a concurrent writer (revoke, delete, another
        # update) invalidates our transaction rather than being clobbered
        # by a stale read-modify-write.
        from redis.exceptions import ResponseError, WatchError

        max_retries = 5
        for _ in range(max_retries):
            pipeline = self._client.pipeline(transaction=True)
            try:
                await pipeline.watch(redis_key)
                # Read through the pipeline (not self._client) so the GET runs on
                # the connection already reserved by WATCH, instead of checking
                # out a second connection from the pool for every call -- which
                # would otherwise double connection-pool pressure on this path,
                # since update_last_used() invokes update() on every authenticated request.
                data = await pipeline.get(redis_key)
                if data is None:
                    return None

                info = self._deserialize_info(data if isinstance(data, str) else data.decode())

                # last_used_at must never move backward. update_last_used()
                # captures datetime.now() before calling update(), so a call
                # that loses the WATCH race and retries here re-reads a
                # record that a concurrent, later-timestamped call may have
                # already written. Without this guard, the retried (stale)
                # timestamp would clobber the newer one on the retry's write.
                new_last_used_at = updates.get("last_used_at", info.last_used_at)
                if "last_used_at" in updates and info.last_used_at is not None and new_last_used_at is not None:
                    # Compare as UTC-aware regardless of whether either side
                    # carries tzinfo, mirroring the naive-as-UTC convention
                    # APIKeyInfo.is_expired already uses -- callers may store
                    # a naive last_used_at, and comparing it directly against
                    # update_last_used()'s aware value would raise TypeError.
                    existing = info.last_used_at
                    incoming = new_last_used_at
                    if existing.tzinfo is None:
                        existing = existing.replace(tzinfo=timezone.utc)
                    if incoming.tzinfo is None:
                        incoming = incoming.replace(tzinfo=timezone.utc)
                    if incoming < existing:
                        new_last_used_at = info.last_used_at

                # Create updated info with new values, mirroring the memory backend pattern
                updated_info = APIKeyInfo(
                    key_id=info.key_id,
                    key_hash=info.key_hash,
                    name=updates.get("name", info.name),
                    scopes=updates.get("scopes", info.scopes),
                    is_active=updates.get("is_active", info.is_active),
                    created_at=info.created_at,
                    expires_at=updates.get("expires_at", info.expires_at),
                    last_used_at=new_last_used_at,
                    metadata=updates.get("metadata", info.metadata),
                )
                serialized = self._serialize_info(updated_info)

                pipeline.multi()
                # keepttl preserves whatever TTL Redis already has on the key
                # instead of wiping it (plain SET clears TTL) or re-applying
                # the full configured TTL. Re-applying the full TTL here would
                # turn RedisConfig.ttl into a sliding inactivity timeout --
                # since update_last_used() calls update() on every
                # authenticated request, an actively used key would have its
                # expiry pushed back forever instead of expiring as a hard
                # cutoff measured from creation.
                # xx=True guards the narrow race where the key expires between
                # our watched GET and EXEC: without it, KEEPTTL on a key that
                # no longer exists would recreate it with no TTL at all (i.e.
                # a key that should have expired coming back permanently).
                pipeline.set(redis_key, serialized, keepttl=True, xx=True)
                results = await pipeline.execute()
                if not results[0]:
                    return None
                return updated_info
            except WatchError:
                continue
            except ResponseError:
                # redis-py annotates a pipeline ResponseError with the full
                # failed command (see Pipeline.annotate_exception), which for
                # the SET above embeds redis_key/key_hash -- the exact stored
                # verifier -- directly in exception.args. This is reachable
                # in practice: KEEPTTL requires Redis 6.0+, so every update()
                # (and update_last_used(), invoked on every authenticated
                # request) raises ResponseError here against an older server.
                # Raise a sanitized RuntimeError instead of re-raising it,
                # with `from None` so the annotated original (and the
                # key_hash inside it) doesn't surface via __context__ in
                # debug-mode responses, logs, or error reporters. RuntimeError
                # also matches what middleware.py's update_last_used() call
                # already treats as a best-effort failure to suppress.
                msg = "Failed to update API key due to a Redis error"
                raise RuntimeError(msg) from None
            finally:
                await pipeline.reset()

        msg = "Failed to update API key due to concurrent writes"
        raise RuntimeError(msg)

    async def delete(self, key_hash: str) -> bool:
        """Delete an API key from Redis.

        Removes the primary hash key, the secondary ID index key, and
        the entry from the all_keys set.

        Uses WATCH/MULTI, the same pattern as update(), so the read (to
        find the ID index), the deletes, and the tracking-set removal
        happen as one atomic transaction: a concurrent create() that
        re-creates this exact hash between our read and the transaction
        aborts our EXEC (WatchError) instead of having its SADD silently
        undone by our SREM -- which would otherwise leave a live, freshly
        (re)created key permanently missing from list() while it still
        authenticates via get().

        Args:
            key_hash: SHA-256 hash of the API key.

        Returns:
            True if the key was deleted, False if not found.

        Raises:
            RuntimeError: If the Redis client is not configured, or if the
                delete could not be applied due to persistent concurrent writes.
        """
        if self._client is None:
            msg = "Redis client is not configured"
            raise RuntimeError(msg)

        redis_key = self._make_key(key_hash)

        from redis.exceptions import ResponseError, WatchError

        max_retries = 5
        for _ in range(max_retries):
            pipeline = self._client.pipeline(transaction=True)
            try:
                await pipeline.watch(redis_key)
                # Read through the pipeline (not self._client) so this
                # runs on the connection already reserved by WATCH.
                data = await pipeline.get(redis_key)
                if data is None:
                    return False

                info = self._deserialize_info(data if isinstance(data, str) else data.decode())
                id_key = self._make_id_key(info.key_id)

                pipeline.multi()
                # Delete the primary key, the ID index, and remove from the all_keys set
                pipeline.delete(redis_key, id_key)
                pipeline.srem(self._all_keys_key, key_hash)
                await pipeline.execute()
                return True
            except WatchError:
                continue
            except ResponseError:
                # redis-py annotates a pipeline ResponseError with the full
                # failed command (see Pipeline.annotate_exception), which for
                # the DELETE/SREM calls above embeds redis_key/id_key/key_hash
                # -- the exact stored verifier -- directly in exception.args.
                # Raise a sanitized RuntimeError instead of re-raising it,
                # with `from None` so the annotated original (and the
                # key_hash inside it) doesn't surface via __context__ in
                # debug-mode responses, logs, or error reporters, mirroring
                # create()'s and update()'s identical handling.
                msg = "Failed to delete API key due to a Redis error"
                raise RuntimeError(msg) from None
            finally:
                await pipeline.reset()

        msg = "Failed to delete API key due to concurrent writes"
        raise RuntimeError(msg)

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

        # Clean up stale entries from the tracking set. A blind SREM here
        # would race a concurrent create() re-creating the same hash: if
        # create()'s SADD (done atomically with its SET) lands between our
        # MGET above and this cleanup, an unconditional SREM would strip the
        # tracking entry for a key that is live again -- making it invisible
        # to list() for the rest of its life even though it still
        # authenticates via get(). Use WATCH/MULTI, the same pattern as
        # update(), to re-check existence at the moment of removal and skip
        # the SREM if the key came back.
        if stale_hashes:
            from redis.exceptions import ResponseError, WatchError

            for stale_hash in stale_hashes:
                redis_key = self._make_key(stale_hash)
                pipeline = self._client.pipeline(transaction=True)
                try:
                    await pipeline.watch(redis_key)
                    # Read through the pipeline (not self._client) so this
                    # re-check runs on the connection already reserved by
                    # WATCH instead of checking out a second one.
                    if await pipeline.get(redis_key) is not None:
                        # Recreated since our MGET; leave it tracked.
                        continue
                    pipeline.multi()
                    pipeline.srem(self._all_keys_key, stale_hash)
                    await pipeline.execute()
                except WatchError:
                    # Key changed concurrently between WATCH and EXEC;
                    # leave the tracking entry alone rather than risk
                    # removing a live key.
                    continue
                except ResponseError:
                    # redis-py annotates a pipeline ResponseError with the
                    # full failed command (see Pipeline.annotate_exception),
                    # which for the SREM call above embeds stale_hash directly
                    # in exception.args. This cleanup is best-effort (list()
                    # has already computed its results), so swallow it exactly
                    # like WatchError -- leaving the tracking entry alone --
                    # rather than letting a hash-bearing exception escape
                    # list() entirely over a single stale entry.
                    continue
                finally:
                    await pipeline.reset()

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
