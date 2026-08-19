"""Tests for Redis backend storage implementation.

This module tests the Redis storage backend for API key management,
including CRUD operations, pagination, serialization round-trips,
and the full key lifecycle.  Uses fakeredis for a hermetic test
environment that requires no running Redis server.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from typing import Any

import fakeredis.aioredis
import pytest

from litestar_api_auth.backends.base import APIKeyInfo
from litestar_api_auth.backends.redis import RedisBackend, RedisConfig
from litestar_api_auth.service import generate_api_key


@pytest.fixture
async def redis_backend():
    """Provide a fresh Redis backend backed by a fake async Redis client.

    Flushes the client after the test to ensure complete isolation.

    Yields:
        A fully initialised RedisBackend instance.
    """
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    config = RedisConfig(client=client, key_prefix="test_api_key:")
    backend = RedisBackend(config=config)
    yield backend
    await client.flushall()
    await client.aclose()


class TestRedisBackendCreate:
    """Tests for creating API keys in the Redis backend."""

    async def test_create(self, redis_backend: RedisBackend) -> None:
        """Test creating a new API key in Redis backend."""
        _raw_key, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read", "write"],
            is_active=True,
        )

        result = await redis_backend.create(hashed_key, key_info)

        assert result.key_id == "test-123"
        assert result.key_hash == hashed_key
        assert result.name == "Test Key"
        assert result.scopes == ["read", "write"]
        assert result.is_active is True
        assert result.created_at is not None

    async def test_create_duplicate_hash(self, redis_backend: RedisBackend) -> None:
        """Test that creating a key with duplicate hash raises error."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )
        await redis_backend.create(hashed_key, key_info)

        duplicate_info = APIKeyInfo(
            key_id="test-456",
            key_hash=hashed_key,
            name="Duplicate Key",
            scopes=["write"],
        )

        with pytest.raises(ValueError, match="already exists"):
            await redis_backend.create(hashed_key, duplicate_info)

    async def test_create_duplicate_hash_error_does_not_leak_hash(self, redis_backend: RedisBackend) -> None:
        """Duplicate-hash error must not embed the stored key_hash verifier.

        The hash is the exact value backends use for lookups; leaking it in
        an exception message (surfaced via debug-mode responses or logs)
        would expose the stored credential unnecessarily.
        """
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )
        await redis_backend.create(hashed_key, key_info)

        duplicate_info = APIKeyInfo(
            key_id="test-456",
            key_hash=hashed_key,
            name="Duplicate Key",
            scopes=["write"],
        )

        with pytest.raises(ValueError) as exc_info:
            await redis_backend.create(hashed_key, duplicate_info)

        assert hashed_key not in str(exc_info.value)
        assert str(exc_info.value) == "API key with this hash already exists"

    async def test_create_pipeline_response_error_does_not_leak_hash(self, redis_backend: RedisBackend) -> None:
        """A Redis-level pipeline failure in create() must not embed key_hash either.

        redis-py annotates a failed pipelined command with its full argument
        list (see ``Pipeline.annotate_exception``), which for the SET/SADD
        calls in create()'s MULTI block includes the raw key_hash. This
        forces that exact failure -- by corrupting the all_keys tracking key
        to the wrong Redis type so the pipelined SADD errors server-side --
        without tripping the earlier hash_exists/id_exists checks, and
        asserts the resulting exception is sanitized like the duplicate-hash
        ValueError above.
        """
        _, hashed_key = generate_api_key("test_")

        # SADD against a string-typed key raises WRONGTYPE from Redis itself,
        # which redis-py surfaces as a ResponseError whose message embeds the
        # full pipelined command (including key_hash) unless sanitized.
        await redis_backend._client.set(redis_backend._all_keys_key, "not-a-set")

        info = APIKeyInfo(
            key_id="test-789",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )

        with pytest.raises(RuntimeError) as exc_info:
            await redis_backend.create(hashed_key, info)

        assert hashed_key not in str(exc_info.value)
        # `from None` suppresses the original ResponseError from traceback
        # rendering (matching the SQLAlchemy backend's identical convention)
        # even though CPython still tracks it on __context__ internally.
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__suppress_context__ is True

    async def test_create_duplicate_id(self, redis_backend: RedisBackend) -> None:
        """Test that creating a key with duplicate ID raises error."""
        _, hashed_key1 = generate_api_key("test_")
        _, hashed_key2 = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="duplicate-id",
            key_hash=hashed_key1,
            name="First Key",
            scopes=["read"],
        )
        await redis_backend.create(hashed_key1, key_info)

        duplicate_info = APIKeyInfo(
            key_id="duplicate-id",
            key_hash=hashed_key2,
            name="Second Key",
            scopes=["write"],
        )

        with pytest.raises(ValueError, match="already exists"):
            await redis_backend.create(hashed_key2, duplicate_info)

    async def test_create_rejects_mismatched_hash(self, redis_backend: RedisBackend) -> None:
        """create() must reject a key_hash argument that disagrees with info.key_hash.

        Regression test for a revocation-integrity bug: the record used to be
        stored under the ``key_hash`` argument while ``info.key_hash`` (a
        different value) was preserved inside it. The key would then
        authenticate via ``key_hash`` (used by get()/the auth middleware),
        but get_by_id() -- used by the management controller's revoke/delete
        endpoints -- would return a record whose key_hash pointed nowhere,
        making the key permanently unrevokable and undeletable through the API.
        """
        _, hashed_key = generate_api_key("test_")
        _, other_hashed_key = generate_api_key("test_")

        mismatched_info = APIKeyInfo(
            key_id="test-123",
            key_hash=other_hashed_key,  # Does not match the key_hash argument below
            name="Test Key",
            scopes=["read"],
        )

        with pytest.raises(ValueError, match="does not match"):
            await redis_backend.create(hashed_key, mismatched_info)

        # Neither hash should have been stored as a side effect of the
        # rejected create() call.
        assert await redis_backend.get(hashed_key) is None
        assert await redis_backend.get(other_hashed_key) is None
        assert await redis_backend.get_by_id("test-123") is None

    async def test_create_sets_created_at(self, redis_backend: RedisBackend) -> None:
        """Test that created_at is set if not provided."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
            created_at=None,
        )

        result = await redis_backend.create(hashed_key, key_info)

        assert result.created_at is not None
        now = datetime.now(timezone.utc)
        assert (now - result.created_at) < timedelta(minutes=1)

    async def test_create_with_metadata(self, redis_backend: RedisBackend) -> None:
        """Test creating a key with metadata."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-meta",
            key_hash=hashed_key,
            name="Meta Key",
            scopes=["read"],
            metadata={"owner": "admin@example.com", "env": "production"},
        )

        result = await redis_backend.create(hashed_key, key_info)

        assert result.metadata == {"owner": "admin@example.com", "env": "production"}

    async def test_create_with_expiry(self, redis_backend: RedisBackend) -> None:
        """Test creating a key with an expiration date."""
        _, hashed_key = generate_api_key("test_")
        expires = datetime.now(timezone.utc) + timedelta(days=30)

        key_info = APIKeyInfo(
            key_id="test-expiry",
            key_hash=hashed_key,
            name="Expiring Key",
            scopes=["read"],
            expires_at=expires,
        )

        result = await redis_backend.create(hashed_key, key_info)

        assert result.expires_at is not None


class TestRedisBackendGet:
    """Tests for retrieving API keys from the Redis backend."""

    async def test_get(self, redis_backend: RedisBackend) -> None:
        """Test retrieving an API key by hash."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )
        await redis_backend.create(hashed_key, key_info)

        result = await redis_backend.get(hashed_key)

        assert result is not None
        assert result.key_id == "test-123"
        assert result.name == "Test Key"
        assert result.scopes == ["read"]

    async def test_get_not_found(self, redis_backend: RedisBackend) -> None:
        """Test retrieving a non-existent key returns None."""
        result = await redis_backend.get("nonexistent_hash")

        assert result is None

    async def test_get_by_id(self, redis_backend: RedisBackend) -> None:
        """Test retrieving an API key by ID."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )
        await redis_backend.create(hashed_key, key_info)

        result = await redis_backend.get_by_id("test-123")

        assert result is not None
        assert result.key_hash == hashed_key
        assert result.name == "Test Key"

    async def test_get_by_id_not_found(self, redis_backend: RedisBackend) -> None:
        """Test retrieving by non-existent ID returns None."""
        result = await redis_backend.get_by_id("nonexistent-id")

        assert result is None

    async def test_get_by_id_rejects_aba_hash_reuse(self, redis_backend: RedisBackend) -> None:
        """Regression test for an ABA race between get_by_id()'s two reads.

        get_by_id() is not atomic: it resolves key_hash from the id index,
        then fetches the record at that hash as a second, separate read. If
        the hash key is deleted and recreated (bound to a different key_id)
        in the window between those two reads -- e.g. a caller deliberately
        reusing a hash -- the second read returns a record that belongs to
        someone else's id.

        This forces that exact interleaving: a concurrent delete()+create()
        recreates the same hash under a different key_id right after
        get_by_id()'s id-index read returns, but before its follow-up get()
        runs. Without the info.key_id verification, get_by_id() would
        return the replacement record and attribute it to the original id.
        """
        _, hashed_key = generate_api_key("test_")
        original_info = APIKeyInfo(
            key_id="aba-original-id",
            key_hash=hashed_key,
            name="Original Key",
            scopes=["read"],
            is_active=True,
        )
        await redis_backend.create(hashed_key, original_info)

        replacement_info = APIKeyInfo(
            key_id="aba-replacement-id",
            key_hash=hashed_key,
            name="Replacement Key",
            scopes=["write"],
            is_active=True,
        )

        client = redis_backend._client
        id_key = redis_backend._make_id_key("aba-original-id")
        original_get = client.get
        triggered = False

        async def racing_get(key: str, *args: Any, **kwargs: Any) -> Any:
            nonlocal triggered
            result = await original_get(key, *args, **kwargs)
            # Land the concurrent delete+recreate strictly after get_by_id()'s
            # id-index read has returned key_hash, but before its follow-up
            # get(key_hash) call runs.
            if key == id_key and not triggered:
                triggered = True
                await redis_backend.delete(hashed_key)
                await redis_backend.create(hashed_key, replacement_info)
            return result

        client.get = racing_get
        try:
            result = await redis_backend.get_by_id("aba-original-id")
        finally:
            client.get = original_get

        assert triggered
        # The hash now holds the replacement record (a different key_id).
        # get_by_id("aba-original-id") must not attribute it to the
        # original id -- it must report the original id as gone rather
        # than returning someone else's record.
        assert result is None
        # The replacement record is still correctly reachable by its own id.
        by_replacement_id = await redis_backend.get_by_id("aba-replacement-id")
        assert by_replacement_id is not None
        assert by_replacement_id.key_id == "aba-replacement-id"

    async def test_get_preserves_metadata(self, redis_backend: RedisBackend) -> None:
        """Test that metadata round-trips correctly through JSON serialization."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-meta-rt",
            key_hash=hashed_key,
            name="Meta Key",
            scopes=["admin:read", "admin:write"],
            metadata={"nested": {"deep": True}, "count": 42},
        )
        await redis_backend.create(hashed_key, key_info)

        result = await redis_backend.get(hashed_key)

        assert result is not None
        assert result.metadata == {"nested": {"deep": True}, "count": 42}
        assert result.scopes == ["admin:read", "admin:write"]


class TestRedisBackendUpdate:
    """Tests for updating API keys in the Redis backend."""

    async def test_update(self, redis_backend: RedisBackend) -> None:
        """Test updating an API key's metadata."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Original Name",
            scopes=["read"],
        )
        await redis_backend.create(hashed_key, key_info)

        result = await redis_backend.update(hashed_key, name="Updated Name", scopes=["read", "write"])

        assert result is not None
        assert result.name == "Updated Name"
        assert result.scopes == ["read", "write"]
        assert result.key_id == "test-123"

    async def test_update_not_found(self, redis_backend: RedisBackend) -> None:
        """Test updating a non-existent key returns None."""
        result = await redis_backend.update("nonexistent_hash", name="New Name")

        assert result is None

    async def test_update_partial(self, redis_backend: RedisBackend) -> None:
        """Test partial update of key metadata."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Original Name",
            scopes=["read", "write"],
            metadata={"key": "value"},
        )
        await redis_backend.create(hashed_key, key_info)

        result = await redis_backend.update(hashed_key, name="New Name")

        assert result is not None
        assert result.name == "New Name"
        assert result.scopes == ["read", "write"]
        assert result.metadata == {"key": "value"}

    async def test_update_is_active(self, redis_backend: RedisBackend) -> None:
        """Test updating the is_active flag."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
            is_active=True,
        )
        await redis_backend.create(hashed_key, key_info)

        result = await redis_backend.update(hashed_key, is_active=False)

        assert result is not None
        assert result.is_active is False

    async def test_update_persists(self, redis_backend: RedisBackend) -> None:
        """Test that update is persisted and retrievable."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Original Name",
            scopes=["read"],
        )
        await redis_backend.create(hashed_key, key_info)
        await redis_backend.update(hashed_key, name="Persisted Name")

        retrieved = await redis_backend.get(hashed_key)

        assert retrieved is not None
        assert retrieved.name == "Persisted Name"

    async def test_update_pipeline_response_error_does_not_leak_hash(self, redis_backend: RedisBackend) -> None:
        """A Redis-level pipeline failure in update() must not embed key_hash either.

        redis-py annotates a failed pipelined command with its full argument
        list (see ``Pipeline.annotate_exception``), which for update()'s
        ``SET ... KEEPTTL XX`` call includes the raw key_hash embedded in
        redis_key. This is a real, reachable failure mode: KEEPTTL requires
        Redis server 6.0+, so every update() call -- including
        update_last_used(), which the middleware invokes on every
        authenticated request -- raises exactly this ResponseError against
        an older server. Forces the pipeline's EXEC to fail with such an
        error and asserts update() sanitizes it the same way create() does,
        instead of letting the hash-bearing ResponseError escape (which the
        middleware's ``contextlib.suppress(RuntimeError)`` would not catch).
        """
        _, hashed_key = generate_api_key("test_")
        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )
        await redis_backend.create(hashed_key, key_info)

        client = redis_backend._client
        redis_key = redis_backend._make_key(hashed_key)
        original_pipeline_factory = client.pipeline

        def failing_pipeline_factory(*args: Any, **kwargs: Any) -> Any:
            pipeline = original_pipeline_factory(*args, **kwargs)

            async def failing_execute(*a: Any, **kw: Any) -> Any:
                from redis.exceptions import ResponseError

                # Mirrors redis-py's real annotation: the failed command and
                # its full arguments (including the raw key_hash) folded into
                # the exception message.
                msg = f"SET {redis_key} '<serialized>' KEEPTTL XX: ERR syntax error"
                raise ResponseError(msg)

            pipeline.execute = failing_execute
            return pipeline

        client.pipeline = failing_pipeline_factory
        try:
            with pytest.raises(RuntimeError) as exc_info:
                await redis_backend.update(hashed_key, name="Updated Name")
        finally:
            client.pipeline = original_pipeline_factory

        assert hashed_key not in str(exc_info.value)
        assert str(exc_info.value) == "Failed to update API key due to a Redis error"
        # `from None` suppresses the original ResponseError from traceback
        # rendering (matching create()'s identical convention) even though
        # CPython still tracks it on __context__ internally.
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__suppress_context__ is True


class TestRedisBackendDelete:
    """Tests for deleting API keys from the Redis backend."""

    async def test_delete(self, redis_backend: RedisBackend) -> None:
        """Test deleting an API key."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )
        await redis_backend.create(hashed_key, key_info)

        result = await redis_backend.delete(hashed_key)

        assert result is True

        retrieved = await redis_backend.get(hashed_key)
        assert retrieved is None

    async def test_delete_not_found(self, redis_backend: RedisBackend) -> None:
        """Test deleting a non-existent key returns False."""
        result = await redis_backend.delete("nonexistent_hash")

        assert result is False

    async def test_delete_removes_from_id_lookup(self, redis_backend: RedisBackend) -> None:
        """Test that deletion means get_by_id also returns None."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )
        await redis_backend.create(hashed_key, key_info)
        await redis_backend.delete(hashed_key)

        result = await redis_backend.get_by_id("test-123")
        assert result is None

    async def test_delete_removes_from_list(self, redis_backend: RedisBackend) -> None:
        """Test that deleted keys no longer appear in list results."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )
        await redis_backend.create(hashed_key, key_info)
        await redis_backend.delete(hashed_key)

        keys = await redis_backend.list()
        assert len(keys) == 0

    async def test_delete_does_not_orphan_key_recreated_mid_delete(self, redis_backend: RedisBackend) -> None:
        """Regression test for a race in delete()'s tracking-set cleanup.

        Without WATCH, delete() read the record, then issued DEL and SREM
        as two separate, non-atomic commands. If a concurrent create()
        landed in that window -- recreating the same hash via its own
        atomic SET + SADD -- delete()'s subsequent SREM would strip the
        freshly (re)created key's tracking entry: the same orphaning bug
        as in list(), just triggered from the opposite direction (the
        write side deleting, rather than the read side cleaning up stale
        entries).

        This forces the concurrent create() to land after delete()'s
        WATCH/GET re-check but before its EXEC, so it can only pass if
        delete() is genuinely transactional (WATCH aborting EXEC), not
        merely re-checking values before proceeding.
        """
        _, hashed_key = generate_api_key("test_")
        key_info = APIKeyInfo(
            key_id="race-delete-recreate-1",
            key_hash=hashed_key,
            name="Race Delete Recreate Key",
            scopes=["read"],
            is_active=True,
        )
        await redis_backend.create(hashed_key, key_info)

        recreated_info = APIKeyInfo(
            key_id="race-delete-recreate-2",
            key_hash=hashed_key,
            name="Recreated Delete Key",
            scopes=["read"],
            is_active=True,
        )

        client = redis_backend._client
        redis_key = redis_backend._make_key(hashed_key)
        original_pipeline_factory = client.pipeline
        triggered = False

        def tracking_pipeline_factory(*args: Any, **kwargs: Any) -> Any:
            pipeline = original_pipeline_factory(*args, **kwargs)
            original_get = pipeline.get

            async def tracking_get(key: str, *a: Any, **kw: Any) -> Any:
                nonlocal triggered
                result = await original_get(key, *a, **kw)
                # Land the concurrent recreate strictly after delete()'s
                # re-check GET has returned, but before it reaches EXEC.
                if key == redis_key and not triggered:
                    triggered = True
                    await client.delete(redis_key, redis_backend._make_id_key("race-delete-recreate-1"))
                    await redis_backend.create(hashed_key, recreated_info)
                return result

            pipeline.get = tracking_get
            return pipeline

        client.pipeline = tracking_pipeline_factory
        try:
            result = await redis_backend.delete(hashed_key)
        finally:
            client.pipeline = original_pipeline_factory

        assert triggered
        assert result is True

        # delete() must retry against the fresh record and fully delete it
        # (hash, ID index, and tracking entry together) rather than leave
        # the recreated key's tracking entry orphaned.
        assert await redis_backend.get(hashed_key) is None
        assert await redis_backend.get_by_id("race-delete-recreate-2") is None
        # get_by_id() alone would also return None if the ID index were left
        # dangling (pointing at an already-deleted primary), so check the
        # index key directly to prove it was actually cleaned up too.
        assert await client.exists(redis_backend._make_id_key("race-delete-recreate-2")) == 0
        remaining = await client.smembers(redis_backend._all_keys_key)
        assert hashed_key not in remaining, "key recreated mid-delete() must not leave a dangling tracking entry"

    async def test_delete_keeps_srem_inside_transaction(self, redis_backend: RedisBackend) -> None:
        """Regression guard: SREM must be queued on the same pipeline as DEL.

        test_delete_does_not_orphan_key_recreated_mid_delete proves the
        overall read-then-write is atomic, but a broken implementation that
        moved the SREM out of the MULTI block into a bare, non-transactional
        `client.srem()` call issued after EXEC could still pass it -- nothing
        in that test recreates the key a second time between DEL and a
        trailing SREM. This test patches the raw client's `srem` (as opposed
        to the pipeline's queued `srem`) to fail loudly if it is ever
        invoked, forcing delete() to route the tracking-set removal through
        the same MULTI/EXEC transaction as the DEL rather than as a separate
        command.
        """
        _, hashed_key = generate_api_key("test_")
        key_info = APIKeyInfo(
            key_id="srem-in-transaction-1",
            key_hash=hashed_key,
            name="SREM Transaction Key",
            scopes=["read"],
            is_active=True,
        )
        await redis_backend.create(hashed_key, key_info)

        client = redis_backend._client
        original_srem = client.srem

        async def guarded_srem(*args: Any, **kwargs: Any) -> Any:
            pytest.fail(
                "delete() must not call the bare client.srem() directly -- "
                "SREM must be queued on the pipeline inside the same MULTI/EXEC as DEL"
            )

        client.srem = guarded_srem
        try:
            result = await redis_backend.delete(hashed_key)
        finally:
            client.srem = original_srem

        assert result is True
        assert await redis_backend.get(hashed_key) is None
        remaining = await client.smembers(redis_backend._all_keys_key)
        assert hashed_key not in remaining

    async def test_delete_pipeline_response_error_does_not_leak_hash(self, redis_backend: RedisBackend) -> None:
        """A Redis-level pipeline failure in delete() must not embed key_hash either.

        Same disclosure mechanism as create()'s and update()'s equivalent
        regression tests: redis-py annotates a failed pipelined command with
        its full argument list (see ``Pipeline.annotate_exception``), which
        for delete()'s DEL/SREM calls includes the raw key_hash embedded in
        redis_key. Forces the pipeline's EXEC to fail with such an error and
        asserts delete() sanitizes it instead of letting the hash-bearing
        ResponseError escape.
        """
        _, hashed_key = generate_api_key("test_")
        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )
        await redis_backend.create(hashed_key, key_info)

        client = redis_backend._client
        redis_key = redis_backend._make_key(hashed_key)
        original_pipeline_factory = client.pipeline

        def failing_pipeline_factory(*args: Any, **kwargs: Any) -> Any:
            pipeline = original_pipeline_factory(*args, **kwargs)

            async def failing_execute(*a: Any, **kw: Any) -> Any:
                from redis.exceptions import ResponseError

                # Mirrors redis-py's real annotation: the failed command and
                # its full arguments (including the raw key_hash) folded into
                # the exception message.
                msg = f"DEL {redis_key}: ERR some Redis-level failure"
                raise ResponseError(msg)

            pipeline.execute = failing_execute
            return pipeline

        client.pipeline = failing_pipeline_factory
        try:
            with pytest.raises(RuntimeError) as exc_info:
                await redis_backend.delete(hashed_key)
        finally:
            client.pipeline = original_pipeline_factory

        assert hashed_key not in str(exc_info.value)
        assert str(exc_info.value) == "Failed to delete API key due to a Redis error"
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__suppress_context__ is True


class TestRedisBackendList:
    """Tests for listing API keys with pagination."""

    async def test_list_empty(self, redis_backend: RedisBackend) -> None:
        """Test listing keys when backend is empty."""
        result = await redis_backend.list()

        assert result == []

    async def test_list_all(self, redis_backend: RedisBackend) -> None:
        """Test listing all keys without pagination."""
        for i in range(5):
            _, hashed_key = generate_api_key(f"test{i}_")
            key_info = APIKeyInfo(
                key_id=f"test-{i}",
                key_hash=hashed_key,
                name=f"Test Key {i}",
                scopes=["read"],
            )
            await redis_backend.create(hashed_key, key_info)

        result = await redis_backend.list()

        assert len(result) == 5
        # Sorted by created_at desc, key_id desc -- newest first
        assert result[0].name == "Test Key 4"
        assert result[-1].name == "Test Key 0"

    async def test_list_with_limit(self, redis_backend: RedisBackend) -> None:
        """Test listing keys with limit."""
        for i in range(5):
            _, hashed_key = generate_api_key(f"test{i}_")
            key_info = APIKeyInfo(
                key_id=f"test-{i}",
                key_hash=hashed_key,
                name=f"Test Key {i}",
                scopes=["read"],
            )
            await redis_backend.create(hashed_key, key_info)

        result = await redis_backend.list(limit=3)

        assert len(result) == 3

    async def test_list_with_offset(self, redis_backend: RedisBackend) -> None:
        """Test listing keys with offset."""
        for i in range(5):
            _, hashed_key = generate_api_key(f"test{i}_")
            key_info = APIKeyInfo(
                key_id=f"test-{i}",
                key_hash=hashed_key,
                name=f"Test Key {i}",
                scopes=["read"],
            )
            await redis_backend.create(hashed_key, key_info)

        result = await redis_backend.list(offset=2)

        assert len(result) == 3
        assert result[0].name == "Test Key 2"

    async def test_list_with_limit_and_offset(self, redis_backend: RedisBackend) -> None:
        """Test listing keys with both limit and offset."""
        for i in range(10):
            _, hashed_key = generate_api_key(f"test{i}_")
            key_info = APIKeyInfo(
                key_id=f"test-{i}",
                key_hash=hashed_key,
                name=f"Test Key {i}",
                scopes=["read"],
            )
            await redis_backend.create(hashed_key, key_info)

        result = await redis_backend.list(limit=3, offset=2)

        assert len(result) == 3
        assert result[0].name == "Test Key 7"
        assert result[1].name == "Test Key 6"
        assert result[2].name == "Test Key 5"

    async def test_list_cleans_up_genuinely_stale_entry(self, redis_backend: RedisBackend) -> None:
        """Test that a tracking entry whose primary record is gone (and stays
        gone) is dropped from the all_keys set and omitted from results.
        """
        _, hashed_key = generate_api_key("test_")
        key_info = APIKeyInfo(
            key_id="stale-1",
            key_hash=hashed_key,
            name="Stale Key",
            scopes=["read"],
        )
        await redis_backend.create(hashed_key, key_info)

        # Simulate TTL expiry of the primary record; the all_keys entry
        # (which has no TTL of its own) survives.
        client = redis_backend._client
        await client.delete(redis_backend._make_key(hashed_key))

        result = await redis_backend.list()

        assert result == []
        remaining = await client.smembers(redis_backend._all_keys_key)
        assert hashed_key not in remaining, "genuinely stale entry must still be cleaned up from the tracking set"

    async def test_list_does_not_orphan_key_recreated_during_stale_cleanup(self, redis_backend: RedisBackend) -> None:
        """Regression test for a race in list()'s stale-entry cleanup.

        Reproduces the exact interleaving from the failure scenario: (1)
        list()'s SMEMBERS includes a hash whose primary record already
        expired, so MGET returns None for it and it gets queued as stale,
        (2) a concurrent create() re-creates that same hash (SET + SADD,
        done atomically) before list() gets to clean up the tracking set,
        (3) list()'s stale-entry cleanup must not then SREM the hash back
        out -- doing so would leave a live, authenticating key permanently
        missing from list() results even though get() still finds it.
        """
        _, hashed_key = generate_api_key("test_")
        key_info = APIKeyInfo(
            key_id="race-list-1",
            key_hash=hashed_key,
            name="Race List Key",
            scopes=["read"],
            is_active=True,
        )
        await redis_backend.create(hashed_key, key_info)

        # Simulate external expiry: the primary hash and its ID index are
        # gone, but the all_keys tracking entry survives, exactly as it
        # would once Redis expires both keys under a configured TTL.
        client = redis_backend._client
        redis_key = redis_backend._make_key(hashed_key)
        await client.delete(redis_key, redis_backend._make_id_key("race-list-1"))

        recreated_info = APIKeyInfo(
            key_id="race-list-1",
            key_hash=hashed_key,
            name="Recreated Key",
            scopes=["read"],
            is_active=True,
        )

        original_mget = client.mget
        recreated = False

        async def racing_mget(*args: Any, **kwargs: Any) -> Any:
            nonlocal recreated
            result = await original_mget(*args, **kwargs)
            # Land the concurrent create() right after list() has already
            # observed the key as missing, before it decides to clean up.
            if not recreated:
                recreated = True
                await redis_backend.create(hashed_key, recreated_info)
            return result

        client.mget = racing_mget
        try:
            await redis_backend.list()
        finally:
            client.mget = original_mget

        assert recreated

        remaining = await client.smembers(redis_backend._all_keys_key)
        assert (
            hashed_key in remaining
        ), "key recreated during list()'s stale-entry cleanup must remain in the all_keys tracking set"

        result = await redis_backend.list()
        assert any(
            k.key_hash == hashed_key for k in result
        ), "recreated key must be visible in list() output, not permanently orphaned"

    async def test_list_cleanup_aborts_via_watch_when_recreated_before_exec(self, redis_backend: RedisBackend) -> None:
        """Regression test for the WATCH-protected window in list()'s cleanup.

        Unlike test_list_does_not_orphan_key_recreated_during_stale_cleanup
        (which recreates the key before the cleanup loop's re-check GET
        even runs), this lands the concurrent create() *after* that GET
        has already returned None but *before* the cleanup transaction's
        EXEC. A naive "GET again, then blind SREM" fix (i.e. one that
        re-checks but doesn't actually use WATCH/MULTI) would still get
        this interleaving wrong, since it has no way to notice a write
        that happens after its re-check read. Only genuine WATCH/MULTI
        protection catches it: Redis aborts the transaction because the
        watched key changed underneath it, regardless of what the GET saw
        a moment earlier.
        """
        _, hashed_key = generate_api_key("test_")
        key_info = APIKeyInfo(
            key_id="race-list-watch-1",
            key_hash=hashed_key,
            name="Race List Watch Key",
            scopes=["read"],
            is_active=True,
        )
        await redis_backend.create(hashed_key, key_info)

        # Simulate external expiry, as in the sibling test above.
        client = redis_backend._client
        redis_key = redis_backend._make_key(hashed_key)
        await client.delete(redis_key, redis_backend._make_id_key("race-list-watch-1"))

        recreated_info = APIKeyInfo(
            key_id="race-list-watch-1",
            key_hash=hashed_key,
            name="Recreated Watch Key",
            scopes=["read"],
            is_active=True,
        )

        original_pipeline_factory = client.pipeline
        triggered = False

        def tracking_pipeline_factory(*args: Any, **kwargs: Any) -> Any:
            pipeline = original_pipeline_factory(*args, **kwargs)
            original_get = pipeline.get

            async def tracking_get(key: str, *a: Any, **kw: Any) -> Any:
                nonlocal triggered
                result = await original_get(key, *a, **kw)
                # Land the concurrent recreate strictly after list()'s
                # cleanup GET has returned (still None), but before it
                # reaches EXEC -- the window only WATCH can catch.
                if key == redis_key and not triggered:
                    triggered = True
                    await redis_backend.create(hashed_key, recreated_info)
                return result

            pipeline.get = tracking_get
            return pipeline

        client.pipeline = tracking_pipeline_factory
        try:
            await redis_backend.list()
        finally:
            client.pipeline = original_pipeline_factory

        assert triggered

        remaining = await client.smembers(redis_backend._all_keys_key)
        assert (
            hashed_key in remaining
        ), "WATCH must abort the cleanup transaction when the key is recreated between the re-check GET and EXEC"

    async def test_list_cleanup_response_error_does_not_leak_hash(self, redis_backend: RedisBackend) -> None:
        """A Redis-level pipeline failure in list()'s stale-cleanup must not embed key_hash either.

        Same disclosure mechanism as create()'s/update()'s/delete()'s
        equivalent regression tests: redis-py annotates a failed pipelined
        command with its full argument list (see
        ``Pipeline.annotate_exception``), which for the cleanup loop's SREM
        call includes the raw stale hash. Since this cleanup is best-effort,
        list() must swallow the error (leaving the tracking entry alone, same
        as it already does for WatchError) rather than let a hash-bearing
        exception escape list() entirely over a single stale entry.
        """
        _, hashed_key = generate_api_key("test_")
        key_info = APIKeyInfo(
            key_id="stale-response-error-1",
            key_hash=hashed_key,
            name="Stale Key",
            scopes=["read"],
        )
        await redis_backend.create(hashed_key, key_info)

        # Simulate external expiry, as in the sibling stale-cleanup tests.
        client = redis_backend._client
        redis_key = redis_backend._make_key(hashed_key)
        await client.delete(redis_key, redis_backend._make_id_key("stale-response-error-1"))

        original_pipeline_factory = client.pipeline

        def failing_pipeline_factory(*args: Any, **kwargs: Any) -> Any:
            pipeline = original_pipeline_factory(*args, **kwargs)
            original_execute = pipeline.execute

            async def failing_execute(*a: Any, **kw: Any) -> Any:
                # Only the cleanup transaction's EXEC (queued after multi())
                # should fail; let the watch/get-only calls pass through.
                if pipeline.explicit_transaction:
                    from redis.exceptions import ResponseError

                    msg = f"SREM {redis_backend._all_keys_key} {hashed_key}: ERR some Redis-level failure"
                    raise ResponseError(msg)
                return await original_execute(*a, **kw)

            pipeline.execute = failing_execute
            return pipeline

        client.pipeline = failing_pipeline_factory
        try:
            result = await redis_backend.list()
        finally:
            client.pipeline = original_pipeline_factory

        # list() itself must not raise -- the failure is swallowed exactly
        # like a WatchError, and the hash never appears in a propagated
        # exception because there is no propagated exception at all.
        assert result == []
        remaining = await client.smembers(redis_backend._all_keys_key)
        assert (
            hashed_key in remaining
        ), "cleanup left the tracking entry alone after a ResponseError, same as WatchError"


class TestRedisBackendRevoke:
    """Tests for revoking API keys."""

    async def test_revoke(self, redis_backend: RedisBackend) -> None:
        """Test revoking an API key."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
            is_active=True,
        )
        await redis_backend.create(hashed_key, key_info)

        result = await redis_backend.revoke(hashed_key)

        assert result is True

        retrieved = await redis_backend.get(hashed_key)
        assert retrieved is not None
        assert retrieved.is_active is False

    async def test_revoke_not_found(self, redis_backend: RedisBackend) -> None:
        """Test revoking a non-existent key returns False."""
        result = await redis_backend.revoke("nonexistent_hash")

        assert result is False

    async def test_revoke_already_revoked(self, redis_backend: RedisBackend) -> None:
        """Test revoking an already revoked key."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
            is_active=False,
        )
        await redis_backend.create(hashed_key, key_info)

        result = await redis_backend.revoke(hashed_key)

        assert result is True

        retrieved = await redis_backend.get(hashed_key)
        assert retrieved is not None
        assert retrieved.is_active is False


class TestRedisBackendUpdateLastUsed:
    """Tests for updating last_used_at timestamp."""

    async def test_update_last_used(self, redis_backend: RedisBackend) -> None:
        """Test updating the last_used_at timestamp."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
            last_used_at=None,
        )
        await redis_backend.create(hashed_key, key_info)

        await redis_backend.update_last_used(hashed_key)

        retrieved = await redis_backend.get(hashed_key)
        assert retrieved is not None
        assert retrieved.last_used_at is not None
        assert (datetime.now(timezone.utc) - retrieved.last_used_at) < timedelta(minutes=1)

    async def test_update_last_used_multiple_times(self, redis_backend: RedisBackend) -> None:
        """Test updating last_used_at multiple times."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )
        await redis_backend.create(hashed_key, key_info)

        await redis_backend.update_last_used(hashed_key)
        first_update = await redis_backend.get(hashed_key)
        first_time = first_update.last_used_at

        await asyncio.sleep(0.01)

        await redis_backend.update_last_used(hashed_key)
        second_update = await redis_backend.get(hashed_key)
        second_time = second_update.last_used_at

        assert first_time is not None
        assert second_time is not None
        assert second_time >= first_time

    async def test_update_last_used_does_not_move_backward(self, redis_backend: RedisBackend) -> None:
        """A stale write must not roll last_used_at backward.

        Regression test for a race where update_last_used() captures
        datetime.now() before entering update()'s WATCH retry loop: a call
        that loses the WATCH race retries against a record a concurrent,
        later-timestamped call already wrote, and must not clobber that
        newer value with its own older one.
        """
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )
        await redis_backend.create(hashed_key, key_info)

        newer = datetime.now(timezone.utc)
        older = newer - timedelta(seconds=5)

        # Simulate the newer timestamp winning the WATCH race and landing first.
        await redis_backend.update(hashed_key, last_used_at=newer)
        # Simulate the race loser's retried write, carrying its stale, older timestamp.
        await redis_backend.update(hashed_key, last_used_at=older)

        retrieved = await redis_backend.get(hashed_key)
        assert retrieved is not None
        assert retrieved.last_used_at == newer

    async def test_update_last_used_with_naive_stored_timestamp(self, redis_backend: RedisBackend) -> None:
        """The monotonicity guard must not raise on a naive stored timestamp.

        APIKeyInfo.is_expired treats a naive last_used_at as UTC, so callers
        may legitimately store one directly (bypassing update_last_used()'s
        own tz-aware datetime.now(timezone.utc)). The guard added to close
        the backward-timestamp race must compare naive and aware values as
        equivalent UTC instants instead of raising
        ``TypeError: can't compare offset-naive and offset-aware datetimes``.
        """
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
            last_used_at=datetime.now() - timedelta(days=1),
        )
        await redis_backend.create(hashed_key, key_info)

        # Should not raise despite comparing a naive stored value against
        # update_last_used()'s tz-aware datetime.now(timezone.utc).
        await redis_backend.update_last_used(hashed_key)

        retrieved = await redis_backend.get(hashed_key)
        assert retrieved is not None
        assert retrieved.last_used_at is not None
        assert (datetime.now(timezone.utc) - retrieved.last_used_at) < timedelta(minutes=1)


class TestRedisBackendClose:
    """Tests for closing the backend."""

    async def test_close(self) -> None:
        """Test closing the backend closes the Redis client."""
        client = fakeredis.aioredis.FakeRedis(decode_responses=True)
        config = RedisConfig(client=client)
        backend = RedisBackend(config=config)

        # Create a key to verify the backend is operational
        _, hashed_key = generate_api_key("test_")
        key_info = APIKeyInfo(
            key_id="test-close",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )
        await backend.create(hashed_key, key_info)

        # Close the backend -- should not raise
        await backend.close()

    async def test_close_with_no_client(self) -> None:
        """Test closing a backend that has no client does not raise."""
        config = RedisConfig(client=None)
        backend = RedisBackend(config=config)

        # Should complete without error
        await backend.close()


class TestRedisConfig:
    """Tests for RedisConfig."""

    def test_config_default(self) -> None:
        """Test default RedisConfig values."""
        config = RedisConfig()

        assert config.client is None
        assert config.key_prefix == "api_key:"
        assert config.ttl is None

    def test_config_custom(self) -> None:
        """Test custom RedisConfig values."""
        client = fakeredis.aioredis.FakeRedis(decode_responses=True)
        config = RedisConfig(
            client=client,
            key_prefix="custom:keys:",
            ttl=3600,
        )

        assert config.client is client
        assert config.key_prefix == "custom:keys:"
        assert config.ttl == 3600

    def test_backend_repr(self) -> None:
        """Test string representation of RedisBackend."""
        backend = RedisBackend(RedisConfig(key_prefix="myapp:"))
        repr_str = repr(backend)

        assert "RedisBackend" in repr_str
        assert "myapp:" in repr_str


class TestRedisBackendRuntimeError:
    """Tests for RuntimeError when Redis client is not configured."""

    async def test_create_no_client(self) -> None:
        """Test create raises RuntimeError with no client."""
        backend = RedisBackend(RedisConfig(client=None))
        _, hashed_key = generate_api_key("test_")
        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )

        with pytest.raises(RuntimeError, match="Redis client is not configured"):
            await backend.create(hashed_key, key_info)

    async def test_get_no_client(self) -> None:
        """Test get raises RuntimeError with no client."""
        backend = RedisBackend(RedisConfig(client=None))

        with pytest.raises(RuntimeError, match="Redis client is not configured"):
            await backend.get("some_hash")

    async def test_get_by_id_no_client(self) -> None:
        """Test get_by_id raises RuntimeError with no client."""
        backend = RedisBackend(RedisConfig(client=None))

        with pytest.raises(RuntimeError, match="Redis client is not configured"):
            await backend.get_by_id("some-id")

    async def test_update_no_client(self) -> None:
        """Test update raises RuntimeError with no client."""
        backend = RedisBackend(RedisConfig(client=None))

        with pytest.raises(RuntimeError, match="Redis client is not configured"):
            await backend.update("some_hash", name="New Name")

    async def test_delete_no_client(self) -> None:
        """Test delete raises RuntimeError with no client."""
        backend = RedisBackend(RedisConfig(client=None))

        with pytest.raises(RuntimeError, match="Redis client is not configured"):
            await backend.delete("some_hash")

    async def test_list_no_client(self) -> None:
        """Test list raises RuntimeError with no client."""
        backend = RedisBackend(RedisConfig(client=None))

        with pytest.raises(RuntimeError, match="Redis client is not configured"):
            await backend.list()


class TestRedisBackendIntegration:
    """Integration tests for the Redis backend."""

    async def test_complete_key_lifecycle(self, redis_backend: RedisBackend) -> None:
        """Test complete lifecycle of an API key: create, get, update, revoke, delete."""
        _raw_key, hashed_key = generate_api_key("app_")

        # Create key
        key_info = APIKeyInfo(
            key_id="lifecycle-test",
            key_hash=hashed_key,
            name="Lifecycle Test",
            scopes=["read", "write"],
        )
        created = await redis_backend.create(hashed_key, key_info)
        assert created.name == "Lifecycle Test"

        # Retrieve key by hash
        retrieved = await redis_backend.get(hashed_key)
        assert retrieved is not None
        assert retrieved.name == "Lifecycle Test"

        # Retrieve key by ID
        by_id = await redis_backend.get_by_id("lifecycle-test")
        assert by_id is not None
        assert by_id.key_hash == hashed_key

        # Update key
        updated = await redis_backend.update(hashed_key, name="Updated Name")
        assert updated is not None
        assert updated.name == "Updated Name"

        # Update last used
        await redis_backend.update_last_used(hashed_key)
        after_use = await redis_backend.get(hashed_key)
        assert after_use is not None
        assert after_use.last_used_at is not None

        # Revoke key
        revoked = await redis_backend.revoke(hashed_key)
        assert revoked is True

        # Verify revoked
        final = await redis_backend.get(hashed_key)
        assert final is not None
        assert final.is_active is False

        # Delete key
        deleted = await redis_backend.delete(hashed_key)
        assert deleted is True

        # Verify deleted
        not_found = await redis_backend.get(hashed_key)
        assert not_found is None

        # Verify gone from ID index
        not_found_by_id = await redis_backend.get_by_id("lifecycle-test")
        assert not_found_by_id is None

    async def test_multiple_keys_isolation(self, redis_backend: RedisBackend) -> None:
        """Test that operations on one key do not affect another."""
        _, hashed_key1 = generate_api_key("test_")
        _, hashed_key2 = generate_api_key("test_")

        key1 = APIKeyInfo(
            key_id="key-1",
            key_hash=hashed_key1,
            name="Key One",
            scopes=["read"],
        )
        key2 = APIKeyInfo(
            key_id="key-2",
            key_hash=hashed_key2,
            name="Key Two",
            scopes=["write"],
        )

        await redis_backend.create(hashed_key1, key1)
        await redis_backend.create(hashed_key2, key2)

        # Revoke key1
        await redis_backend.revoke(hashed_key1)

        # key2 should be unaffected
        retrieved_key2 = await redis_backend.get(hashed_key2)
        assert retrieved_key2 is not None
        assert retrieved_key2.is_active is True
        assert retrieved_key2.name == "Key Two"

        # Delete key2
        await redis_backend.delete(hashed_key2)

        # key1 should still be retrievable
        retrieved_key1 = await redis_backend.get(hashed_key1)
        assert retrieved_key1 is not None
        assert retrieved_key1.is_active is False

    async def test_duplicate_id_rollback(self, redis_backend: RedisBackend) -> None:
        """Test that creating a key with a duplicate ID rolls back the hash key."""
        _, hashed_key1 = generate_api_key("test_")
        _, hashed_key2 = generate_api_key("test_")

        key1 = APIKeyInfo(
            key_id="shared-id",
            key_hash=hashed_key1,
            name="First Key",
            scopes=["read"],
        )
        await redis_backend.create(hashed_key1, key1)

        key2 = APIKeyInfo(
            key_id="shared-id",
            key_hash=hashed_key2,
            name="Second Key",
            scopes=["write"],
        )

        with pytest.raises(ValueError, match="already exists"):
            await redis_backend.create(hashed_key2, key2)

        # The rolled-back hash key should not be retrievable
        result = await redis_backend.get(hashed_key2)
        assert result is None

        # The original key should still be fine
        original = await redis_backend.get(hashed_key1)
        assert original is not None
        assert original.name == "First Key"

    async def test_concurrent_create_duplicate_id(self, redis_backend: RedisBackend) -> None:
        """Test duplicate key_id handling under concurrent create calls."""
        _, hashed_key1 = generate_api_key("test_")
        _, hashed_key2 = generate_api_key("test_")
        shared_id = "concurrent-id"

        key1 = APIKeyInfo(
            key_id=shared_id,
            key_hash=hashed_key1,
            name="Concurrent One",
            scopes=["read"],
        )
        key2 = APIKeyInfo(
            key_id=shared_id,
            key_hash=hashed_key2,
            name="Concurrent Two",
            scopes=["write"],
        )

        results = await asyncio.gather(
            redis_backend.create(hashed_key1, key1),
            redis_backend.create(hashed_key2, key2),
            return_exceptions=True,
        )

        errors = [r for r in results if isinstance(r, Exception)]
        successes = [r for r in results if not isinstance(r, Exception)]
        assert len(successes) == 1
        assert len(errors) == 1
        assert isinstance(errors[0], ValueError)

        # Index should resolve to exactly one key.
        by_id = await redis_backend.get_by_id(shared_id)
        assert by_id is not None
        assert by_id.key_hash in {hashed_key1, hashed_key2}

        found = [await redis_backend.get(hashed_key1), await redis_backend.get(hashed_key2)]
        assert sum(v is not None for v in found) == 1

    async def test_update_preserves_ttl_for_id_index(self) -> None:
        """Test that update() keeps the hash key and ID index TTLs in sync without extending either.

        update() writes with SET ... KEEPTTL, so the existing (creation-time)
        TTL keeps counting down across metadata updates -- it is neither wiped
        (which plain SET would do, persisting the key forever) nor reset to
        the full configured TTL (which would turn it into a sliding inactivity
        timeout). Both the hash key and the untouched ID index key were given
        the same TTL at creation, so they stay in sync without needing update()
        to refresh anything.
        """
        client = fakeredis.aioredis.FakeRedis(decode_responses=True)
        backend = RedisBackend(config=RedisConfig(client=client, key_prefix="ttl_test:", ttl=2))

        try:
            _, hashed_key = generate_api_key("test_")
            key_info = APIKeyInfo(
                key_id="ttl-id",
                key_hash=hashed_key,
                name="TTL Key",
                scopes=["read"],
            )
            await backend.create(hashed_key, key_info)

            await asyncio.sleep(1.2)
            await backend.update(hashed_key, name="TTL Updated")

            # The update must not have reset the TTL back up to the full 2s,
            # nor cleared it (persisting the key) -- it should still be
            # counting down from the original creation time. Check both keys
            # directly (rather than only inferring via get_by_id(), which
            # would also read None once the primary key alone expires, even
            # if the ID index itself never expired).
            redis_key = backend._make_key(hashed_key)
            id_key = backend._make_id_key("ttl-id")
            remaining_hash_ttl = await client.ttl(redis_key)
            remaining_id_ttl = await client.ttl(id_key)
            assert 0 < remaining_hash_ttl <= 1
            assert 0 < remaining_id_ttl <= 1

            # Once the original TTL elapses, both the primary record and the
            # ID index must be gone -- the update earlier must not have
            # extended their lifetime.
            await asyncio.sleep(1.0)

            by_hash = await backend.get(hashed_key)
            by_id = await backend.get_by_id("ttl-id")
            assert by_hash is None
            assert by_id is None
            assert await client.exists(redis_key) == 0
            assert await client.exists(id_key) == 0
        finally:
            await backend.close()

    async def test_update_last_used_does_not_extend_ttl_past_configured_expiry(self) -> None:
        """Regression test: TTL must be a hard expiry, not a sliding inactivity timeout.

        Before the fix, update() unconditionally re-applied the *full*
        configured TTL on every call. Since update_last_used() invokes
        update() on every authenticated request, an actively used key would
        have its expiry pushed back on each request and would never actually
        hit the operator-configured TTL -- effectively living forever under
        continuous traffic. This asserts the key expires on schedule even
        while being used repeatedly, faster than the TTL, right up to (and
        past) the point it should expire.
        """
        client = fakeredis.aioredis.FakeRedis(decode_responses=True)
        backend = RedisBackend(config=RedisConfig(client=client, key_prefix="ttl_hard:", ttl=2))

        try:
            _, hashed_key = generate_api_key("test_")
            key_info = APIKeyInfo(
                key_id="hard-ttl-id",
                key_hash=hashed_key,
                name="Hard TTL Key",
                scopes=["read"],
            )
            await backend.create(hashed_key, key_info)

            # Simulate continuous authenticated traffic touching the key more
            # often than its TTL, spanning well past when the configured TTL
            # should have expired it.
            for _ in range(4):
                await asyncio.sleep(0.7)
                await backend.update_last_used(hashed_key)

            result = await backend.get(hashed_key)
            assert result is None, "key must expire per its configured TTL even under continuous activity"
        finally:
            await backend.close()

    async def _race_update_last_used(
        self,
        redis_backend: RedisBackend,
        hashed_key: str,
        concurrent_op: Callable[[], Awaitable[None]],
    ) -> None:
        """Force update_last_used() to race a concurrent write on the same key.

        Patches every pipeline's `get()` so that the *first* read of
        `redis_key` (update_last_used()'s own read, inside its WATCH) blocks
        until `concurrent_op` has fully committed. This reproduces the exact
        interleaving from the failure scenario: (1) usage update reads the
        current record, (2) a concurrent write lands, (3) usage update
        attempts to write its now-stale copy back. Reads made *after* the
        first (e.g. by `concurrent_op` itself, or update_last_used()'s own
        retry) pass straight through untouched.
        """
        redis_key = redis_backend._make_key(hashed_key)
        client = redis_backend._client
        original_pipeline_factory = client.pipeline

        reader_ready = asyncio.Event()
        concurrent_op_done = asyncio.Event()

        def tracking_pipeline_factory(*args: Any, **kwargs: Any) -> Any:
            pipeline = original_pipeline_factory(*args, **kwargs)
            original_get = pipeline.get

            async def tracking_get(key: str, *a: Any, **kw: Any) -> Any:
                result = await original_get(key, *a, **kw)
                if key == redis_key and not reader_ready.is_set():
                    reader_ready.set()
                    await concurrent_op_done.wait()
                return result

            pipeline.get = tracking_get
            return pipeline

        client.pipeline = tracking_pipeline_factory

        async def run_concurrent_op() -> None:
            await reader_ready.wait()
            try:
                await concurrent_op()
            finally:
                # Always release the waiting update_last_used(), even if
                # concurrent_op() raises, so the test can't hang on failure.
                concurrent_op_done.set()

        try:
            await asyncio.gather(
                redis_backend.update_last_used(hashed_key),
                run_concurrent_op(),
            )
        finally:
            client.pipeline = original_pipeline_factory

    async def test_update_does_not_resurrect_concurrently_revoked_key(self, redis_backend: RedisBackend) -> None:
        """Test that a concurrent update() cannot clobber a concurrent revoke.

        Regression test for a race where update_last_used() (triggered on every
        authenticated request) performs a non-atomic GET/rebuild/SET. If an
        admin's revoke() lands in between the read and the write, the stale
        write used to resurrect the key as active again. update() must now use
        WATCH/MULTI so the stale write aborts and retries against the fresh
        (revoked) record instead.
        """
        _, hashed_key = generate_api_key("test_")
        key_info = APIKeyInfo(
            key_id="race-1",
            key_hash=hashed_key,
            name="Race Key",
            scopes=["read"],
            is_active=True,
        )
        await redis_backend.create(hashed_key, key_info)

        await self._race_update_last_used(
            redis_backend,
            hashed_key,
            lambda: redis_backend.revoke(hashed_key),
        )

        final = await redis_backend.get(hashed_key)
        assert final is not None
        assert final.is_active is False, "revoked key must not be resurrected by a racing update_last_used()"
        assert final.last_used_at is not None

    async def test_update_does_not_resurrect_concurrently_deleted_key(self, redis_backend: RedisBackend) -> None:
        """Test that a concurrent update() cannot recreate a concurrently deleted key.

        Same race as revoke, but for delete(): without WATCH, a stale
        update_last_used() write would recreate the primary hash record after
        deletion, so hash-based auth would keep succeeding on a "deleted" key
        even though it no longer appears in list() or get_by_id().
        """
        _, hashed_key = generate_api_key("test_")
        key_info = APIKeyInfo(
            key_id="race-delete-1",
            key_hash=hashed_key,
            name="Race Delete Key",
            scopes=["read"],
            is_active=True,
        )
        await redis_backend.create(hashed_key, key_info)

        await self._race_update_last_used(
            redis_backend,
            hashed_key,
            lambda: redis_backend.delete(hashed_key),
        )

        assert await redis_backend.get(hashed_key) is None, "deleted key must not be recreated by update_last_used()"
        assert await redis_backend.get_by_id("race-delete-1") is None

    async def test_update_last_used_retry_does_not_move_backward(self, redis_backend: RedisBackend) -> None:
        """A stale, WATCH-retried update_last_used() must not roll last_used_at backward.

        Forces the exact interleaving from the failure scenario using
        `_race_update_last_used`: update_last_used() reads the record with
        its own (real-time, effectively-older) timestamp, a concurrent write
        carrying a strictly newer last_used_at commits and wins the WATCH
        race, and update_last_used() then retries against that fresh record.
        The retry must preserve the newer timestamp instead of clobbering it
        with its own stale one.
        """
        _, hashed_key = generate_api_key("test_")
        key_info = APIKeyInfo(
            key_id="race-lastused-1",
            key_hash=hashed_key,
            name="Race Last-Used Key",
            scopes=["read"],
        )
        await redis_backend.create(hashed_key, key_info)

        newer = datetime.now(timezone.utc) + timedelta(seconds=5)

        await self._race_update_last_used(
            redis_backend,
            hashed_key,
            lambda: redis_backend.update(hashed_key, last_used_at=newer),
        )

        final = await redis_backend.get(hashed_key)
        assert final is not None
        assert (
            final.last_used_at == newer
        ), "a stale update_last_used() retry must not roll last_used_at backward past a newer concurrent write"
