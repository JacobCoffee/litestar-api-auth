"""Tests for Redis backend storage implementation.

This module tests the Redis storage backend for API key management,
including CRUD operations, pagination, serialization round-trips,
and the full key lifecycle.  Uses fakeredis for a hermetic test
environment that requires no running Redis server.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

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

    async def test_update_refreshes_ttl_for_id_index(self) -> None:
        """Test that update() refreshes TTL on both hash key and ID index key."""
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

            # Let initial TTL age, then update. Without refreshing ID TTL,
            # get_by_id() would start failing while get() still works.
            await asyncio.sleep(1.2)
            await backend.update(hashed_key, name="TTL Updated")
            await asyncio.sleep(1.2)

            by_hash = await backend.get(hashed_key)
            by_id = await backend.get_by_id("ttl-id")
            assert by_hash is not None
            assert by_id is not None
            assert by_id.name == "TTL Updated"
        finally:
            await backend.close()
