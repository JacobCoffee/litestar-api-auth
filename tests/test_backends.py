"""Tests for memory backend storage implementation.

This module tests the in-memory storage backend for API key management,
including CRUD operations, pagination, and concurrent access.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from litestar_api_auth.backends.base import APIKeyInfo
from litestar_api_auth.backends.memory import MemoryBackend, MemoryConfig
from litestar_api_auth.service import generate_api_key


class TestMemoryBackendCreate:
    """Tests for creating API keys in the memory backend."""

    @pytest.mark.asyncio
    async def test_memory_backend_create(self, memory_backend: MemoryBackend) -> None:
        """Test creating a new API key in memory backend."""
        raw_key, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read", "write"],
            is_active=True,
        )

        result = await memory_backend.create(hashed_key, key_info)

        assert result.key_id == "test-123"
        assert result.key_hash == hashed_key
        assert result.name == "Test Key"
        assert result.scopes == ["read", "write"]
        assert result.is_active is True
        assert result.created_at is not None  # Should be set by backend

    @pytest.mark.asyncio
    async def test_memory_backend_create_duplicate_hash(self, memory_backend: MemoryBackend) -> None:
        """Test that creating a key with duplicate hash raises error."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )

        # Create first key
        await memory_backend.create(hashed_key, key_info)

        # Attempt to create duplicate should fail
        duplicate_info = APIKeyInfo(
            key_id="test-456",  # Different ID
            key_hash=hashed_key,  # Same hash
            name="Duplicate Key",
            scopes=["write"],
        )

        with pytest.raises(ValueError, match="already exists"):
            await memory_backend.create(hashed_key, duplicate_info)

    @pytest.mark.asyncio
    async def test_memory_backend_create_duplicate_id(self, memory_backend: MemoryBackend) -> None:
        """Test that creating a key with duplicate ID raises error."""
        raw_key1, hashed_key1 = generate_api_key("test_")
        raw_key2, hashed_key2 = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="duplicate-id",
            key_hash=hashed_key1,
            name="First Key",
            scopes=["read"],
        )

        # Create first key
        await memory_backend.create(hashed_key1, key_info)

        # Attempt to create with same ID should fail
        duplicate_info = APIKeyInfo(
            key_id="duplicate-id",  # Same ID
            key_hash=hashed_key2,  # Different hash
            name="Second Key",
            scopes=["write"],
        )

        with pytest.raises(ValueError, match="already exists"):
            await memory_backend.create(hashed_key2, duplicate_info)

    @pytest.mark.asyncio
    async def test_memory_backend_create_sets_created_at(self, memory_backend: MemoryBackend) -> None:
        """Test that created_at is set if not provided."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
            created_at=None,  # Not provided
        )

        result = await memory_backend.create(hashed_key, key_info)

        assert result.created_at is not None
        # Should be recent (within last minute)
        assert (datetime.now(timezone.utc) - result.created_at) < timedelta(minutes=1)


class TestMemoryBackendGet:
    """Tests for retrieving API keys from the memory backend."""

    @pytest.mark.asyncio
    async def test_memory_backend_get(self, memory_backend: MemoryBackend) -> None:
        """Test retrieving an API key by hash."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )

        await memory_backend.create(hashed_key, key_info)

        # Retrieve the key
        result = await memory_backend.get(hashed_key)

        assert result is not None
        assert result.key_id == "test-123"
        assert result.name == "Test Key"
        assert result.scopes == ["read"]

    @pytest.mark.asyncio
    async def test_memory_backend_get_not_found(self, memory_backend: MemoryBackend) -> None:
        """Test retrieving a non-existent key returns None."""
        result = await memory_backend.get("nonexistent_hash")

        assert result is None

    @pytest.mark.asyncio
    async def test_memory_backend_get_by_id(self, memory_backend: MemoryBackend) -> None:
        """Test retrieving an API key by ID."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )

        await memory_backend.create(hashed_key, key_info)

        # Retrieve by ID
        result = await memory_backend.get_by_id("test-123")

        assert result is not None
        assert result.key_hash == hashed_key
        assert result.name == "Test Key"

    @pytest.mark.asyncio
    async def test_memory_backend_get_by_id_not_found(self, memory_backend: MemoryBackend) -> None:
        """Test retrieving by non-existent ID returns None."""
        result = await memory_backend.get_by_id("nonexistent-id")

        assert result is None

    @pytest.mark.asyncio
    async def test_memory_backend_get_returns_copy(self, memory_backend: MemoryBackend) -> None:
        """Test that get returns a copy, not the original object."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )

        await memory_backend.create(hashed_key, key_info)

        # Get the key twice
        result1 = await memory_backend.get(hashed_key)
        result2 = await memory_backend.get(hashed_key)

        # Should be equal but not the same object
        assert result1 is not None
        assert result2 is not None
        assert result1.key_id == result2.key_id
        assert result1 is not result2  # Different objects


class TestMemoryBackendUpdate:
    """Tests for updating API keys in the memory backend."""

    @pytest.mark.asyncio
    async def test_memory_backend_update(self, memory_backend: MemoryBackend) -> None:
        """Test updating an API key's metadata."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Original Name",
            scopes=["read"],
        )

        await memory_backend.create(hashed_key, key_info)

        # Update the key
        result = await memory_backend.update(hashed_key, name="Updated Name", scopes=["read", "write"])

        assert result is not None
        assert result.name == "Updated Name"
        assert result.scopes == ["read", "write"]
        assert result.key_id == "test-123"  # Unchanged

    @pytest.mark.asyncio
    async def test_memory_backend_update_not_found(self, memory_backend: MemoryBackend) -> None:
        """Test updating a non-existent key returns None."""
        result = await memory_backend.update("nonexistent_hash", name="New Name")

        assert result is None

    @pytest.mark.asyncio
    async def test_memory_backend_update_partial(self, memory_backend: MemoryBackend) -> None:
        """Test partial update of key metadata."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Original Name",
            scopes=["read", "write"],
            metadata={"key": "value"},
        )

        await memory_backend.create(hashed_key, key_info)

        # Update only name
        result = await memory_backend.update(hashed_key, name="New Name")

        assert result is not None
        assert result.name == "New Name"
        assert result.scopes == ["read", "write"]  # Unchanged
        assert result.metadata == {"key": "value"}  # Unchanged

    @pytest.mark.asyncio
    async def test_memory_backend_update_is_active(self, memory_backend: MemoryBackend) -> None:
        """Test updating the is_active flag."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
            is_active=True,
        )

        await memory_backend.create(hashed_key, key_info)

        # Deactivate the key
        result = await memory_backend.update(hashed_key, is_active=False)

        assert result is not None
        assert result.is_active is False


class TestMemoryBackendDelete:
    """Tests for deleting API keys from the memory backend."""

    @pytest.mark.asyncio
    async def test_memory_backend_delete(self, memory_backend: MemoryBackend) -> None:
        """Test deleting an API key."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )

        await memory_backend.create(hashed_key, key_info)

        # Delete the key
        result = await memory_backend.delete(hashed_key)

        assert result is True

        # Verify it's deleted
        retrieved = await memory_backend.get(hashed_key)
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_memory_backend_delete_not_found(self, memory_backend: MemoryBackend) -> None:
        """Test deleting a non-existent key returns False."""
        result = await memory_backend.delete("nonexistent_hash")

        assert result is False

    @pytest.mark.asyncio
    async def test_memory_backend_delete_removes_from_id_index(self, memory_backend: MemoryBackend) -> None:
        """Test that deletion removes key from ID index."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )

        await memory_backend.create(hashed_key, key_info)
        await memory_backend.delete(hashed_key)

        # Verify not retrievable by ID
        result = await memory_backend.get_by_id("test-123")
        assert result is None


class TestMemoryBackendList:
    """Tests for listing API keys with pagination."""

    @pytest.mark.asyncio
    async def test_memory_backend_list_empty(self, memory_backend: MemoryBackend) -> None:
        """Test listing keys when backend is empty."""
        result = await memory_backend.list()

        assert result == []

    @pytest.mark.asyncio
    async def test_memory_backend_list_all(self, memory_backend: MemoryBackend) -> None:
        """Test listing all keys without pagination."""
        # Create multiple keys
        for i in range(5):
            _, hashed_key = generate_api_key(f"test{i}_")
            key_info = APIKeyInfo(
                key_id=f"test-{i}",
                key_hash=hashed_key,
                name=f"Test Key {i}",
                scopes=["read"],
            )
            await memory_backend.create(hashed_key, key_info)

        result = await memory_backend.list()

        assert len(result) == 5
        # Should be sorted by created_at descending (newest first)
        assert result[0].name == "Test Key 4"
        assert result[-1].name == "Test Key 0"

    @pytest.mark.asyncio
    async def test_memory_backend_list_with_limit(self, memory_backend: MemoryBackend) -> None:
        """Test listing keys with limit."""
        # Create multiple keys
        for i in range(5):
            _, hashed_key = generate_api_key(f"test{i}_")
            key_info = APIKeyInfo(
                key_id=f"test-{i}",
                key_hash=hashed_key,
                name=f"Test Key {i}",
                scopes=["read"],
            )
            await memory_backend.create(hashed_key, key_info)

        result = await memory_backend.list(limit=3)

        assert len(result) == 3

    @pytest.mark.asyncio
    async def test_memory_backend_list_with_offset(self, memory_backend: MemoryBackend) -> None:
        """Test listing keys with offset."""
        # Create multiple keys
        for i in range(5):
            _, hashed_key = generate_api_key(f"test{i}_")
            key_info = APIKeyInfo(
                key_id=f"test-{i}",
                key_hash=hashed_key,
                name=f"Test Key {i}",
                scopes=["read"],
            )
            await memory_backend.create(hashed_key, key_info)

        result = await memory_backend.list(offset=2)

        assert len(result) == 3  # 5 total - 2 offset = 3
        # Should skip first 2 (newest)
        assert result[0].name == "Test Key 2"

    @pytest.mark.asyncio
    async def test_memory_backend_list_with_limit_and_offset(self, memory_backend: MemoryBackend) -> None:
        """Test listing keys with both limit and offset."""
        # Create multiple keys
        for i in range(10):
            _, hashed_key = generate_api_key(f"test{i}_")
            key_info = APIKeyInfo(
                key_id=f"test-{i}",
                key_hash=hashed_key,
                name=f"Test Key {i}",
                scopes=["read"],
            )
            await memory_backend.create(hashed_key, key_info)

        result = await memory_backend.list(limit=3, offset=2)

        assert len(result) == 3
        # Should get items 2, 3, 4 (0-indexed after sorting by created_at desc)
        assert result[0].name == "Test Key 7"
        assert result[1].name == "Test Key 6"
        assert result[2].name == "Test Key 5"


class TestMemoryBackendRevoke:
    """Tests for revoking API keys."""

    @pytest.mark.asyncio
    async def test_memory_backend_revoke(self, memory_backend: MemoryBackend) -> None:
        """Test revoking an API key."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
            is_active=True,
        )

        await memory_backend.create(hashed_key, key_info)

        # Revoke the key
        result = await memory_backend.revoke(hashed_key)

        assert result is True

        # Verify it's revoked
        retrieved = await memory_backend.get(hashed_key)
        assert retrieved is not None
        assert retrieved.is_active is False

    @pytest.mark.asyncio
    async def test_memory_backend_revoke_not_found(self, memory_backend: MemoryBackend) -> None:
        """Test revoking a non-existent key returns False."""
        result = await memory_backend.revoke("nonexistent_hash")

        assert result is False

    @pytest.mark.asyncio
    async def test_memory_backend_revoke_already_revoked(self, memory_backend: MemoryBackend) -> None:
        """Test revoking an already revoked key."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
            is_active=False,  # Already revoked
        )

        await memory_backend.create(hashed_key, key_info)

        # Revoke again
        result = await memory_backend.revoke(hashed_key)

        assert result is True  # Should still return True

        # Verify still revoked
        retrieved = await memory_backend.get(hashed_key)
        assert retrieved is not None
        assert retrieved.is_active is False


class TestMemoryBackendUpdateLastUsed:
    """Tests for updating last_used_at timestamp."""

    @pytest.mark.asyncio
    async def test_memory_backend_update_last_used(self, memory_backend: MemoryBackend) -> None:
        """Test updating the last_used_at timestamp."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
            last_used_at=None,
        )

        await memory_backend.create(hashed_key, key_info)

        # Update last used
        await memory_backend.update_last_used(hashed_key)

        # Verify updated
        retrieved = await memory_backend.get(hashed_key)
        assert retrieved is not None
        assert retrieved.last_used_at is not None
        # Should be recent
        assert (datetime.now(timezone.utc) - retrieved.last_used_at) < timedelta(minutes=1)

    @pytest.mark.asyncio
    async def test_memory_backend_update_last_used_multiple_times(self, memory_backend: MemoryBackend) -> None:
        """Test updating last_used_at multiple times."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )

        await memory_backend.create(hashed_key, key_info)

        # First update
        await memory_backend.update_last_used(hashed_key)
        first_update = await memory_backend.get(hashed_key)
        first_time = first_update.last_used_at

        # Small delay to ensure different timestamp
        import asyncio

        await asyncio.sleep(0.01)

        # Second update
        await memory_backend.update_last_used(hashed_key)
        second_update = await memory_backend.get(hashed_key)
        second_time = second_update.last_used_at

        assert first_time is not None
        assert second_time is not None
        assert second_time > first_time


class TestMemoryBackendClose:
    """Tests for closing the backend."""

    @pytest.mark.asyncio
    async def test_memory_backend_close(self, memory_backend: MemoryBackend) -> None:
        """Test closing the backend clears all data."""
        # Create some keys
        for i in range(3):
            _, hashed_key = generate_api_key(f"test{i}_")
            key_info = APIKeyInfo(
                key_id=f"test-{i}",
                key_hash=hashed_key,
                name=f"Test Key {i}",
                scopes=["read"],
            )
            await memory_backend.create(hashed_key, key_info)

        # Verify keys exist
        keys = await memory_backend.list()
        assert len(keys) == 3

        # Close the backend
        await memory_backend.close()

        # Verify all data cleared
        keys = await memory_backend.list()
        assert len(keys) == 0


class TestMemoryBackendConfig:
    """Tests for MemoryConfig."""

    def test_memory_config_default(self) -> None:
        """Test default MemoryConfig values."""
        config = MemoryConfig()

        assert config.name == "memory"

    def test_memory_config_custom(self) -> None:
        """Test custom MemoryConfig values."""
        config = MemoryConfig(name="test_backend")

        assert config.name == "test_backend"

    def test_memory_backend_repr(self) -> None:
        """Test string representation of MemoryBackend."""
        backend = MemoryBackend(MemoryConfig(name="test"))
        repr_str = repr(backend)

        assert "MemoryBackend" in repr_str
        assert "test" in repr_str
        assert "keys=0" in repr_str


class TestMemoryBackendIntegration:
    """Integration tests for the memory backend."""

    @pytest.mark.asyncio
    async def test_complete_key_lifecycle(self, memory_backend: MemoryBackend) -> None:
        """Test complete lifecycle of an API key."""
        # Generate key
        raw_key, hashed_key = generate_api_key("app_")

        # Create key
        key_info = APIKeyInfo(
            key_id="lifecycle-test",
            key_hash=hashed_key,
            name="Lifecycle Test",
            scopes=["read", "write"],
        )
        created = await memory_backend.create(hashed_key, key_info)
        assert created.name == "Lifecycle Test"

        # Retrieve key
        retrieved = await memory_backend.get(hashed_key)
        assert retrieved is not None
        assert retrieved.name == "Lifecycle Test"

        # Update key
        updated = await memory_backend.update(hashed_key, name="Updated Name")
        assert updated is not None
        assert updated.name == "Updated Name"

        # Update last used
        await memory_backend.update_last_used(hashed_key)
        after_use = await memory_backend.get(hashed_key)
        assert after_use is not None
        assert after_use.last_used_at is not None

        # Revoke key
        revoked = await memory_backend.revoke(hashed_key)
        assert revoked is True

        # Verify revoked
        final = await memory_backend.get(hashed_key)
        assert final is not None
        assert final.is_active is False

        # Delete key
        deleted = await memory_backend.delete(hashed_key)
        assert deleted is True

        # Verify deleted
        not_found = await memory_backend.get(hashed_key)
        assert not_found is None

    @pytest.mark.asyncio
    async def test_concurrent_operations(self, memory_backend: MemoryBackend) -> None:
        """Test that concurrent operations are thread-safe."""
        import asyncio

        # Create multiple keys concurrently
        async def create_key(index: int) -> None:
            _, hashed_key = generate_api_key(f"concurrent{index}_")
            key_info = APIKeyInfo(
                key_id=f"concurrent-{index}",
                key_hash=hashed_key,
                name=f"Concurrent Key {index}",
                scopes=["read"],
            )
            await memory_backend.create(hashed_key, key_info)

        # Create 10 keys concurrently
        await asyncio.gather(*[create_key(i) for i in range(10)])

        # Verify all created
        keys = await memory_backend.list()
        assert len(keys) == 10
