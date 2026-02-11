"""Tests for SQLAlchemy backend storage implementation.

This module tests the SQLAlchemy storage backend for API key management,
including CRUD operations, pagination, table creation, and the full lifecycle.
Uses an async in-memory SQLite database via aiosqlite.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from litestar_api_auth.backends.base import APIKeyInfo
from litestar_api_auth.backends.sqlalchemy import SQLAlchemyBackend, SQLAlchemyConfig
from litestar_api_auth.service import generate_api_key


@pytest.fixture
async def sa_backend():
    """Provide a fresh SQLAlchemy backend backed by an in-memory SQLite database.

    Yields:
        A fully initialised SQLAlchemyBackend instance.
    """
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    config = SQLAlchemyConfig(engine=engine, table_name="api_keys", create_tables=True)
    backend = SQLAlchemyBackend(config=config)
    await backend.startup()
    yield backend
    await backend.close()


class TestSQLAlchemyBackendCreate:
    """Tests for creating API keys in the SQLAlchemy backend."""

    async def test_create(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test creating a new API key."""
        _raw_key, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read", "write"],
            is_active=True,
        )

        result = await sa_backend.create(hashed_key, key_info)

        assert result.key_id == "test-123"
        assert result.key_hash == hashed_key
        assert result.name == "Test Key"
        assert result.scopes == ["read", "write"]
        assert result.is_active is True
        assert result.created_at is not None

    async def test_create_duplicate_hash(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test that creating a key with duplicate hash raises error."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )
        await sa_backend.create(hashed_key, key_info)

        duplicate_info = APIKeyInfo(
            key_id="test-456",
            key_hash=hashed_key,
            name="Duplicate Key",
            scopes=["write"],
        )

        with pytest.raises(ValueError, match="already exists"):
            await sa_backend.create(hashed_key, duplicate_info)

    async def test_create_duplicate_id(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test that creating a key with duplicate ID raises error."""
        _, hashed_key1 = generate_api_key("test_")
        _, hashed_key2 = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="duplicate-id",
            key_hash=hashed_key1,
            name="First Key",
            scopes=["read"],
        )
        await sa_backend.create(hashed_key1, key_info)

        duplicate_info = APIKeyInfo(
            key_id="duplicate-id",
            key_hash=hashed_key2,
            name="Second Key",
            scopes=["write"],
        )

        with pytest.raises(ValueError, match="already exists"):
            await sa_backend.create(hashed_key2, duplicate_info)

    async def test_create_sets_created_at(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test that created_at is set if not provided."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
            created_at=None,
        )

        result = await sa_backend.create(hashed_key, key_info)

        assert result.created_at is not None
        now = datetime.now(timezone.utc)
        created = result.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        assert (now - created) < timedelta(minutes=1)

    async def test_create_with_metadata(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test creating a key with metadata."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-meta",
            key_hash=hashed_key,
            name="Meta Key",
            scopes=["read"],
            metadata={"owner": "admin@example.com", "env": "production"},
        )

        result = await sa_backend.create(hashed_key, key_info)

        assert result.metadata == {"owner": "admin@example.com", "env": "production"}

    async def test_create_with_expiry(self, sa_backend: SQLAlchemyBackend) -> None:
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

        result = await sa_backend.create(hashed_key, key_info)

        assert result.expires_at is not None


class TestSQLAlchemyBackendGet:
    """Tests for retrieving API keys from the SQLAlchemy backend."""

    async def test_get(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test retrieving an API key by hash."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )
        await sa_backend.create(hashed_key, key_info)

        result = await sa_backend.get(hashed_key)

        assert result is not None
        assert result.key_id == "test-123"
        assert result.name == "Test Key"
        assert result.scopes == ["read"]

    async def test_get_not_found(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test retrieving a non-existent key returns None."""
        result = await sa_backend.get("nonexistent_hash")

        assert result is None

    async def test_get_by_id(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test retrieving an API key by ID."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )
        await sa_backend.create(hashed_key, key_info)

        result = await sa_backend.get_by_id("test-123")

        assert result is not None
        assert result.key_hash == hashed_key
        assert result.name == "Test Key"

    async def test_get_by_id_not_found(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test retrieving by non-existent ID returns None."""
        result = await sa_backend.get_by_id("nonexistent-id")

        assert result is None

    async def test_get_preserves_metadata(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test that metadata round-trips correctly through JSON serialization."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-meta-rt",
            key_hash=hashed_key,
            name="Meta Key",
            scopes=["admin:read", "admin:write"],
            metadata={"nested": {"deep": True}, "count": 42},
        )
        await sa_backend.create(hashed_key, key_info)

        result = await sa_backend.get(hashed_key)

        assert result is not None
        assert result.metadata == {"nested": {"deep": True}, "count": 42}
        assert result.scopes == ["admin:read", "admin:write"]


class TestSQLAlchemyBackendUpdate:
    """Tests for updating API keys in the SQLAlchemy backend."""

    async def test_update(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test updating an API key's metadata."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Original Name",
            scopes=["read"],
        )
        await sa_backend.create(hashed_key, key_info)

        result = await sa_backend.update(hashed_key, name="Updated Name", scopes=["read", "write"])

        assert result is not None
        assert result.name == "Updated Name"
        assert result.scopes == ["read", "write"]
        assert result.key_id == "test-123"

    async def test_update_not_found(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test updating a non-existent key returns None."""
        result = await sa_backend.update("nonexistent_hash", name="New Name")

        assert result is None

    async def test_update_partial(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test partial update of key metadata."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Original Name",
            scopes=["read", "write"],
            metadata={"key": "value"},
        )
        await sa_backend.create(hashed_key, key_info)

        result = await sa_backend.update(hashed_key, name="New Name")

        assert result is not None
        assert result.name == "New Name"
        assert result.scopes == ["read", "write"]
        assert result.metadata == {"key": "value"}

    async def test_update_is_active(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test updating the is_active flag."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
            is_active=True,
        )
        await sa_backend.create(hashed_key, key_info)

        result = await sa_backend.update(hashed_key, is_active=False)

        assert result is not None
        assert result.is_active is False


class TestSQLAlchemyBackendDelete:
    """Tests for deleting API keys from the SQLAlchemy backend."""

    async def test_delete(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test deleting an API key."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )
        await sa_backend.create(hashed_key, key_info)

        result = await sa_backend.delete(hashed_key)

        assert result is True

        retrieved = await sa_backend.get(hashed_key)
        assert retrieved is None

    async def test_delete_not_found(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test deleting a non-existent key returns False."""
        result = await sa_backend.delete("nonexistent_hash")

        assert result is False

    async def test_delete_removes_from_id_lookup(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test that deletion means get_by_id also returns None."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )
        await sa_backend.create(hashed_key, key_info)
        await sa_backend.delete(hashed_key)

        result = await sa_backend.get_by_id("test-123")
        assert result is None


class TestSQLAlchemyBackendList:
    """Tests for listing API keys with pagination."""

    async def test_list_empty(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test listing keys when backend is empty."""
        result = await sa_backend.list()

        assert result == []

    async def test_list_all(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test listing all keys without pagination."""
        for i in range(5):
            _, hashed_key = generate_api_key(f"test{i}_")
            key_info = APIKeyInfo(
                key_id=f"test-{i}",
                key_hash=hashed_key,
                name=f"Test Key {i}",
                scopes=["read"],
            )
            await sa_backend.create(hashed_key, key_info)

        result = await sa_backend.list()

        assert len(result) == 5
        # Sorted by created_at desc, key_id desc -- newest first
        assert result[0].name == "Test Key 4"
        assert result[-1].name == "Test Key 0"

    async def test_list_with_limit(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test listing keys with limit."""
        for i in range(5):
            _, hashed_key = generate_api_key(f"test{i}_")
            key_info = APIKeyInfo(
                key_id=f"test-{i}",
                key_hash=hashed_key,
                name=f"Test Key {i}",
                scopes=["read"],
            )
            await sa_backend.create(hashed_key, key_info)

        result = await sa_backend.list(limit=3)

        assert len(result) == 3

    async def test_list_with_offset(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test listing keys with offset."""
        for i in range(5):
            _, hashed_key = generate_api_key(f"test{i}_")
            key_info = APIKeyInfo(
                key_id=f"test-{i}",
                key_hash=hashed_key,
                name=f"Test Key {i}",
                scopes=["read"],
            )
            await sa_backend.create(hashed_key, key_info)

        result = await sa_backend.list(offset=2)

        assert len(result) == 3
        assert result[0].name == "Test Key 2"

    async def test_list_with_limit_and_offset(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test listing keys with both limit and offset."""
        for i in range(10):
            _, hashed_key = generate_api_key(f"test{i}_")
            key_info = APIKeyInfo(
                key_id=f"test-{i}",
                key_hash=hashed_key,
                name=f"Test Key {i}",
                scopes=["read"],
            )
            await sa_backend.create(hashed_key, key_info)

        result = await sa_backend.list(limit=3, offset=2)

        assert len(result) == 3
        assert result[0].name == "Test Key 7"
        assert result[1].name == "Test Key 6"
        assert result[2].name == "Test Key 5"


class TestSQLAlchemyBackendRevoke:
    """Tests for revoking API keys."""

    async def test_revoke(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test revoking an API key."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
            is_active=True,
        )
        await sa_backend.create(hashed_key, key_info)

        result = await sa_backend.revoke(hashed_key)

        assert result is True

        retrieved = await sa_backend.get(hashed_key)
        assert retrieved is not None
        assert retrieved.is_active is False

    async def test_revoke_not_found(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test revoking a non-existent key returns False."""
        result = await sa_backend.revoke("nonexistent_hash")

        assert result is False

    async def test_revoke_already_revoked(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test revoking an already revoked key."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
            is_active=False,
        )
        await sa_backend.create(hashed_key, key_info)

        result = await sa_backend.revoke(hashed_key)

        assert result is True

        retrieved = await sa_backend.get(hashed_key)
        assert retrieved is not None
        assert retrieved.is_active is False


class TestSQLAlchemyBackendUpdateLastUsed:
    """Tests for updating last_used_at timestamp."""

    async def test_update_last_used(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test updating the last_used_at timestamp."""
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
            last_used_at=None,
        )
        await sa_backend.create(hashed_key, key_info)

        await sa_backend.update_last_used(hashed_key)

        retrieved = await sa_backend.get(hashed_key)
        assert retrieved is not None
        assert retrieved.last_used_at is not None

    async def test_update_last_used_multiple_times(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test updating last_used_at multiple times."""
        import asyncio

        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )
        await sa_backend.create(hashed_key, key_info)

        await sa_backend.update_last_used(hashed_key)
        first_update = await sa_backend.get(hashed_key)
        first_time = first_update.last_used_at

        await asyncio.sleep(0.01)

        await sa_backend.update_last_used(hashed_key)
        second_update = await sa_backend.get(hashed_key)
        second_time = second_update.last_used_at

        assert first_time is not None
        assert second_time is not None
        assert second_time >= first_time


class TestSQLAlchemyBackendClose:
    """Tests for closing the backend."""

    async def test_close_disposes_engine(self) -> None:
        """Test closing the backend disposes the engine."""
        engine = create_async_engine("sqlite+aiosqlite://", echo=False)
        config = SQLAlchemyConfig(engine=engine, create_tables=True)
        backend = SQLAlchemyBackend(config=config)
        await backend.startup()

        # Create a key to ensure the database is working
        _, hashed_key = generate_api_key("test_")
        key_info = APIKeyInfo(
            key_id="test-close",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )
        await backend.create(hashed_key, key_info)

        # Close the backend
        await backend.close()

        # Engine should be disposed; the pool is invalidated


class TestSQLAlchemyBackendConfig:
    """Tests for SQLAlchemyConfig."""

    def test_config_default(self) -> None:
        """Test default SQLAlchemyConfig values."""
        config = SQLAlchemyConfig()

        assert config.engine is None
        assert config.table_name == "api_keys"
        assert config.schema is None
        assert config.create_tables is True

    def test_config_custom(self) -> None:
        """Test custom SQLAlchemyConfig values."""
        engine = create_async_engine("sqlite+aiosqlite://")
        config = SQLAlchemyConfig(
            engine=engine,
            table_name="custom_keys",
            schema="auth",
            create_tables=False,
        )

        assert config.engine is engine
        assert config.table_name == "custom_keys"
        assert config.schema == "auth"
        assert config.create_tables is False

    def test_backend_repr(self) -> None:
        """Test string representation of SQLAlchemyBackend."""
        backend = SQLAlchemyBackend(SQLAlchemyConfig(table_name="my_keys"))
        repr_str = repr(backend)

        assert "SQLAlchemyBackend" in repr_str
        assert "my_keys" in repr_str


class TestSQLAlchemyBackendIntegration:
    """Integration tests for the SQLAlchemy backend."""

    async def test_complete_key_lifecycle(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test complete lifecycle of an API key."""
        _raw_key, hashed_key = generate_api_key("app_")

        # Create key
        key_info = APIKeyInfo(
            key_id="lifecycle-test",
            key_hash=hashed_key,
            name="Lifecycle Test",
            scopes=["read", "write"],
        )
        created = await sa_backend.create(hashed_key, key_info)
        assert created.name == "Lifecycle Test"

        # Retrieve key
        retrieved = await sa_backend.get(hashed_key)
        assert retrieved is not None
        assert retrieved.name == "Lifecycle Test"

        # Update key
        updated = await sa_backend.update(hashed_key, name="Updated Name")
        assert updated is not None
        assert updated.name == "Updated Name"

        # Update last used
        await sa_backend.update_last_used(hashed_key)
        after_use = await sa_backend.get(hashed_key)
        assert after_use is not None
        assert after_use.last_used_at is not None

        # Revoke key
        revoked = await sa_backend.revoke(hashed_key)
        assert revoked is True

        # Verify revoked
        final = await sa_backend.get(hashed_key)
        assert final is not None
        assert final.is_active is False

        # Delete key
        deleted = await sa_backend.delete(hashed_key)
        assert deleted is True

        # Verify deleted
        not_found = await sa_backend.get(hashed_key)
        assert not_found is None

    async def test_startup_without_engine(self) -> None:
        """Test that startup with no engine does not raise."""
        config = SQLAlchemyConfig(engine=None, create_tables=True)
        backend = SQLAlchemyBackend(config=config)
        # Should complete without error even with no engine
        await backend.startup()

    async def test_startup_create_tables_false(self) -> None:
        """Test that startup respects create_tables=False."""
        engine = create_async_engine("sqlite+aiosqlite://", echo=False)
        config = SQLAlchemyConfig(engine=engine, create_tables=False)
        backend = SQLAlchemyBackend(config=config)
        # Should not create tables; _create_tables should not be called
        await backend.startup()
        await backend.close()

    async def test_concurrent_duplicate_id_raises_value_error(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test concurrent create collisions are normalized to ValueError."""
        _, hashed_key1 = generate_api_key("test_")
        _, hashed_key2 = generate_api_key("test_")

        key1 = APIKeyInfo(
            key_id="concurrent-id",
            key_hash=hashed_key1,
            name="Concurrent One",
            scopes=["read"],
        )
        key2 = APIKeyInfo(
            key_id="concurrent-id",
            key_hash=hashed_key2,
            name="Concurrent Two",
            scopes=["write"],
        )

        results = await asyncio.gather(
            sa_backend.create(hashed_key1, key1),
            sa_backend.create(hashed_key2, key2),
            return_exceptions=True,
        )

        errors = [r for r in results if isinstance(r, Exception)]
        successes = [r for r in results if not isinstance(r, Exception)]
        assert len(successes) == 1
        assert len(errors) == 1
        assert isinstance(errors[0], ValueError)
