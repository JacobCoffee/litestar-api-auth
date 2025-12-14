"""SQLAlchemy storage backend for API keys.

This backend stores API keys in a relational database using SQLAlchemy.
Supports PostgreSQL, MySQL, SQLite, and any other database supported by SQLAlchemy.

Note:
    This module requires the `sqlalchemy` optional dependency:
    `pip install litestar-api-auth[sqlalchemy]`
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from litestar_api_auth.backends.base import APIKeyInfo

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine

__all__ = ("SQLAlchemyBackend", "SQLAlchemyConfig")


@dataclass
class SQLAlchemyConfig:
    """Configuration for the SQLAlchemy backend.

    Attributes:
        engine: The async SQLAlchemy engine to use for database operations.
        table_name: Name of the table to store API keys in.
        schema: Optional database schema name.
        create_tables: Whether to create tables on startup if they don't exist.
    """

    engine: AsyncEngine | None = None
    table_name: str = "api_keys"
    schema: str | None = None
    create_tables: bool = True


class SQLAlchemyBackend:
    """SQLAlchemy storage backend for API keys.

    This implementation stores API keys in a relational database using
    SQLAlchemy's async ORM. It supports all databases that SQLAlchemy supports.

    Features:
        - Async operations using SQLAlchemy's async session
        - Automatic table creation on startup
        - Configurable table and schema names
        - Efficient queries with proper indexing

    Example:
        ```python
        from sqlalchemy.ext.asyncio import create_async_engine
        from litestar_api_auth.backends.sqlalchemy import (
            SQLAlchemyBackend,
            SQLAlchemyConfig,
        )

        engine = create_async_engine("postgresql+asyncpg://...")
        backend = SQLAlchemyBackend(
            config=SQLAlchemyConfig(
                engine=engine,
                table_name="api_keys",
            )
        )
        ```

    Note:
        This backend requires the `sqlalchemy` optional dependency.
        Install with: `pip install litestar-api-auth[sqlalchemy]`
    """

    def __init__(self, config: SQLAlchemyConfig | None = None) -> None:
        """Initialize the SQLAlchemy backend.

        Args:
            config: Configuration for the backend.

        Raises:
            ImportError: If SQLAlchemy is not installed.
        """
        try:
            from sqlalchemy.ext.asyncio import AsyncSession
        except ImportError as exc:
            msg = (
                "SQLAlchemy is required for SQLAlchemyBackend. "
                "Install it with: pip install litestar-api-auth[sqlalchemy]"
            )
            raise ImportError(msg) from exc

        self.config = config or SQLAlchemyConfig()
        self._engine = self.config.engine
        self._table = None  # Lazy initialization

    async def startup(self) -> None:
        """Initialize the backend on application startup.

        Creates the API keys table if it doesn't exist and create_tables is True.
        """
        if self.config.create_tables and self._engine is not None:
            await self._create_tables()

    async def _create_tables(self) -> None:
        """Create the API keys table if it doesn't exist."""
        # TODO: Implement table creation using SQLAlchemy metadata

    async def create(self, key_hash: str, info: APIKeyInfo) -> APIKeyInfo:
        """Create a new API key in the database.

        Args:
            key_hash: SHA-256 hash of the API key.
            info: Metadata about the API key.

        Returns:
            The created APIKeyInfo with any backend-generated fields populated.

        Raises:
            ValueError: If a key with the same hash already exists.
        """
        # TODO: Implement database insert
        raise NotImplementedError("SQLAlchemy backend is not yet implemented")

    async def get(self, key_hash: str) -> APIKeyInfo | None:
        """Retrieve an API key by its hash.

        Args:
            key_hash: SHA-256 hash of the API key.

        Returns:
            The APIKeyInfo if found, None otherwise.
        """
        # TODO: Implement database query
        raise NotImplementedError("SQLAlchemy backend is not yet implemented")

    async def get_by_id(self, key_id: str) -> APIKeyInfo | None:
        """Retrieve an API key by its unique ID.

        Args:
            key_id: Unique identifier (UUID) of the key.

        Returns:
            The APIKeyInfo if found, None otherwise.
        """
        # TODO: Implement database query
        raise NotImplementedError("SQLAlchemy backend is not yet implemented")

    async def update(self, key_hash: str, **updates: Any) -> APIKeyInfo | None:
        """Update an API key's metadata.

        Args:
            key_hash: SHA-256 hash of the API key.
            **updates: Fields to update (name, scopes, is_active, etc.).

        Returns:
            The updated APIKeyInfo if found, None otherwise.
        """
        # TODO: Implement database update
        raise NotImplementedError("SQLAlchemy backend is not yet implemented")

    async def delete(self, key_hash: str) -> bool:
        """Delete an API key from the database.

        Args:
            key_hash: SHA-256 hash of the API key.

        Returns:
            True if the key was deleted, False if not found.
        """
        # TODO: Implement database delete
        raise NotImplementedError("SQLAlchemy backend is not yet implemented")

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
            List of APIKeyInfo objects sorted by creation date (newest first).
        """
        # TODO: Implement paginated database query
        raise NotImplementedError("SQLAlchemy backend is not yet implemented")

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
        """Close the backend and release database connections.

        Disposes of the SQLAlchemy engine and its connection pool.
        """
        if self._engine is not None:
            await self._engine.dispose()

    def __repr__(self) -> str:
        """Return a string representation of the backend."""
        return f"SQLAlchemyBackend(table={self.config.table_name!r})"
