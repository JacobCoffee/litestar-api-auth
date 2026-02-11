"""SQLAlchemy storage backend for API keys.

This backend stores API keys in a relational database using SQLAlchemy Core.
Supports PostgreSQL, MySQL, SQLite, and any other database supported by SQLAlchemy.

Note:
    This module requires the `sqlalchemy` optional dependency:
    `pip install litestar-api-auth[sqlalchemy]`
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from litestar_api_auth.backends.base import APIKeyInfo

if TYPE_CHECKING:
    from sqlalchemy import Table
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


def _build_api_keys_table(table_name: str, schema: str | None = None) -> Table:
    """Build the SQLAlchemy Table definition for API keys.

    Args:
        table_name: Name of the database table.
        schema: Optional database schema name.

    Returns:
        A SQLAlchemy Table object with columns matching APIKeyInfo fields.
    """
    from sqlalchemy import Boolean, Column, DateTime, Index, MetaData, String, Table, Text

    metadata = MetaData(schema=schema)
    table = Table(
        table_name,
        metadata,
        Column("key_id", String(length=255), nullable=False, unique=True),
        Column("key_hash", String(length=255), nullable=False, unique=True),
        Column("name", String(length=255), nullable=False),
        Column("scopes", Text, nullable=False, default="[]"),
        Column("is_active", Boolean, nullable=False, default=True),
        Column("created_at", DateTime(timezone=True), nullable=True),
        Column("expires_at", DateTime(timezone=True), nullable=True),
        Column("last_used_at", DateTime(timezone=True), nullable=True),
        Column("metadata_", Text, nullable=True),
    )
    Index("ix_api_keys_key_hash", table.c.key_hash)
    Index("ix_api_keys_key_id", table.c.key_id)
    return table


def _row_to_info(row: Any) -> APIKeyInfo:
    """Convert a database row mapping to an APIKeyInfo struct.

    Args:
        row: A SQLAlchemy row mapping from a query result.

    Returns:
        An APIKeyInfo instance populated from the row data.
    """
    scopes_raw = row["scopes"]
    scopes: list[str] = json.loads(scopes_raw) if isinstance(scopes_raw, str) else (scopes_raw or [])

    metadata_raw = row["metadata_"]
    metadata: dict[str, Any] | None = None
    if metadata_raw is not None:
        metadata = json.loads(metadata_raw) if isinstance(metadata_raw, str) else metadata_raw

    return APIKeyInfo(
        key_id=row["key_id"],
        key_hash=row["key_hash"],
        name=row["name"],
        scopes=scopes,
        is_active=row["is_active"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        last_used_at=row["last_used_at"],
        metadata=metadata,
    )


class SQLAlchemyBackend:
    """SQLAlchemy storage backend for API keys.

    This implementation stores API keys in a relational database using
    SQLAlchemy Core with an async engine. It supports all databases that
    SQLAlchemy supports.

    Features:
        - Async operations using SQLAlchemy's async engine
        - Automatic table creation on startup
        - Configurable table and schema names
        - Efficient queries with proper indexing on key_hash and key_id

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
            import sqlalchemy
        except ImportError as exc:
            msg = (
                "SQLAlchemy is required for SQLAlchemyBackend. "
                "Install it with: pip install litestar-api-auth[sqlalchemy]"
            )
            raise ImportError(msg) from exc

        self.config = config or SQLAlchemyConfig()
        self._engine = self.config.engine
        self._table: Table = _build_api_keys_table(
            table_name=self.config.table_name,
            schema=self.config.schema,
        )

    async def startup(self) -> None:
        """Initialize the backend on application startup.

        Creates the API keys table if it doesn't exist and create_tables is True.
        """
        if self.config.create_tables and self._engine is not None:
            await self._create_tables()

    async def _create_tables(self) -> None:
        """Create the API keys table if it doesn't exist.

        Uses ``run_sync`` to execute the synchronous ``metadata.create_all``
        within the async engine's connection context.
        """
        if self._engine is None:
            return

        async with self._engine.begin() as conn:
            await conn.run_sync(self._table.metadata.create_all)

    async def create(self, key_hash: str, info: APIKeyInfo) -> APIKeyInfo:
        """Create a new API key in the database.

        Args:
            key_hash: SHA-256 hash of the API key.
            info: Metadata about the API key.

        Returns:
            The created APIKeyInfo with any backend-generated fields populated.

        Raises:
            ValueError: If a key with the same hash or ID already exists.
        """
        if self._engine is None:
            msg = "Engine is not configured. Set config.engine before calling create()."
            raise RuntimeError(msg)

        from sqlalchemy.exc import IntegrityError

        created_at = info.created_at if info.created_at is not None else datetime.now(timezone.utc)

        try:
            async with self._engine.begin() as conn:
                await conn.execute(
                    self._table.insert().values(
                        key_id=info.key_id,
                        key_hash=key_hash,
                        name=info.name,
                        scopes=json.dumps(info.scopes),
                        is_active=info.is_active,
                        created_at=created_at,
                        expires_at=info.expires_at,
                        last_used_at=info.last_used_at,
                        metadata_=json.dumps(info.metadata) if info.metadata is not None else None,
                    )
                )
        except IntegrityError as exc:
            detail = str(exc.orig).lower()
            if "key_id" in detail:
                msg = f"API key with ID {info.key_id} already exists"
                raise ValueError(msg) from exc
            if "key_hash" in detail:
                msg = f"API key with hash {key_hash} already exists"
                raise ValueError(msg) from exc
            msg = "API key with the same hash or ID already exists"
            raise ValueError(msg) from exc

        return APIKeyInfo(
            key_id=info.key_id,
            key_hash=key_hash,
            name=info.name,
            scopes=info.scopes,
            is_active=info.is_active,
            created_at=created_at,
            expires_at=info.expires_at,
            last_used_at=info.last_used_at,
            metadata=info.metadata,
        )

    async def get(self, key_hash: str) -> APIKeyInfo | None:
        """Retrieve an API key by its hash.

        Args:
            key_hash: SHA-256 hash of the API key.

        Returns:
            The APIKeyInfo if found, None otherwise.
        """
        if self._engine is None:
            return None

        from sqlalchemy import select as sa_select

        async with self._engine.connect() as conn:
            result = await conn.execute(sa_select(self._table).where(self._table.c.key_hash == key_hash))
            row = result.mappings().first()
            if row is None:
                return None
            return _row_to_info(row)

    async def get_by_id(self, key_id: str) -> APIKeyInfo | None:
        """Retrieve an API key by its unique ID.

        Args:
            key_id: Unique identifier (UUID) of the key.

        Returns:
            The APIKeyInfo if found, None otherwise.
        """
        if self._engine is None:
            return None

        from sqlalchemy import select as sa_select

        async with self._engine.connect() as conn:
            result = await conn.execute(sa_select(self._table).where(self._table.c.key_id == key_id))
            row = result.mappings().first()
            if row is None:
                return None
            return _row_to_info(row)

    async def update(self, key_hash: str, **updates: Any) -> APIKeyInfo | None:
        """Update an API key's metadata.

        Args:
            key_hash: SHA-256 hash of the API key.
            **updates: Fields to update (name, scopes, is_active, etc.).

        Returns:
            The updated APIKeyInfo if found, None otherwise.
        """
        if self._engine is None:
            return None

        # Map Python field names to column values, serializing as needed
        column_updates: dict[str, Any] = {}
        for field, value in updates.items():
            if field == "scopes":
                column_updates["scopes"] = json.dumps(value)
            elif field == "metadata":
                column_updates["metadata_"] = json.dumps(value) if value is not None else None
            else:
                column_updates[field] = value

        if not column_updates:
            return await self.get(key_hash)

        async with self._engine.begin() as conn:
            result = await conn.execute(
                self._table.update().where(self._table.c.key_hash == key_hash).values(**column_updates)
            )
            if result.rowcount == 0:
                return None

        return await self.get(key_hash)

    async def delete(self, key_hash: str) -> bool:
        """Delete an API key from the database.

        Args:
            key_hash: SHA-256 hash of the API key.

        Returns:
            True if the key was deleted, False if not found.
        """
        if self._engine is None:
            return False

        async with self._engine.begin() as conn:
            result = await conn.execute(self._table.delete().where(self._table.c.key_hash == key_hash))
            return result.rowcount > 0  # type: ignore[return-value]

    async def list(
        self,
        *,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[APIKeyInfo]:
        """List API keys with pagination.

        Results are sorted by created_at descending (newest first), then by
        key_id descending as a secondary sort key for stable ordering when
        timestamps are identical.

        Args:
            limit: Maximum number of keys to return (None for all).
            offset: Number of keys to skip.

        Returns:
            List of APIKeyInfo objects sorted by creation date (newest first).
        """
        if self._engine is None:
            return []

        from sqlalchemy import select as sa_select

        query = (
            sa_select(self._table).order_by(self._table.c.created_at.desc(), self._table.c.key_id.desc()).offset(offset)
        )
        if limit is not None:
            query = query.limit(limit)

        async with self._engine.connect() as conn:
            result = await conn.execute(query)
            rows = result.mappings().all()
            return [_row_to_info(row) for row in rows]

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
