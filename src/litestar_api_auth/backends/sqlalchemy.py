"""SQLAlchemy storage backend for API keys using Advanced Alchemy.

This backend stores API keys in a relational database using Advanced Alchemy's
Model → Repository → Service pattern. Supports PostgreSQL, MySQL, SQLite, and
any other database supported by SQLAlchemy.

Note:
    This module requires the ``sqlalchemy`` optional dependency:
    ``pip install litestar-api-auth[sqlalchemy]``
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, ClassVar

from advanced_alchemy.base import BigIntBase
from advanced_alchemy.repository import SQLAlchemyAsyncRepository
from advanced_alchemy.service import SQLAlchemyAsyncRepositoryService
from advanced_alchemy.types import DateTimeUTC, JsonB
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from litestar_api_auth.backends.base import APIKeyInfo

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

__all__ = ("APIKeyModel", "APIKeyRepository", "APIKeyService", "SQLAlchemyBackend", "SQLAlchemyConfig")


class _APIKeyModelBase(BigIntBase):
    """Abstract base for the API key ORM model.

    Columns are defined here so that subclasses with different ``__tablename__``
    values do not trigger SQLAlchemy joined-table inheritance.
    """

    __abstract__ = True

    key_id: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    key_hash: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    scopes: Mapped[list[Any]] = mapped_column(JsonB, default=list)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTimeUTC, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTimeUTC, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTimeUTC, nullable=True)
    metadata_: Mapped[dict[str, Any] | None] = mapped_column("metadata_", JsonB, nullable=True)


class APIKeyModel(_APIKeyModelBase):
    """SQLAlchemy ORM model for API keys.

    Uses Advanced Alchemy's ``BigIntBase`` which provides an auto-increment
    ``id`` primary key. The ``key_id`` and ``key_hash`` fields serve as the
    external identifiers.
    """

    __tablename__ = "api_keys"


_model_cache: dict[tuple[str, str | None], type[_APIKeyModelBase]] = {}


def _create_api_key_model(table_name: str, *, schema: str | None = None) -> type[_APIKeyModelBase]:
    """Create a concrete model class with a custom table name (and optional schema).

    Results are cached so that creating multiple backend instances with the same
    ``(table_name, schema)`` pair reuses the same model class, avoiding
    SQLAlchemy "already defined for this MetaData" errors.

    Args:
        table_name: Name of the database table.
        schema: Optional database schema name.

    Returns:
        A new (or cached) model class bound to the given table name.
    """
    cache_key = (table_name, schema)
    if cache_key in _model_cache:
        return _model_cache[cache_key]

    attrs: dict[str, Any] = {"__tablename__": table_name}
    if schema is not None:
        attrs["__table_args__"] = {"schema": schema}

    model = type(f"APIKeyModel_{table_name}", (_APIKeyModelBase,), attrs)
    _model_cache[cache_key] = model
    return model


class APIKeyRepository(SQLAlchemyAsyncRepository[APIKeyModel]):
    """Advanced Alchemy repository for API key data access.

    Handles all direct database operations. Subclass this to add custom
    query methods (e.g. ``find_by_scope``, ``find_expired``).
    """

    model_type = APIKeyModel


class APIKeyService(SQLAlchemyAsyncRepositoryService[APIKeyModel]):
    """Advanced Alchemy service for API key business logic.

    Sits on top of :class:`APIKeyRepository` and provides automatic session
    management, dict-to-model conversion, and a place for domain logic.

    The service is instantiated per-request with an async session and handles
    commits, rollbacks, and the unit-of-work pattern automatically.

    Example:
        ```python
        async with sessionmaker() as session:
            service = APIKeyService(session=session)
            model = await service.create({"key_id": "...", "name": "My Key", ...})
            results, count = await service.list_and_count(LimitOffset(10, 0))
        ```
    """

    repository_type = APIKeyRepository
    match_fields: ClassVar[list[str]] = ["key_id"]


def _model_to_info(model: _APIKeyModelBase) -> APIKeyInfo:
    """Convert an ORM model instance to an APIKeyInfo struct.

    Args:
        model: An APIKeyModel instance.

    Returns:
        An APIKeyInfo populated from the model.
    """
    return APIKeyInfo(
        key_id=model.key_id,
        key_hash=model.key_hash,
        name=model.name,
        scopes=list(model.scopes) if model.scopes else [],
        is_active=model.is_active,
        created_at=model.created_at,
        expires_at=model.expires_at,
        last_used_at=model.last_used_at,
        metadata=dict(model.metadata_) if model.metadata_ else None,
    )


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
    """SQLAlchemy storage backend for API keys using Advanced Alchemy.

    This implementation stores API keys in a relational database using
    Advanced Alchemy's Model → Repository → Service architecture. It supports
    all databases that SQLAlchemy supports.

    Internally, each backend method opens a session and delegates to
    :class:`APIKeyService` for the actual CRUD operation. The service handles
    commits and rollbacks automatically.

    Features:
        - Async operations using SQLAlchemy's async engine
        - Advanced Alchemy Model / Repository / Service for type-safe CRUD
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
        This backend requires the ``sqlalchemy`` optional dependency.
        Install with: ``pip install litestar-api-auth[sqlalchemy]``
    """

    def __init__(self, config: SQLAlchemyConfig | None = None) -> None:
        """Initialize the SQLAlchemy backend.

        Args:
            config: Configuration for the backend.
        """
        self.config = config or SQLAlchemyConfig()
        self._engine = self.config.engine
        self._sessionmaker: async_sessionmaker[AsyncSession] | None = None

        if self.config.table_name != "api_keys" or self.config.schema is not None:
            self._model = _create_api_key_model(self.config.table_name, schema=self.config.schema)
        else:
            self._model = APIKeyModel

        if self._engine is not None:
            self._init_sessionmaker()

    def _init_sessionmaker(self) -> None:
        """Create the async sessionmaker from the engine."""
        from sqlalchemy.ext.asyncio import async_sessionmaker as make_session

        self._sessionmaker = make_session(self._engine, expire_on_commit=False)

    def _make_service(self, session: AsyncSession) -> APIKeyService:
        """Create a service instance bound to the given session.

        Args:
            session: An async SQLAlchemy session.

        Returns:
            An APIKeyService for the configured model type.
        """
        svc = APIKeyService(session=session)
        svc.repository.model_type = self._model
        return svc

    async def startup(self) -> None:
        """Initialize the backend on application startup.

        Creates the API keys table if it doesn't exist and create_tables is True.
        """
        if self.config.create_tables and self._engine is not None:
            async with self._engine.begin() as conn:
                await conn.run_sync(self._model.metadata.create_all)

    async def create(self, key_hash: str, info: APIKeyInfo) -> APIKeyInfo:
        """Create a new API key in the database.

        Args:
            key_hash: SHA-256 hash of the API key.
            info: Metadata about the API key.

        Returns:
            The created APIKeyInfo with any backend-generated fields populated.

        Raises:
            ValueError: If a key with the same hash or ID already exists.
            RuntimeError: If the engine is not configured.
        """
        if self._sessionmaker is None:
            msg = "Engine is not configured. Set config.engine before calling create()."
            raise RuntimeError(msg)

        from advanced_alchemy.exceptions import DuplicateKeyError
        from sqlalchemy.exc import IntegrityError

        created_at = info.created_at if info.created_at is not None else datetime.now(timezone.utc)

        try:
            async with self._sessionmaker() as session:
                svc = self._make_service(session)
                result = await svc.create(
                    {
                        "key_id": info.key_id,
                        "key_hash": key_hash,
                        "name": info.name,
                        "scopes": list(info.scopes),
                        "is_active": info.is_active,
                        "created_at": created_at,
                        "expires_at": info.expires_at,
                        "last_used_at": info.last_used_at,
                        "metadata_": dict(info.metadata) if info.metadata is not None else None,
                    },
                    auto_commit=True,
                )
                return _model_to_info(result)
        except (IntegrityError, DuplicateKeyError) as exc:
            detail = str(exc).lower()
            if "key_id" in detail:
                msg = f"API key with ID {info.key_id} already exists"
                raise ValueError(msg) from exc
            if "key_hash" in detail:
                msg = f"API key with hash {key_hash} already exists"
                raise ValueError(msg) from exc
            msg = "API key with the same hash or ID already exists"
            raise ValueError(msg) from exc

    async def get(self, key_hash: str) -> APIKeyInfo | None:
        """Retrieve an API key by its hash.

        Args:
            key_hash: SHA-256 hash of the API key.

        Returns:
            The APIKeyInfo if found, None otherwise.
        """
        if self._sessionmaker is None:
            return None

        async with self._sessionmaker() as session:
            svc = self._make_service(session)
            model = await svc.get_one_or_none(self._model.key_hash == key_hash)
            if model is None:
                return None
            return _model_to_info(model)

    async def get_by_id(self, key_id: str) -> APIKeyInfo | None:
        """Retrieve an API key by its unique ID.

        Args:
            key_id: Unique identifier (UUID) of the key.

        Returns:
            The APIKeyInfo if found, None otherwise.
        """
        if self._sessionmaker is None:
            return None

        async with self._sessionmaker() as session:
            svc = self._make_service(session)
            model = await svc.get_one_or_none(self._model.key_id == key_id)
            if model is None:
                return None
            return _model_to_info(model)

    async def update(self, key_hash: str, **updates: Any) -> APIKeyInfo | None:
        """Update an API key's metadata.

        Args:
            key_hash: SHA-256 hash of the API key.
            **updates: Fields to update (name, scopes, is_active, etc.).

        Returns:
            The updated APIKeyInfo if found, None otherwise.
        """
        if self._sessionmaker is None:
            return None

        async with self._sessionmaker() as session:
            svc = self._make_service(session)
            model = await svc.get_one_or_none(self._model.key_hash == key_hash)
            if model is None:
                return None

            # Map the "metadata" kwarg to the model's "metadata_" column
            update_data: dict[str, Any] = {}
            for field, value in updates.items():
                if field == "metadata":
                    update_data["metadata_"] = value
                else:
                    update_data[field] = value

            update_data["id"] = model.id
            result = await svc.update(update_data, item_id=model.id, auto_commit=True)
            return _model_to_info(result)

    async def delete(self, key_hash: str) -> bool:
        """Delete an API key from the database.

        Args:
            key_hash: SHA-256 hash of the API key.

        Returns:
            True if the key was deleted, False if not found.
        """
        if self._sessionmaker is None:
            return False

        async with self._sessionmaker() as session:
            svc = self._make_service(session)
            model = await svc.get_one_or_none(self._model.key_hash == key_hash)
            if model is None:
                return False
            await svc.delete(model.id, auto_commit=True)
            return True

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
        if self._sessionmaker is None:
            return []

        from advanced_alchemy.filters import LimitOffset, OrderBy

        filters: list[LimitOffset | OrderBy] = [
            OrderBy(field_name="created_at", sort_order="desc"),
            OrderBy(field_name="key_id", sort_order="desc"),
        ]
        if limit is not None:
            filters.append(LimitOffset(limit=limit, offset=offset))

        async with self._sessionmaker() as session:
            svc = self._make_service(session)
            results = await svc.list(*filters)
            # When offset is requested without a limit, slice in Python to
            # avoid LIMIT -1 which is invalid on PostgreSQL/MySQL.
            if limit is None and offset > 0:
                results = results[offset:]
            return [_model_to_info(m) for m in results]

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
