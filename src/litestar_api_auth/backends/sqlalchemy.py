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
from sqlalchemy import String, select
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
        dispose_engine: Whether ``SQLAlchemyBackend.close()`` disposes the
            engine (and its connection pool). Defaults to True, which suits an
            engine created solely for this backend. Set False when handing in
            an engine owned by the host application and shared with the rest of
            it -- otherwise the plugin's shutdown hook (see
            ``APIAuthPlugin._register_lifespan_handlers``, which calls
            ``close()``) tears down connections that other parts of the app
            still use.
    """

    engine: AsyncEngine | None = None
    table_name: str = "api_keys"
    schema: str | None = None
    create_tables: bool = True
    dispose_engine: bool = True


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

    Warning:
        ``key_hash`` is bound as a SQL parameter on every ``create()``,
        ``get()``, ``update()`` (and therefore ``revoke()`` /
        ``update_last_used()``), and ``delete()`` call. SQLAlchemy engines
        default to ``hide_parameters=False``, and this backend does not
        modify the logging configuration of the engine you pass in -- so a
        deployment that enables ``echo=True`` on ``create_async_engine()``,
        or raises the ``sqlalchemy.engine.Engine`` logger to ``INFO`` for
        debugging, writes the exact stored verifier for every key lookup,
        and for every ``update_last_used()`` call (when ``track_usage`` is
        enabled, the default), to its logs. Deployments that treat
        ``key_hash`` as sensitive must construct their own engine with
        ``hide_parameters=True`` and keep the effective
        ``sqlalchemy.engine.Engine`` logger at ``WARNING`` or higher (i.e.
        never enable ``INFO`` or ``DEBUG``) in any environment whose logs
        are persisted or shipped to a log aggregator.

        ``hide_parameters=True`` only redacts *bound statement parameters* --
        it does not touch *result rows*. ``get()`` and ``get_by_id()`` select
        the ``key_hash`` column back out of the table, so raising the engine
        to ``echo="debug"`` (SQLAlchemy's row-level echo mode, stronger than
        ``echo=True``) logs every fetched row -- ``key_hash`` included --
        regardless of ``hide_parameters``. Treat ``echo="debug"`` the same as
        ``echo=True``: never enable it, or the ``sqlalchemy.engine.Engine``
        logger at ``DEBUG``, in any environment whose logs are persisted or
        shipped to a log aggregator.
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
        # The repository's __init__ already built `self.statement` from the
        # class-level `model_type` (APIKeyModel) before the reassignment
        # above took effect, so it must be rebuilt against the configured
        # model or queries silently target the wrong table.
        svc.repository.statement = select(self._model)
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
            RuntimeError: If the engine is not configured, or if the insert
                fails due to a database error.
        """
        if self._sessionmaker is None:
            msg = "Engine is not configured. Set config.engine before calling create()."
            raise RuntimeError(msg)

        from advanced_alchemy.exceptions import DuplicateKeyError, IntegrityError, RepositoryError
        from sqlalchemy.exc import IntegrityError as SQLAlchemyIntegrityError

        created_at = info.created_at if info.created_at is not None else datetime.now(timezone.utc)

        # `error_to_raise` is raised *after* this try/except/else, rather than
        # from inside an `except` clause via `raise ... from None`: `from None`
        # only sets `__suppress_context__` (which standard traceback formatting
        # and Sentry's chain walker both honor), but leaves the caught exception
        # -- and, through it, key_hash as a bound SQL parameter on `__cause__`
        # -- reachable via `__context__` for anything that walks the raw
        # exception graph. Raising once the handler has exited leaves
        # `__context__` unset entirely, so there is nothing left to walk.
        error_to_raise: ValueError | RuntimeError | None = None
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
        except (IntegrityError, DuplicateKeyError) as exc:
            # These are Advanced Alchemy's own exception classes, not
            # SQLAlchemy's: ``APIKeyService.create`` wraps every underlying
            # ``sqlalchemy.exc`` failure via ``wrap_sqlalchemy_exception``
            # (``wrap_exceptions`` defaults to ``True`` and is never
            # overridden here), so a raw ``sqlalchemy.exc.IntegrityError``
            # never actually reaches this call site -- only the wrapped
            # ``IntegrityError``/``DuplicateKeyError`` do, chained (``from
            # exc``) to the original SQLAlchemy error as ``__cause__``.
            #
            # Crucially, that wrapper funnels *every* non-constraint
            # ``StatementError`` (e.g. ``OperationalError`` from a dropped
            # connection or lock timeout) into this same wrapped
            # ``IntegrityError`` class -- it is not exclusive to genuine
            # constraint violations. ``DuplicateKeyError`` is: Advanced
            # Alchemy only raises it from the branch that already confirmed
            # ``exc.__cause__`` is a real ``sqlalchemy.exc.IntegrityError``.
            # So a bare ``IntegrityError`` must still check its cause's
            # *type* (never its string contents -- that would risk
            # rendering key_hash) to tell an actual constraint violation
            # apart from a transient failure that only looks like one.
            if isinstance(exc, DuplicateKeyError) or isinstance(exc.__cause__, SQLAlchemyIntegrityError):
                detail = str(exc).lower()
                if "key_id" in detail:
                    error_to_raise = ValueError(f"API key with ID {info.key_id} already exists")
                elif "key_hash" in detail:
                    error_to_raise = ValueError("API key with this hash already exists")
                else:
                    error_to_raise = ValueError("API key with the same hash or ID already exists")
            else:
                error_to_raise = RuntimeError("Failed to create API key due to a database error")
        except RepositoryError:
            # Catches whatever ``wrap_sqlalchemy_exception`` wraps the
            # remaining failure modes into (a non-``IntegrityError``
            # ``InvalidRequestError``, or the catch-all ``RepositoryError``
            # for a bare ``SQLAlchemyError``/``AttributeError``) --
            # ``RepositoryError`` is the base of every class that wrapper
            # raises, so this is the backstop for anything not already
            # handled above.
            error_to_raise = RuntimeError("Failed to create API key due to a database error")
        else:
            return _model_to_info(result)

        raise error_to_raise

    async def get(self, key_hash: str) -> APIKeyInfo | None:
        """Retrieve an API key by its hash.

        Args:
            key_hash: SHA-256 hash of the API key.

        Returns:
            The APIKeyInfo if found, None otherwise.

        Raises:
            RuntimeError: If the lookup fails due to a database error.
        """
        if self._sessionmaker is None:
            return None

        from advanced_alchemy.exceptions import RepositoryError

        # See the comment in create() on why the RuntimeError below is raised
        # after this try/except/else instead of via `raise ... from None`
        # inside the `except` clause: that only suppresses the chain from
        # standard traceback formatting, it doesn't clear `__context__`.
        error_to_raise: RuntimeError | None = None
        try:
            async with self._sessionmaker() as session:
                svc = self._make_service(session)
                model = await svc.get_one_or_none(self._model.key_hash == key_hash)
        except RepositoryError:
            # SQLAlchemy engines default to hide_parameters=False, and the
            # engine is user-supplied so this library never sets it -- a
            # StatementError/OperationalError here (e.g. a dropped
            # connection or lock timeout) renders key_hash, the exact
            # stored verifier used for this lookup, as a bound SQL
            # parameter in str(exc). ``get_one_or_none`` never lets that raw
            # SQLAlchemy exception escape, though: it wraps every failure via
            # ``wrap_sqlalchemy_exception`` into an ``AdvancedAlchemyError``
            # subclass (``wrap_exceptions`` defaults to ``True`` and is never
            # overridden here), always chaining the original as
            # ``__cause__``. Catching ``sqlalchemy.exc.StatementError`` alone
            # would therefore never fire, and the hash would still reach a
            # formatted traceback via that chain.
            error_to_raise = RuntimeError("Failed to retrieve API key due to a database error")
        else:
            if model is None:
                return None
            return _model_to_info(model)

        raise error_to_raise

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

        Raises:
            RuntimeError: If the update fails due to a database error.
        """
        if self._sessionmaker is None:
            return None

        from sqlalchemy import bindparam, case, or_
        from sqlalchemy import update as sa_update
        from sqlalchemy.exc import StatementError

        # Map the "metadata" kwarg to the model's "metadata_" column
        update_data: dict[str, Any] = {}
        for field, value in updates.items():
            if field == "metadata":
                update_data["metadata_"] = value
            else:
                update_data[field] = value
        # Never let a caller reassign the surrogate primary key through this
        # generic field-update API -- key_hash is the only column that identifies
        # which row gets written below.
        update_data.pop("id", None)

        # last_used_at must never move backward. update_last_used() captures
        # datetime.now() before this UPDATE commits, so a slow request A can
        # race a faster, later-timestamped request B: if B's UPDATE commits
        # first, A's delayed UPDATE must not clobber B's newer value with its
        # own stale one -- see RedisBackend.update() for the same race. The
        # guard is expressed as a CASE inside the UPDATE's SET clause (rather
        # than a read-compare-write) so the write stays a single
        # UPDATE ... WHERE key_hash = :key_hash statement -- a read-then-write
        # split would reintroduce the ABA race described below.
        if "last_used_at" in update_data and update_data["last_used_at"] is not None:
            # Bind `incoming` explicitly as the column's own DateTimeUTC type.
            # Passing the bare Python datetime as the THEN value instead binds
            # it as a plain, untyped literal -- silently skipping DateTimeUTC's
            # UTC-normalizing bind processor for that one bind -- and the CASE
            # expression's own result type then gets inferred from that
            # untyped literal rather than from the compared column. A
            # non-UTC-offset (but still tz-aware) timestamp would then be
            # stored under its raw, un-normalized wall-clock value, defeating
            # the very guard being added here.
            incoming = bindparam("last_used_at_guard", update_data["last_used_at"], type_=self._model.last_used_at.type)
            update_data["last_used_at"] = case(
                (or_(self._model.last_used_at.is_(None), self._model.last_used_at < incoming), incoming),
                else_=self._model.last_used_at,
            )

        if not update_data:
            return await self.get(key_hash)

        async with self._sessionmaker() as session:
            # A single UPDATE ... WHERE key_hash = :key_hash keeps the write scoped
            # to the row identified by key_hash. A get-then-write-by-id split here
            # would be vulnerable to an ABA race: another key's row could be
            # deleted and replaced by a row that reuses the same primary key
            # (SQLite reuses rowids without AUTOINCREMENT) between the read and the
            # write, silently mutating the replacement key instead of this one.
            #
            # `RETURNING` is deliberately not used here: MySQL supports it for
            # neither UPDATE nor DELETE, and this backend targets PostgreSQL,
            # MySQL, and SQLite alike. The row is re-read by that same key_hash
            # (never by id) inside the same transaction instead -- but only once
            # `rowcount` confirms the UPDATE actually matched a row. Skipping that
            # check let a zero-match UPDATE (no row with this key_hash) fall
            # through to the re-read anyway: under READ COMMITTED, a concurrent
            # create() committing a row with this exact key_hash between the
            # UPDATE and the SELECT would make the SELECT observe that unrelated,
            # never-updated row as if it were this call's result -- e.g. letting
            # revoke() report a key as deactivated when the UPDATE never touched
            # it and it is still active.
            # error_to_raise is raised after this try/except/else -- see the
            # comment in create() on why: `raise ... from None` inside the
            # `except` clause would only suppress the chain from standard
            # traceback formatting, not clear `__context__` itself.
            error_to_raise: RuntimeError | None = None
            try:
                result = await session.execute(
                    sa_update(self._model).where(self._model.key_hash == key_hash).values(**update_data)
                )
                if result.rowcount == 0:
                    await session.rollback()
                    return None
                model = await session.scalar(select(self._model).where(self._model.key_hash == key_hash))
                if model is None:
                    await session.rollback()
                    return None
                # commit() is inside this try, not in an `else` after it, so a
                # commit-time failure (a dropped connection, lock timeout, or a
                # deferred constraint firing at COMMIT) is caught by the same
                # sanitizer below instead of escaping as a raw SQLAlchemy
                # exception -- matching delete(), which commits inside its try
                # for the same reason.
                await session.commit()
            except StatementError:
                # The UPDATE and SELECT above bind key_hash as a SQL parameter.
                # SQLAlchemy engines default to hide_parameters=False, and the
                # engine is user-supplied so this library never sets it, so an
                # unhandled StatementError/OperationalError here (e.g. a dropped
                # connection or lock timeout) would put the exact stored
                # verifier into a 500 response, logs, or an error reporter's
                # captured traceback. commit() itself carries no bound
                # parameters, but it must raise through this same sanitizer too
                # (as delete()'s commit does) so every DB failure in this method
                # -- not just the ones that happen to bind key_hash -- follows
                # the same RuntimeError contract.
                error_to_raise = RuntimeError("Failed to update API key due to a database error")
            else:
                return _model_to_info(model)

            raise error_to_raise

    async def delete(self, key_hash: str) -> bool:
        """Delete an API key from the database.

        Args:
            key_hash: SHA-256 hash of the API key.

        Returns:
            True if the key was deleted, False if not found.

        Raises:
            RuntimeError: If the delete fails due to a database error.
        """
        if self._sessionmaker is None:
            return False

        from sqlalchemy import delete as sa_delete
        from sqlalchemy.exc import StatementError

        async with self._sessionmaker() as session:
            # A single DELETE ... WHERE key_hash = :key_hash keeps the write scoped
            # to the row identified by key_hash -- see the comment in update() for
            # why a get-then-delete-by-id split is unsafe here, and why `RETURNING`
            # is avoided. `rowcount` is enough to know whether a row matched: unlike
            # an UPDATE whose new values might equal the old ones, a DELETE always
            # reports the row it removed.
            # error_to_raise is raised after this try/except/else -- see the
            # comment in create() on why: `raise ... from None` inside the
            # `except` clause would only suppress the chain from standard
            # traceback formatting, not clear `__context__` itself.
            error_to_raise: RuntimeError | None = None
            try:
                result = await session.execute(sa_delete(self._model).where(self._model.key_hash == key_hash))
                await session.commit()
            except StatementError:
                # The DELETE above binds key_hash as a SQL parameter.
                # SQLAlchemy engines default to hide_parameters=False, and
                # the engine is user-supplied so this library never sets
                # it, so an unhandled StatementError/OperationalError here
                # would put the exact stored verifier into a 500 response,
                # logs, or an error reporter's captured traceback.
                error_to_raise = RuntimeError("Failed to delete API key due to a database error")
            else:
                return result.rowcount > 0

            raise error_to_raise

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

    async def update_last_used(self, key_hash: str) -> APIKeyInfo | None:
        """Update the last_used_at timestamp for a key.

        Returns the freshly updated record when the key still exists, so
        callers can detect a concurrent revoke() (or an expiry shortened by
        a concurrent update()) that landed between their earlier get() and
        this call -- see ``APIKeyBackend.update_last_used``. A ``None``
        return is ambiguous: it also covers the key having been deleted
        concurrently, which is therefore not distinguishable this way.

        Args:
            key_hash: SHA-256 hash of the API key.

        Returns:
            The updated APIKeyInfo if found, None otherwise.
        """
        return await self.update(key_hash, last_used_at=datetime.now(timezone.utc))

    async def close(self) -> None:
        """Close the backend and release database connections.

        Disposes of the SQLAlchemy engine and its connection pool, unless
        ``SQLAlchemyConfig.dispose_engine`` is False -- in which case the
        engine is left untouched because the host application owns it and
        other parts of that application may still be using it. This is a
        no-op either way when no engine is configured.
        """
        if self._engine is not None and self.config.dispose_engine:
            await self._engine.dispose()

    def __repr__(self) -> str:
        """Return a string representation of the backend."""
        return f"SQLAlchemyBackend(table={self.config.table_name!r})"
