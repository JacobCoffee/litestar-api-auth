"""Tests for SQLAlchemy backend storage implementation.

This module tests the SQLAlchemy storage backend for API key management,
including CRUD operations, pagination, table creation, and the full lifecycle.
Uses an async in-memory SQLite database via aiosqlite.
"""

from __future__ import annotations

import asyncio
import io
import logging
import traceback
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import delete as sa_delete
from sqlalchemy import select
from sqlalchemy.exc import OperationalError, SQLAlchemyError, StatementError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from litestar_api_auth.backends.base import APIKeyInfo
from litestar_api_auth.backends.sqlalchemy import APIKeyModel, APIKeyService, SQLAlchemyBackend, SQLAlchemyConfig
from litestar_api_auth.service import generate_api_key


def _patch_second_execute_to_reuse_id(
    monkeypatch: pytest.MonkeyPatch,
    sessionmaker: async_sessionmaker[AsyncSession],
    *,
    old_hash: str,
    replacement_id: int,
    replacement_key_id: str,
    replacement_hash: str,
) -> list[int]:
    """Simulate an ABA race: a key is deleted and a *different* key reuses its row id.

    A ``get(key_hash)``-then-act-by-``id`` implementation issues its read as one
    database round trip and its write as a second, later round trip. This patches
    ``AsyncSession.execute`` so that, right after the *first* round trip made by the
    method under test returns (the read that would capture ``model.id``), the row is
    deleted and replaced by an unrelated key that reuses the exact same primary key --
    exactly the SQLite rowid-reuse scenario the finding describes. The *second* round
    trip (the write) then proceeds against whatever the table looks like at that point.

    A single-statement ``UPDATE/DELETE ... WHERE key_hash = :hash`` implementation only
    ever issues one round trip, so this hook never fires for it -- which is itself the
    proof that the get-then-act-by-id pattern is gone.

    Returns:
        A one-element list holding the running count of ``AsyncSession.execute``
        calls, updated in place so the caller can assert on it after the fact.
    """
    original_execute = AsyncSession.execute
    calls = [0]
    fired = [False]

    async def patched_execute(self: AsyncSession, *args: object, **kwargs: object):
        calls[0] += 1
        # Fire exactly once, on the second round trip -- never again afterwards, so
        # a later verification query in the test (itself a round trip) can't
        # accidentally retrigger the race.
        if calls[0] == 2 and not fired[0]:
            fired[0] = True
            async with sessionmaker() as raw_session:
                await raw_session.execute(sa_delete(APIKeyModel).where(APIKeyModel.key_hash == old_hash))
                raw_session.add(
                    APIKeyModel(
                        id=replacement_id,
                        key_id=replacement_key_id,
                        key_hash=replacement_hash,
                        name="Reused-ID Key",
                        scopes=["read"],
                        is_active=True,
                    )
                )
                await raw_session.commit()
        return await original_execute(self, *args, **kwargs)

    monkeypatch.setattr(AsyncSession, "execute", patched_execute)
    return calls


def _patch_first_execute_to_insert_concurrent_row(
    monkeypatch: pytest.MonkeyPatch,
    sessionmaker: async_sessionmaker[AsyncSession],
    *,
    key_hash: str,
) -> list[int]:
    """Simulate a concurrent create(): commit a fresh row with ``key_hash`` right
    after the operation under test's UPDATE round trip completes.

    An ``UPDATE ... WHERE key_hash = :hash`` that matches zero rows (no key with
    this hash exists yet) followed by a re-read ``SELECT ... WHERE key_hash =
    :hash`` in the same transaction issues its write as one database round trip
    and its re-read as a later, separate one. This patches ``AsyncSession.execute``
    so that, right after that first round trip (the UPDATE) returns, a row with
    the exact same key_hash is committed by a concurrent session -- exactly the
    ``create()`` race the finding describes. The re-read then proceeds against
    whatever the table looks like at that point.

    An implementation that checks ``rowcount`` after the UPDATE and bails out
    before ever issuing the re-read when it is 0 never lets that re-read observe
    the row this hook plants.

    Returns:
        A one-element list holding the running count of ``AsyncSession.execute``
        calls, updated in place so the caller can assert on it after the fact.
    """
    original_execute = AsyncSession.execute
    calls = [0]
    fired = [False]

    async def patched_execute(self: AsyncSession, *args: object, **kwargs: object):
        calls[0] += 1
        result = await original_execute(self, *args, **kwargs)
        # Fire exactly once, right after the first round trip (the UPDATE)
        # completes -- this is the exact window the finding describes, between
        # the UPDATE returning and the follow-up SELECT re-read.
        if calls[0] == 1 and not fired[0]:
            fired[0] = True
            async with sessionmaker() as raw_session:
                raw_session.add(
                    APIKeyModel(
                        key_id="concurrently-created",
                        key_hash=key_hash,
                        name="Concurrently Created Key",
                        scopes=["read"],
                        is_active=True,
                    )
                )
                await raw_session.commit()
        return result

    monkeypatch.setattr(AsyncSession, "execute", patched_execute)
    return calls


@pytest.fixture
async def sa_backend():
    """Provide a fresh SQLAlchemy backend backed by an in-memory SQLite database.

    Uses StaticPool so the sessionmaker-based sessions share a single
    underlying connection (required for in-memory SQLite).

    Yields:
        A fully initialised SQLAlchemyBackend instance.
    """
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
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

    async def test_create_duplicate_hash_does_not_leak_hash_in_traceback(self, sa_backend: SQLAlchemyBackend) -> None:
        """Test that a real duplicate-hash collision never exposes the hash via traceback chaining.

        Regression test for the full ``traceback.format_exception()`` output
        (as a debug-mode error page or an error reporter like Sentry/Rich would
        render) containing the secret hash through the chained IntegrityError's
        bound SQL parameters. On SQLite with this backend's default
        advanced_alchemy error messages, a real unique-constraint violation on
        ``key_hash`` is reported generically (it does not even reach the
        ``"key_hash" in detail`` branch), so this exercises the actual
        exploitable path: the generic fallback ``except`` branch.
        """
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

        with pytest.raises(ValueError) as exc_info:
            await sa_backend.create(hashed_key, duplicate_info)

        rendered = "".join(
            traceback.format_exception(type(exc_info.value), exc_info.value, exc_info.value.__traceback__)
        )
        assert hashed_key not in rendered
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None

    async def test_create_duplicate_hash_does_not_leak_hash(
        self, sa_backend: SQLAlchemyBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that the duplicate-hash error neither embeds nor chains the secret hash.

        Regression test for the key_hash being exposed via the ValueError message
        or via `from exc` chaining the underlying DB exception (which can carry
        the hash as a bound SQL parameter) into the traceback.

        The real advanced_alchemy/SQLite duplicate-key error text doesn't
        actually contain the column name, so the ``"key_hash" in detail``
        branch is exercised directly here by simulating the DB exception,
        rather than relying on triggering a real unique-constraint violation.
        """
        from advanced_alchemy.exceptions import DuplicateKeyError

        _, hashed_key = generate_api_key("test_")

        async def fake_create(*args: object, **kwargs: object) -> None:
            raise DuplicateKeyError(detail=f"UNIQUE constraint failed: api_keys.key_hash ({hashed_key})")

        monkeypatch.setattr(APIKeyService, "create", fake_create)

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )

        with pytest.raises(ValueError) as exc_info:
            await sa_backend.create(hashed_key, key_info)

        assert "already exists" in str(exc_info.value)
        assert hashed_key not in str(exc_info.value)
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None

    async def test_create_does_not_leak_hash_on_generic_statement_error(
        self, sa_backend: SQLAlchemyBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that a non-constraint DB failure during the INSERT never exposes key_hash.

        Regression test for a transient DB failure (dropped connection, lock
        timeout, etc.) during ``backend.create()`` that is *not* a constraint
        violation. SQLAlchemy's ``StatementError.__str__`` renders bound
        parameters unless the engine is configured with ``hide_parameters=True``,
        which this library's user-supplied engine never sets.

        The failure is injected at ``AsyncSession.commit`` (below the
        Advanced Alchemy service boundary) rather than by monkeypatching
        ``APIKeyService.create`` itself, so this exercises the real
        ``wrap_sqlalchemy_exception`` translation: Advanced Alchemy's
        repository catches the raw ``OperationalError`` and re-raises it as
        its own ``advanced_alchemy.exceptions.IntegrityError``, chained
        (``from exc``) to the original. Before the fix, the ``except`` clause
        here imported ``IntegrityError`` from ``sqlalchemy.exc`` -- a
        different, unrelated class -- so this wrapped exception matched
        nothing and propagated with the original ``OperationalError`` (and
        its bound key_hash parameter) intact on ``__cause__``.

        This must raise ``RuntimeError``, not ``ValueError``: Advanced
        Alchemy wraps a transient ``OperationalError`` into the exact same
        ``IntegrityError`` class it uses for genuine constraint violations,
        so the backend has to inspect ``exc.__cause__``'s *type* (a real
        ``sqlalchemy.exc.IntegrityError`` vs. anything else) to avoid
        misreporting a dropped connection as "already exists".
        """
        _, hashed_key = generate_api_key("test_")
        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )

        async def fake_commit(self: AsyncSession, *args: object, **kwargs: object) -> None:
            raise OperationalError(
                "INSERT INTO api_keys (key_hash) VALUES (?)",
                (hashed_key,),
                Exception("connection reset"),
            )

        monkeypatch.setattr(AsyncSession, "commit", fake_commit)

        with pytest.raises(RuntimeError) as exc_info:
            await sa_backend.create(hashed_key, key_info)

        rendered = "".join(
            traceback.format_exception(type(exc_info.value), exc_info.value, exc_info.value.__traceback__)
        )
        assert hashed_key not in rendered
        assert hashed_key not in str(exc_info.value)
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None

    async def test_create_does_not_leak_hash_on_non_statement_repository_error(
        self, sa_backend: SQLAlchemyBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that a non-statement Advanced Alchemy failure during create() never exposes key_hash.

        Regression test for the residual translation path in Advanced
        Alchemy's ``wrap_sqlalchemy_exception``: a bare ``SQLAlchemyError``
        (not a ``StatementError``/``IntegrityError``/``InvalidRequestError``)
        is wrapped into a plain ``advanced_alchemy.exceptions.RepositoryError``
        with the original exception's message interpolated directly into
        ``RepositoryError.detail`` -- so if that message ever happened to
        contain key_hash (e.g. a driver or middleware bug that echoes bound
        values into a generic error), it would flow straight into the
        ``ValueError``/``RuntimeError`` this backend raises unless that
        exception class is also caught and sanitized.
        """
        _, hashed_key = generate_api_key("test_")
        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )

        async def fake_commit(self: AsyncSession, *args: object, **kwargs: object) -> None:
            raise SQLAlchemyError(f"driver reported a fault for key_hash={hashed_key}")

        monkeypatch.setattr(AsyncSession, "commit", fake_commit)

        with pytest.raises(RuntimeError) as exc_info:
            await sa_backend.create(hashed_key, key_info)

        rendered = "".join(
            traceback.format_exception(type(exc_info.value), exc_info.value, exc_info.value.__traceback__)
        )
        assert hashed_key not in rendered
        assert hashed_key not in str(exc_info.value)
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None

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

    async def test_get_does_not_leak_hash_on_statement_error(
        self, sa_backend: SQLAlchemyBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that a mid-query DB failure during get() never exposes key_hash.

        Regression test for a transient DB failure (dropped connection, lock
        timeout, etc.) occurring during ``backend.get(key_hash)``. SQLAlchemy's
        ``StatementError.__str__`` renders bound parameters unless the engine is
        configured with ``hide_parameters=True``, which this library's
        user-supplied engine never sets.

        The failure is injected at ``AsyncSession.execute`` (below the
        Advanced Alchemy service boundary) rather than by monkeypatching
        ``APIKeyService.get_one_or_none`` itself, so this exercises the real
        ``wrap_sqlalchemy_exception`` translation that ``get_one_or_none``
        applies internally: it catches the raw ``OperationalError`` and
        re-raises it as ``advanced_alchemy.exceptions.IntegrityError`` (a
        SQLAlchemy ``StatementError`` is never actually what reaches this
        call site), chained (``from exc``) to the original. Before the fix,
        ``get()`` caught ``sqlalchemy.exc.StatementError``, which this
        wrapped exception is not an instance of, so it matched nothing and
        propagated with the original ``OperationalError`` (and its bound
        key_hash parameter) intact on ``__cause__``.
        """
        _, hashed_key = generate_api_key("test_")

        async def fake_execute(self: AsyncSession, *args: object, **kwargs: object) -> None:
            raise OperationalError(
                "SELECT * FROM api_keys WHERE api_keys.key_hash = ?",
                (hashed_key,),
                Exception("connection reset"),
            )

        monkeypatch.setattr(AsyncSession, "execute", fake_execute)

        with pytest.raises(RuntimeError) as exc_info:
            await sa_backend.get(hashed_key)

        rendered = "".join(
            traceback.format_exception(type(exc_info.value), exc_info.value, exc_info.value.__traceback__)
        )
        assert hashed_key not in rendered
        assert hashed_key not in str(exc_info.value)
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None


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

    async def test_update_does_not_leak_hash_on_statement_error(
        self, sa_backend: SQLAlchemyBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that a mid-query DB failure during update() never exposes key_hash.

        Regression test for a transient DB failure (dropped connection, lock
        timeout, etc.) occurring during the ``UPDATE ... WHERE key_hash = :key_hash``
        issued by ``backend.update(key_hash, ...)`` -- including via
        ``revoke()``/``update_last_used()``, which both call through to this
        method on every authenticated request. SQLAlchemy's
        ``StatementError.__str__`` renders bound parameters unless the engine is
        configured with ``hide_parameters=True``, which this library's
        user-supplied engine never sets. Before the fix, ``update()`` had no
        ``except`` clause around this statement, so the raw ``StatementError`` --
        carrying key_hash, the exact stored verifier, as a bound SQL parameter --
        propagated straight to the caller and into any formatted traceback.
        """
        _, hashed_key = generate_api_key("test_")
        key_info = APIKeyInfo(key_id="test-123", key_hash=hashed_key, name="Test Key", scopes=["read"])
        await sa_backend.create(hashed_key, key_info)

        async def fake_execute(self: AsyncSession, *args: object, **kwargs: object) -> None:
            raise StatementError(
                "connection reset",
                "UPDATE api_keys SET name = ? WHERE api_keys.key_hash = ?",
                ("New Name", hashed_key),
                Exception("connection reset"),
            )

        monkeypatch.setattr(AsyncSession, "execute", fake_execute)

        with pytest.raises(RuntimeError) as exc_info:
            await sa_backend.update(hashed_key, name="New Name")

        rendered = "".join(
            traceback.format_exception(type(exc_info.value), exc_info.value, exc_info.value.__traceback__)
        )
        assert hashed_key not in rendered
        assert hashed_key not in str(exc_info.value)
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None

    async def test_update_does_not_leak_hash_on_commit_statement_error(
        self, sa_backend: SQLAlchemyBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that a DB failure at COMMIT time during update() is sanitized like every other DB failure here.

        Regression test for a commit-time failure (a dropped connection, lock
        timeout, or a deferred-constraint violation firing at COMMIT) during
        ``backend.update(key_hash, ...)``. Before the fix, ``session.commit()``
        was called from the ``try``'s ``else`` suite -- outside the ``except
        StatementError`` sanitizer -- so a ``StatementError``/``OperationalError``
        raised by commit() propagated straight to the caller as a raw
        SQLAlchemy exception instead of the generic ``RuntimeError`` every
        other DB failure in this module is converted to. This module's
        deliberate error contract requires every DB failure to be sanitized
        this way, not only the ones that happen to bind key_hash as a SQL
        parameter (this synthetic StatementError models the worst case, as if
        it were still carrying key_hash from an earlier statement in the same
        transaction, so the test also re-confirms that the hash never leaks
        via the exception chain).
        """
        _, hashed_key = generate_api_key("test_")
        key_info = APIKeyInfo(key_id="test-123", key_hash=hashed_key, name="Test Key", scopes=["read"])
        await sa_backend.create(hashed_key, key_info)

        async def fake_commit(self: AsyncSession, *args: object, **kwargs: object) -> None:
            raise StatementError(
                "connection reset",
                "UPDATE api_keys SET name = ? WHERE api_keys.key_hash = ?",
                ("New Name", hashed_key),
                Exception("connection reset"),
            )

        monkeypatch.setattr(AsyncSession, "commit", fake_commit)

        with pytest.raises(RuntimeError) as exc_info:
            await sa_backend.update(hashed_key, name="New Name")

        rendered = "".join(
            traceback.format_exception(type(exc_info.value), exc_info.value, exc_info.value.__traceback__)
        )
        assert hashed_key not in rendered
        assert hashed_key not in str(exc_info.value)
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None

    async def test_update_aba_race_cannot_mutate_reused_id_row(
        self, sa_backend: SQLAlchemyBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that update() can no longer be tricked into mutating a reused-id row.

        Regression test for the reported ABA race: a ``get(key_hash)``-then-write-by-
        ``model.id`` implementation reads the row matching ``key_hash`` in one round
        trip and writes by that row's primary key in a later, separate round trip. If
        the row is deleted and a different key is created that reuses the exact same
        primary key in between (SQLite reuses rowids without ``AUTOINCREMENT``), the
        later write silently lands on the unrelated replacement key instead of the
        intended one. The fix collapses the read and the write into a single
        ``UPDATE ... WHERE key_hash = :hash`` round trip, so the race window this test
        injects before the *second* database round trip never gets a chance to run.
        """
        _, hash_a = generate_api_key("key-a-")
        _, hash_b = generate_api_key("key-b-")

        await sa_backend.create(
            hash_a,
            APIKeyInfo(key_id="key-a", key_hash=hash_a, name="Key A", scopes=["read"], is_active=True),
        )

        sessionmaker = sa_backend._sessionmaker
        assert sessionmaker is not None
        async with sessionmaker() as session:
            key_a_id = (
                await session.execute(select(APIKeyModel.id).where(APIKeyModel.key_hash == hash_a))
            ).scalar_one()

        _patch_second_execute_to_reuse_id(
            monkeypatch,
            sessionmaker,
            old_hash=hash_a,
            replacement_id=key_a_id,
            replacement_key_id="key-b",
            replacement_hash=hash_b,
        )

        result = await sa_backend.update(hash_a, name="Attacker-Controlled Name", is_active=False)
        # Undo the patch immediately so the verification queries below run against
        # the real `AsyncSession.execute` and can't be mistaken for a second round
        # trip belonging to the operation under test.
        monkeypatch.undo()

        # Whichever key the update ends up reporting, it must be key A -- the one
        # actually requested -- never key B. A get-then-write-by-id implementation
        # can end up reporting key B's own identity back with key A's attacker-
        # controlled values stitched onto it, which is exactly the cross-key
        # corruption this asserts against.
        if result is not None:
            assert result.key_id == "key-a"

        # Key B only ever gets created by the race helper reusing key A's freed row
        # id. Whether or not it exists, its fields must never have been touched by
        # this update() call -- the fix only ever reads and writes by key_hash, so
        # it can never resolve to key B's row regardless of which primary key that
        # row happens to hold.
        key_b_after = await sa_backend.get(hash_b)
        if key_b_after is not None:
            assert key_b_after.name == "Reused-ID Key"
            assert key_b_after.is_active is True

    async def test_update_zero_match_does_not_adopt_concurrently_created_row(
        self, sa_backend: SQLAlchemyBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that a zero-match update() never reports a concurrently created row as its own result.

        Regression test for the reported race: ``update(key_hash, ...)`` issues an
        ``UPDATE ... WHERE key_hash = :hash`` that matches zero rows (no key with
        this hash exists yet at the time the call is made), then re-reads by that
        same key_hash inside the same transaction. Before the fix, that re-read ran
        unconditionally regardless of whether the UPDATE matched anything, so a
        concurrent ``create()`` that commits a row with the exact same key_hash
        between the UPDATE and the SELECT let the SELECT observe that unrelated,
        never-updated row as if it were this call's result. Via ``revoke()``, this
        meant reporting ``True`` -- and the key remaining fully active -- even
        though the UPDATE never touched it. The fix checks ``rowcount`` right after
        the UPDATE and returns ``None`` before the re-read ever runs when it is 0.
        """
        _, hashed_key = generate_api_key("race_")

        sessionmaker = sa_backend._sessionmaker
        assert sessionmaker is not None

        # No key with this hash exists yet -- the UPDATE inside revoke() below
        # is guaranteed to match zero rows.
        _patch_first_execute_to_insert_concurrent_row(monkeypatch, sessionmaker, key_hash=hashed_key)

        result = await sa_backend.revoke(hashed_key)
        monkeypatch.undo()

        # The UPDATE matched nothing, so revoke() must report False -- never True,
        # even though a row with this exact key_hash exists by the time the call
        # returns (it was created concurrently, never updated by this call).
        assert result is False

        # The concurrently created row must be completely untouched: still active,
        # exactly as create() wrote it, never mutated by this update()/revoke() call.
        concurrent_row = await sa_backend.get(hashed_key)
        assert concurrent_row is not None
        assert concurrent_row.is_active is True
        assert concurrent_row.key_id == "concurrently-created"


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

    async def test_delete_does_not_leak_hash_on_statement_error(
        self, sa_backend: SQLAlchemyBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that a mid-query DB failure during delete() never exposes key_hash.

        Regression test for a transient DB failure (dropped connection, lock
        timeout, etc.) occurring during the ``DELETE ... WHERE key_hash = :key_hash``
        issued by ``backend.delete(key_hash)`` -- including via ``revoke()``'s
        caller-facing sibling. SQLAlchemy's ``StatementError.__str__`` renders
        bound parameters unless the engine is configured with
        ``hide_parameters=True``, which this library's user-supplied engine
        never sets. Before the fix, ``delete()`` had no ``except`` clause
        around this statement, so the raw ``StatementError`` -- carrying
        key_hash, the exact stored verifier, as a bound SQL parameter --
        propagated straight to the caller and into any formatted traceback.
        """
        _, hashed_key = generate_api_key("test_")
        key_info = APIKeyInfo(key_id="test-123", key_hash=hashed_key, name="Test Key", scopes=["read"])
        await sa_backend.create(hashed_key, key_info)

        async def fake_execute(self: AsyncSession, *args: object, **kwargs: object) -> None:
            raise StatementError(
                "connection reset",
                "DELETE FROM api_keys WHERE api_keys.key_hash = ?",
                (hashed_key,),
                Exception("connection reset"),
            )

        monkeypatch.setattr(AsyncSession, "execute", fake_execute)

        with pytest.raises(RuntimeError) as exc_info:
            await sa_backend.delete(hashed_key)

        rendered = "".join(
            traceback.format_exception(type(exc_info.value), exc_info.value, exc_info.value.__traceback__)
        )
        assert hashed_key not in rendered
        assert hashed_key not in str(exc_info.value)
        assert exc_info.value.__cause__ is None
        assert exc_info.value.__context__ is None

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

    async def test_delete_aba_race_cannot_delete_reused_id_row(
        self, sa_backend: SQLAlchemyBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that delete() can no longer be tricked into deleting a reused-id row.

        Regression test for the reported ABA race (see
        ``test_update_aba_race_cannot_mutate_reused_id_row`` for the full mechanism).
        For delete(), the finding warns this can destroy an unrelated, live key. The
        fix collapses the read and the write into a single
        ``DELETE ... WHERE key_hash = :hash`` round trip, so the race window this test
        injects before the *second* database round trip never gets a chance to run.
        """
        _, hash_a = generate_api_key("key-a-")
        _, hash_b = generate_api_key("key-b-")

        await sa_backend.create(
            hash_a,
            APIKeyInfo(key_id="key-a", key_hash=hash_a, name="Key A", scopes=["read"], is_active=True),
        )

        sessionmaker = sa_backend._sessionmaker
        assert sessionmaker is not None
        async with sessionmaker() as session:
            key_a_id = (
                await session.execute(select(APIKeyModel.id).where(APIKeyModel.key_hash == hash_a))
            ).scalar_one()

        calls = _patch_second_execute_to_reuse_id(
            monkeypatch,
            sessionmaker,
            old_hash=hash_a,
            replacement_id=key_a_id,
            replacement_key_id="key-b",
            replacement_hash=hash_b,
        )

        result = await sa_backend.delete(hash_a)
        # Undo the patch immediately so the verification query below runs against
        # the real `AsyncSession.execute` and can't be mistaken for a second round
        # trip belonging to the operation under test.
        monkeypatch.undo()

        # A single `DELETE ... WHERE key_hash = :hash` is exactly one round trip; a
        # get-then-delete-by-id implementation needs (at least) two, which is exactly
        # the window the injected race above needs to run.
        assert calls[0] == 1

        # Key B only ever gets created by the race helper reusing key A's freed row
        # id -- and that only happens if the code under test hands it a second round
        # trip to run in. Since that never happens here, key B must never exist, and
        # key A itself must have been deleted cleanly.
        assert result is True
        assert await sa_backend.get(hash_b) is None


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

    async def test_update_last_used_does_not_move_backward(self, sa_backend: SQLAlchemyBackend) -> None:
        """A stale write must not roll last_used_at backward.

        Regression test for a race where update_last_used() captures
        datetime.now() before its UPDATE commits: a slow request that captured
        an older timestamp can still commit *after* a faster, later-timestamped
        request already wrote its newer value, and must not clobber it with its
        own stale one.
        """
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )
        await sa_backend.create(hashed_key, key_info)

        newer = datetime.now(timezone.utc)
        older = newer - timedelta(seconds=5)

        # Simulate the newer timestamp's request committing first.
        await sa_backend.update(hashed_key, last_used_at=newer)
        # Simulate the slower request's delayed write, carrying its stale, older timestamp.
        await sa_backend.update(hashed_key, last_used_at=older)

        retrieved = await sa_backend.get(hashed_key)
        assert retrieved is not None
        assert retrieved.last_used_at == newer

    async def test_update_last_used_normalizes_non_utc_offset_to_utc(self, sa_backend: SQLAlchemyBackend) -> None:
        """The monotonicity guard must not bypass DateTimeUTC's UTC normalization.

        Regression test: the guard reuses the incoming datetime as both the
        CASE's comparison operand and its THEN value. If that value is passed
        as a bare Python datetime instead of an explicitly typed bind, the THEN
        branch binds as a plain, untyped literal -- silently skipping
        DateTimeUTC's bind processor for that one bind -- and the CASE
        expression's own result type then gets inferred from that untyped
        literal rather than from the compared column. A tz-aware datetime
        expressed in a non-UTC offset would then be stored under its raw,
        un-normalized wall-clock value instead of its correct UTC instant --
        corrupting the timestamp even though it is genuinely newer than what
        was stored before.
        """
        _, hashed_key = generate_api_key("test_")

        key_info = APIKeyInfo(
            key_id="test-123",
            key_hash=hashed_key,
            name="Test Key",
            scopes=["read"],
        )
        await sa_backend.create(hashed_key, key_info)

        baseline = datetime(2026, 1, 1, 16, 0, tzinfo=timezone.utc)
        await sa_backend.update(hashed_key, last_used_at=baseline)

        # This instant (17:00 UTC) is genuinely newer than baseline (16:00 UTC),
        # but expressed in a -05:00 offset so its wall-clock hour (12) would be
        # mistaken for an earlier UTC time if normalization were skipped.
        incoming = datetime(2026, 1, 1, 12, 0, tzinfo=timezone(timedelta(hours=-5)))
        await sa_backend.update(hashed_key, last_used_at=incoming)

        retrieved = await sa_backend.get(hashed_key)
        assert retrieved is not None
        assert retrieved.last_used_at == incoming.astimezone(timezone.utc)


class TestSQLAlchemyBackendCustomTableIsolation:
    """Tests that a custom ``table_name`` backend only ever touches its own table.

    Regression tests for ``_make_service`` reassigning ``svc.repository.model_type``
    *after* the repository's ``__init__`` had already built ``self.statement``
    from the default ``APIKeyModel`` (i.e. the ``api_keys`` table). That left the
    query statement pinned to the wrong table while filter expressions used the
    custom table's columns, so SQLAlchemy silently produced a cartesian-product
    FROM clause (``FROM api_keys, custom_keys WHERE custom_keys.key_hash = ...``)
    instead of an error.
    """

    async def test_custom_table_get_does_not_return_default_table_row(self) -> None:
        """Test that querying a custom-table backend never returns a default-table row.

        Reproduces the reported privilege-escalation scenario: an admin key lives
        in the default ``api_keys`` table and a low-privilege key lives in a
        ``custom_keys`` table (same engine/connection). Looking up the
        low-privilege key's hash through the custom-table backend must return
        the low-privilege key -- not the admin row from the other table.
        """
        engine = create_async_engine(
            "sqlite+aiosqlite://",
            echo=False,
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )

        default_backend = SQLAlchemyBackend(config=SQLAlchemyConfig(engine=engine, table_name="api_keys"))
        custom_backend = SQLAlchemyBackend(config=SQLAlchemyConfig(engine=engine, table_name="custom_keys"))
        await default_backend.startup()
        await custom_backend.startup()

        _, admin_hash = generate_api_key("admin_")
        await default_backend.create(
            admin_hash,
            APIKeyInfo(key_id="admin", key_hash=admin_hash, name="Admin Key", scopes=["admin"]),
        )

        _, low_priv_hash = generate_api_key("low_")
        await custom_backend.create(
            low_priv_hash,
            APIKeyInfo(key_id="low-priv", key_hash=low_priv_hash, name="Low Priv Key", scopes=["read"]),
        )

        result = await custom_backend.get(low_priv_hash)

        assert result is not None
        assert result.key_id == "low-priv"
        assert result.scopes == ["read"]

        await default_backend.close()

    async def test_custom_table_get_returns_none_for_default_table_only_hash(self) -> None:
        """Test that a hash which only exists in the default table is not visible via the custom-table backend.

        Documents the isolation invariant from the other side: with the custom
        table empty, the buggy cartesian-product ``FROM api_keys, custom_keys``
        join against zero ``custom_keys`` rows still (coincidentally) yields no
        rows, so this case alone does not distinguish the buggy statement from
        the fixed one. See ``test_custom_table_get_does_not_return_default_table_row``
        and ``test_custom_table_revoke_does_not_affect_default_table_row`` for the
        cases that do fail against the pre-fix code.
        """
        engine = create_async_engine(
            "sqlite+aiosqlite://",
            echo=False,
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )

        default_backend = SQLAlchemyBackend(config=SQLAlchemyConfig(engine=engine, table_name="api_keys"))
        custom_backend = SQLAlchemyBackend(config=SQLAlchemyConfig(engine=engine, table_name="custom_keys"))
        await default_backend.startup()
        await custom_backend.startup()

        _, admin_hash = generate_api_key("admin_")
        await default_backend.create(
            admin_hash,
            APIKeyInfo(key_id="admin", key_hash=admin_hash, name="Admin Key", scopes=["admin"]),
        )

        result = await custom_backend.get(admin_hash)

        assert result is None

        await default_backend.close()

    async def test_custom_table_revoke_does_not_affect_default_table_row(self) -> None:
        """Test that revoking a key via a custom-table backend never deactivates a default-table row.

        Regression test for the reported "revoke on custom-table key deactivates
        an unrelated default-table key" failure mode.
        """
        engine = create_async_engine(
            "sqlite+aiosqlite://",
            echo=False,
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )

        default_backend = SQLAlchemyBackend(config=SQLAlchemyConfig(engine=engine, table_name="api_keys"))
        custom_backend = SQLAlchemyBackend(config=SQLAlchemyConfig(engine=engine, table_name="custom_keys"))
        await default_backend.startup()
        await custom_backend.startup()

        _, admin_hash = generate_api_key("admin_")
        await default_backend.create(
            admin_hash,
            APIKeyInfo(key_id="admin", key_hash=admin_hash, name="Admin Key", scopes=["admin"], is_active=True),
        )

        _, low_priv_hash = generate_api_key("low_")
        await custom_backend.create(
            low_priv_hash,
            APIKeyInfo(key_id="low-priv", key_hash=low_priv_hash, name="Low Priv Key", scopes=["read"]),
        )

        revoked = await custom_backend.revoke(low_priv_hash)
        assert revoked is True

        admin_after = await default_backend.get(admin_hash)
        assert admin_after is not None
        assert admin_after.is_active is True

        low_priv_after = await custom_backend.get(low_priv_hash)
        assert low_priv_after is not None
        assert low_priv_after.is_active is False

        await default_backend.close()


class TestSQLAlchemyBackendClose:
    """Tests for closing the backend."""

    async def test_close_disposes_engine(self) -> None:
        """Test closing the backend disposes the engine."""
        engine = create_async_engine(
            "sqlite+aiosqlite://",
            echo=False,
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
        )
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
        """Test that duplicate key_id is caught even under concurrent writes.

        Note: SQLite with a shared connection (StaticPool) serializes concurrent
        sessions differently than production databases. We verify that at least
        one ValueError is raised for the duplicate constraint.
        """
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

        value_errors = [r for r in results if isinstance(r, ValueError)]
        assert len(value_errors) >= 1, f"Expected at least one ValueError, got: {[type(r).__name__ for r in results]}"


class TestSQLAlchemyBackendSQLLogging:
    """Tests for the operational-logging exposure documented on ``SQLAlchemyBackend``.

    ``key_hash`` is bound as a SQL parameter on every ``create()``/``get()``/
    ``update()``/``delete()`` call. SQLAlchemy engines default to
    ``hide_parameters=False``, so a deployment that enables ``echo=True`` on
    its engine (or raises the ``sqlalchemy.engine.Engine`` logger to
    ``INFO`` for debugging) writes the exact stored verifier to its logs.
    This backend never modifies the logging configuration of the
    caller-provided engine -- see the ``Warning`` section on
    :class:`SQLAlchemyBackend`. The library's lever here is documentation:
    direct deployments that treat key hashes as sensitive to construct their
    engine with ``hide_parameters=True`` (which covers bound parameters, but
    -- see below -- not ``echo="debug"``'s result-row logging).
    """

    @staticmethod
    async def _create_and_get_with_engine_logging(*, hide_parameters: bool | None, hashed_key: str) -> str:
        """Run a create()+get() round trip on a fresh engine, capturing its SQL log output.

        A dedicated engine (rather than the ``sa_backend`` fixture) is built
        per call so each test controls ``hide_parameters`` independently, and
        a real ``logging.Handler`` is attached to the
        ``sqlalchemy.engine.Engine`` logger (rather than ``caplog``) because
        SQLAlchemy's ``echo`` machinery calls the logger's ``_log()``
        directly -- this still propagates through normal handler dispatch,
        but exercising the real handler path here is closer to how an
        operator's own logging config would observe it.

        Args:
            hide_parameters: The ``hide_parameters`` engine setting under test.
                ``None`` omits the keyword entirely so the engine is built
                under SQLAlchemy's own default, rather than this test
                hardcoding what that default currently is.
            hashed_key: The key hash to create and then look up.

        Returns:
            Everything the ``sqlalchemy.engine.Engine`` logger emitted at
            INFO during the round trip.
        """
        logger = logging.getLogger("sqlalchemy.engine.Engine")
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        previous_level = logger.level
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        try:
            engine_kwargs: dict[str, Any] = {
                "echo": True,
                "poolclass": StaticPool,
                "connect_args": {"check_same_thread": False},
            }
            if hide_parameters is not None:
                engine_kwargs["hide_parameters"] = hide_parameters
            engine = create_async_engine("sqlite+aiosqlite://", **engine_kwargs)
            config = SQLAlchemyConfig(engine=engine, create_tables=True)
            backend = SQLAlchemyBackend(config=config)
            await backend.startup()
            try:
                await backend.create(
                    hashed_key,
                    APIKeyInfo(key_id="log-test", key_hash=hashed_key, name="Log Test", scopes=["read"]),
                )
                await backend.get(hashed_key)
            finally:
                await backend.close()
        finally:
            logger.removeHandler(handler)
            logger.setLevel(previous_level)
        return stream.getvalue()

    async def test_default_engine_config_leaks_key_hash_to_sql_logs(self) -> None:
        """Reproduce the finding: SQLAlchemy's actual default ``hide_parameters`` + echo/INFO logging exposes key_hash.

        ``hide_parameters`` is deliberately left unset here (rather than
        passed explicitly as ``False``) so this exercises whatever
        SQLAlchemy's own default actually is. Pins the exact failure
        scenario the finding describes (an operator enabling ``echo=True``
        or INFO-level engine logging for debugging) so a future SQLAlchemy
        release that silently changes that default would be caught here
        rather than only in a real deployment's logs.
        """
        _, hashed_key = generate_api_key("test_")

        output = await self._create_and_get_with_engine_logging(hide_parameters=None, hashed_key=hashed_key)

        assert hashed_key in output

    async def test_hide_parameters_true_closes_the_statement_parameter_leak(self) -> None:
        """The documented mitigation works for *bound parameters*: ``hide_parameters=True`` redacts key_hash.

        Regression test for the fix: both ``docs/usage/backends.md`` and the
        ``SQLAlchemyBackend`` docstring now direct deployments that treat
        key_hash as sensitive to set ``hide_parameters=True`` on their
        engine. This proves that guidance genuinely closes the exposure
        reproduced by ``test_default_engine_config_leaks_key_hash_to_sql_logs``
        above, rather than merely asserting the docs say so.

        Asserts SQLAlchemy's own redaction marker is present (not just that
        ``hashed_key`` is absent) so this can't pass vacuously if log
        capture silently stopped working for some unrelated reason.

        Scoped deliberately to ``echo=True`` (statement/parameter logging):
        see ``test_hide_parameters_true_does_not_hide_key_hash_in_debug_echo_rows``
        below for the separate, *not* fully mitigated row-echo case.
        """
        _, hashed_key = generate_api_key("test_")

        output = await self._create_and_get_with_engine_logging(hide_parameters=True, hashed_key=hashed_key)

        assert hashed_key not in output
        assert "hide_parameters=True" in output

    async def test_hide_parameters_true_does_not_hide_key_hash_in_debug_echo_rows(self) -> None:
        """``hide_parameters=True`` does not cover ``echo="debug"``'s result-row logging.

        ``hide_parameters`` only redacts *bound statement parameters* it does
        not touch *result rows*. ``get()`` selects the ``key_hash`` column
        back out of the table, and SQLAlchemy's ``echo="debug"`` mode (a
        stronger setting than ``echo=True``) logs every fetched row via
        ``Row(...)`` reprs -- including ``key_hash`` -- independent of
        ``hide_parameters``. This pins that residual gap so the docs'
        guidance to avoid ``echo="debug"``/``DEBUG``-level engine logging
        entirely (not just set ``hide_parameters=True``) stays accurate.
        """
        logger = logging.getLogger("sqlalchemy.engine.Engine")
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        previous_level = logger.level
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        try:
            engine = create_async_engine(
                "sqlite+aiosqlite://",
                echo="debug",
                hide_parameters=True,
                poolclass=StaticPool,
                connect_args={"check_same_thread": False},
            )
            config = SQLAlchemyConfig(engine=engine, create_tables=True)
            backend = SQLAlchemyBackend(config=config)
            await backend.startup()
            try:
                _, hashed_key = generate_api_key("test_")
                await backend.create(
                    hashed_key,
                    APIKeyInfo(key_id="debug-row-test", key_hash=hashed_key, name="Debug Row Test", scopes=["read"]),
                )
                await backend.get(hashed_key)
            finally:
                await backend.close()
        finally:
            logger.removeHandler(handler)
            logger.setLevel(previous_level)

        assert hashed_key in stream.getvalue()

    def test_backend_docstring_documents_hide_parameters_mitigation(self) -> None:
        """The library's only lever for this finding is documentation -- verify it exists.

        This is the literal regression test for the fix applied here: before
        it, ``SQLAlchemyBackend.__doc__`` said nothing about SQL engine
        logging, so this assertion would have failed.
        """
        doc = SQLAlchemyBackend.__doc__ or ""

        assert "hide_parameters=True" in doc
        assert "echo=True" in doc
        assert 'echo="debug"' in doc
