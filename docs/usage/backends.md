# Storage Backends

litestar-api-auth supports multiple storage backends for API key persistence.
Each backend implements the {class}`~litestar_api_auth.backends.base.APIKeyBackend` protocol
and stores {class}`~litestar_api_auth.backends.base.APIKeyInfo` structs.

## Memory Backend

The memory backend stores keys in a Python dictionary with an asyncio lock for
safe concurrent access. It is intended for development and testing only.

```python
from litestar_api_auth import APIAuthConfig
from litestar_api_auth.backends.memory import MemoryBackend, MemoryConfig

config = APIAuthConfig(
    backend=MemoryBackend(config=MemoryConfig(name="dev")),
    key_prefix="dev_",
)
```

You can also instantiate it with no arguments -- sensible defaults are applied:

```python
backend = MemoryBackend()  # MemoryConfig(name="memory") is used
```

```{warning}
Keys are lost when the application restarts. Do not use in production.
```

## SQLAlchemy Backend

The SQLAlchemy backend persists keys to a relational database. It is powered by
[Advanced Alchemy](https://docs.advanced-alchemy.litestar.dev/) and follows its
**Model → Repository → Service** architecture:

- **Model** ({class}`~litestar_api_auth.backends.sqlalchemy.APIKeyModel`) -- ORM model with `BigIntBase`
- **Repository** ({class}`~litestar_api_auth.backends.sqlalchemy.APIKeyRepository`) -- type-safe async data access
- **Service** ({class}`~litestar_api_auth.backends.sqlalchemy.APIKeyService`) -- business logic, automatic session/commit management, dict-to-model conversion

It supports PostgreSQL, MySQL, SQLite, and any other database supported by
SQLAlchemy.

Install the optional dependency first:

```bash
pip install litestar-api-auth[sqlalchemy]
```

Then configure the backend with a {class}`~litestar_api_auth.backends.sqlalchemy.SQLAlchemyConfig`:

```python
from sqlalchemy.ext.asyncio import create_async_engine
from litestar_api_auth import APIAuthConfig
from litestar_api_auth.backends.sqlalchemy import SQLAlchemyBackend, SQLAlchemyConfig

engine = create_async_engine("postgresql+asyncpg://user:pass@localhost/myapp")

config = APIAuthConfig(
    backend=SQLAlchemyBackend(
        config=SQLAlchemyConfig(
            engine=engine,
            table_name="api_keys",   # default
            create_tables=True,      # auto-create table on startup
        )
    ),
    key_prefix="prod_",
)
```

### Configuration Options

`SQLAlchemyConfig` accepts the following fields:

| Field           | Type                   | Default      | Description                                      |
|-----------------|------------------------|--------------|--------------------------------------------------|
| `engine`        | `AsyncEngine \| None`  | `None`       | The async SQLAlchemy engine for database access.  |
| `table_name`    | `str`                  | `"api_keys"` | Name of the table that stores API keys.           |
| `schema`        | `str \| None`          | `None`       | Optional database schema name.                    |
| `create_tables` | `bool`                 | `True`       | Create the table on startup if it does not exist. |

### Database Schema

The {class}`~litestar_api_auth.backends.sqlalchemy.APIKeyModel` ORM model extends
Advanced Alchemy's `BigIntBase`, which provides an auto-increment `id` primary key.
The remaining columns map directly to the fields on
{class}`~litestar_api_auth.backends.base.APIKeyInfo`:

| Column         | Type                          | Notes                                                    |
|----------------|-------------------------------|----------------------------------------------------------|
| `id`           | `BigInteger` (PK)             | Auto-increment primary key from `BigIntBase`.            |
| `key_id`       | `String(255)`                 | Unique, indexed. UUID identifier for the key.            |
| `key_hash`     | `String(255)`                 | Unique, indexed. SHA-256 hash of the raw key.            |
| `name`         | `String(255)`                 | Human-readable label.                                    |
| `scopes`       | `JsonB`                       | JSON array of permission scopes.                         |
| `is_active`    | `Boolean`                     | Defaults to `True`.                                      |
| `created_at`   | `DateTimeUTC` (nullable)      | Timezone-aware creation timestamp.                       |
| `expires_at`   | `DateTimeUTC` (nullable)      | Optional expiration timestamp.                           |
| `last_used_at` | `DateTimeUTC` (nullable)      | Updated on each authenticated request.                   |
| `metadata_`    | `JsonB` (nullable)            | Arbitrary key-value metadata. Maps to `metadata` on `APIKeyInfo`. |

`DateTimeUTC` and `JsonB` are portable Advanced Alchemy column types that
adapt automatically to each database dialect (e.g. native `jsonb` on PostgreSQL,
`JSON` on MySQL/SQLite).

### Advanced Usage: Model → Repository → Service

The SQLAlchemy backend is built on [Advanced Alchemy](https://docs.advanced-alchemy.litestar.dev/)
and exposes the full Model → Repository → Service stack for advanced customization:

- {class}`~litestar_api_auth.backends.sqlalchemy.APIKeyModel` -- the SQLAlchemy ORM model (extends `BigIntBase`)
- {class}`~litestar_api_auth.backends.sqlalchemy.APIKeyRepository` -- the async repository (extends `SQLAlchemyAsyncRepository`)
- {class}`~litestar_api_auth.backends.sqlalchemy.APIKeyService` -- the async service (extends `SQLAlchemyAsyncRepositoryService`)

The **service** layer sits on top of the repository and adds:
- Automatic session and transaction management (commits, rollbacks)
- Dict-to-model conversion (pass a `dict` instead of constructing a model)
- Unit-of-work pattern with `auto_commit` control
- A `match_fields` option for upsert-style operations

#### Subclassing the Model

Add custom columns, relationships, or constraints by subclassing
{class}`~litestar_api_auth.backends.sqlalchemy.APIKeyModel`:

```python
from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from litestar_api_auth.backends.sqlalchemy import APIKeyModel

class MyAPIKeyModel(APIKeyModel):
    """API key model with an owner relationship."""

    __tablename__ = "my_api_keys"

    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    owner: Mapped["User"] = relationship(lazy="joined")
```

#### Custom Repository with Additional Queries

Create a custom {class}`~litestar_api_auth.backends.sqlalchemy.APIKeyRepository`
subclass to add domain-specific query methods:

```python
from advanced_alchemy.filters import LimitOffset, OrderBy
from advanced_alchemy.repository import SQLAlchemyAsyncRepository
from litestar_api_auth.backends.sqlalchemy import APIKeyModel

class MyAPIKeyRepository(SQLAlchemyAsyncRepository[APIKeyModel]):
    """Repository with custom query helpers."""

    model_type = APIKeyModel

    async def find_by_scope(
        self,
        scope: str,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[APIKeyModel]:
        """Find active keys that contain a specific scope.

        Args:
            scope: The scope string to search for (e.g. ``"admin:write"``).
            limit: Maximum number of results.
            offset: Number of results to skip.

        Returns:
            List of matching APIKeyModel instances.
        """
        from sqlalchemy import cast, String as SAString

        return await self.list(
            APIKeyModel.is_active == True,  # noqa: E712
            cast(APIKeyModel.scopes, SAString).contains(scope),
            LimitOffset(limit=limit, offset=offset),
            OrderBy(field_name="created_at", sort_order="desc"),
        )

    async def find_expired(self) -> list[APIKeyModel]:
        """Find all keys that have passed their expiration date."""
        from datetime import datetime, timezone

        return await self.list(
            APIKeyModel.expires_at < datetime.now(timezone.utc),
            APIKeyModel.is_active == True,  # noqa: E712
        )
```

#### Using the Service Directly

{class}`~litestar_api_auth.backends.sqlalchemy.APIKeyService` wraps the repository
and adds automatic session management, dict-to-model conversion, and commit handling.
This is what the backend itself uses internally:

```python
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from litestar_api_auth.backends.sqlalchemy import APIKeyService

engine = create_async_engine("postgresql+asyncpg://...")
session_factory = async_sessionmaker(engine, expire_on_commit=False)

async with session_factory() as session:
    service = APIKeyService(session=session)

    # Create from a dict -- the service handles model construction
    new_key = await service.create(
        {"key_id": "abc-123", "key_hash": "sha256...", "name": "My Key", "scopes": ["read"]},
        auto_commit=True,
    )

    # Query with Advanced Alchemy filters
    from advanced_alchemy.filters import LimitOffset, OrderBy

    results = await service.list(
        LimitOffset(limit=20, offset=0),
        OrderBy(field_name="created_at", sort_order="desc"),
    )

    # Update by passing a dict with the item_id
    updated = await service.update(
        {"name": "Renamed Key", "id": new_key.id},
        item_id=new_key.id,
        auto_commit=True,
    )

    # Delete by primary key
    await service.delete(new_key.id, auto_commit=True)
```

#### Using the Repository Directly

For lower-level access without the service overhead, use
{class}`~litestar_api_auth.backends.sqlalchemy.APIKeyRepository` directly:

```python
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from litestar_api_auth.backends.sqlalchemy import APIKeyModel, APIKeyRepository

engine = create_async_engine("postgresql+asyncpg://...")
session_factory = async_sessionmaker(engine, expire_on_commit=False)

async with session_factory() as session:
    repo = APIKeyRepository(session=session)

    # Use Advanced Alchemy's built-in methods
    key = await repo.get_one_or_none(APIKeyModel.key_id == "some-uuid")

    # Paginate with Advanced Alchemy filters
    from advanced_alchemy.filters import LimitOffset, OrderBy

    keys = await repo.list(
        LimitOffset(limit=20, offset=0),
        OrderBy(field_name="created_at", sort_order="desc"),
    )
```

## Redis Backend

The Redis backend stores keys in Redis, making it a good fit for distributed
systems and high-performance applications that need fast key lookups.

Install the optional dependency first:

```bash
pip install litestar-api-auth[redis]
```

Then configure the backend with a {class}`~litestar_api_auth.backends.redis.RedisConfig`:

```python
from redis.asyncio import Redis
from litestar_api_auth import APIAuthConfig
from litestar_api_auth.backends.redis import RedisBackend, RedisConfig

redis_client = Redis.from_url("redis://localhost:6379/0")

config = APIAuthConfig(
    backend=RedisBackend(
        config=RedisConfig(
            client=redis_client,
            key_prefix="myapp:api_keys:",  # namespace keys in Redis
            ttl=None,                      # no automatic expiration
        )
    ),
    key_prefix="api_",
)
```

### Configuration Options

`RedisConfig` accepts the following fields:

| Field        | Type              | Default       | Description                                             |
|--------------|-------------------|---------------|---------------------------------------------------------|
| `client`     | `Redis \| None`   | `None`        | An async Redis client instance.                         |
| `key_prefix` | `str`             | `"api_key:"`  | Prefix for all Redis keys (useful for namespacing).     |
| `ttl`        | `int \| None`     | `None`        | Optional TTL in seconds for stored keys.                |

## Custom Backends

To build your own storage backend, implement the
{class}`~litestar_api_auth.backends.base.APIKeyBackend` protocol.
The protocol is decorated with `@runtime_checkable`, so structural (duck)
typing works -- you do not need to inherit from it explicitly.

Here is the full set of methods you must implement:

```python
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from litestar_api_auth.backends.base import APIKeyBackend, APIKeyInfo


class MyCustomBackend:
    """Custom storage backend implementing the APIKeyBackend protocol."""

    async def create(self, key_hash: str, info: APIKeyInfo) -> APIKeyInfo:
        """Store a new API key.

        Args:
            key_hash: SHA-256 hash of the raw API key.
            info: Metadata about the API key.

        Returns:
            The created APIKeyInfo.
        """
        ...

    async def get(self, key_hash: str) -> APIKeyInfo | None:
        """Retrieve an API key by its hash.

        Args:
            key_hash: SHA-256 hash of the raw API key.

        Returns:
            The APIKeyInfo if found, None otherwise.
        """
        ...

    async def get_by_id(self, key_id: str) -> APIKeyInfo | None:
        """Retrieve an API key by its unique ID.

        Args:
            key_id: UUID identifier of the key.

        Returns:
            The APIKeyInfo if found, None otherwise.
        """
        ...

    async def update(self, key_hash: str, **updates: Any) -> APIKeyInfo | None:
        """Update an API key's metadata.

        Args:
            key_hash: SHA-256 hash of the raw API key.
            **updates: Fields to update (name, scopes, is_active, etc.).

        Returns:
            The updated APIKeyInfo if found, None otherwise.
        """
        ...

    async def delete(self, key_hash: str) -> bool:
        """Delete an API key.

        Args:
            key_hash: SHA-256 hash of the raw API key.

        Returns:
            True if the key was deleted, False if not found.
        """
        ...

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
            List of APIKeyInfo objects.
        """
        ...

    async def revoke(self, key_hash: str) -> bool:
        """Revoke an API key (set is_active to False).

        Args:
            key_hash: SHA-256 hash of the raw API key.

        Returns:
            True if the key was revoked, False if not found.
        """
        ...

    async def update_last_used(self, key_hash: str) -> None:
        """Update the last_used_at timestamp for a key.

        Called automatically on each authenticated request when
        ``APIAuthConfig.track_usage`` is enabled.

        Args:
            key_hash: SHA-256 hash of the raw API key.
        """
        ...

    async def close(self) -> None:
        """Release any resources held by the backend.

        Called automatically when the Litestar application shuts down.
        """
        ...
```

You can verify that your class satisfies the protocol at runtime:

```python
assert isinstance(MyCustomBackend(), APIKeyBackend)
```

### The APIKeyInfo Struct

All backends store and return {class}`~litestar_api_auth.backends.base.APIKeyInfo`
instances. This is a `msgspec.Struct` with the following fields:

| Field          | Type                      | Default  | Description                                |
|----------------|---------------------------|----------|--------------------------------------------|
| `key_id`       | `str`                     | required | Unique identifier (UUID) for the key.      |
| `key_hash`     | `str`                     | required | SHA-256 hash of the raw API key.           |
| `name`         | `str`                     | required | Human-readable name for the key.           |
| `scopes`       | `list[str]`               | required | Permission scopes (e.g. `["read"]`).       |
| `is_active`    | `bool`                    | `True`   | Whether the key is currently active.       |
| `created_at`   | `datetime \| None`        | `None`   | When the key was created.                  |
| `expires_at`   | `datetime \| None`        | `None`   | When the key expires (None = no expiry).   |
| `last_used_at` | `datetime \| None`        | `None`   | When the key was last used.                |
| `metadata`     | `dict[str, Any] \| None`  | `None`   | Arbitrary key-value metadata.              |

`APIKeyInfo` also provides convenience methods:

- `is_expired` -- property that checks whether the key has passed its `expires_at`.
- `has_scope(scope)` -- returns `True` if the key has a specific scope.
- `has_scopes(scopes, requirement="all")` -- checks for multiple scopes. Set
  `requirement="any"` to require at least one match instead of all.
