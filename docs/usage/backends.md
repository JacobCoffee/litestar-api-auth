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

The SQLAlchemy backend persists keys to a relational database. It supports
PostgreSQL, MySQL, SQLite, and any other database supported by SQLAlchemy.

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
