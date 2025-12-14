# Storage Backends

litestar-api-auth supports multiple storage backends for API key persistence.

## Memory Backend

The memory backend stores keys in memory. Perfect for development and testing:

```python
from litestar_api_auth import APIAuthConfig
from litestar_api_auth.backends.memory import MemoryBackend

config = APIAuthConfig(
    backend=MemoryBackend(),
    key_prefix="dev_",
)
```

```{warning}
Keys are lost when the application restarts. Do not use in production.
```

## SQLAlchemy Backend

The SQLAlchemy backend persists keys to your database. Recommended for production:

```python
from sqlalchemy.ext.asyncio import create_async_engine
from litestar_api_auth import APIAuthConfig
from litestar_api_auth.backends.sqlalchemy import SQLAlchemyBackend

engine = create_async_engine("postgresql+asyncpg://user:pass@localhost/myapp")

config = APIAuthConfig(
    backend=SQLAlchemyBackend(engine),
    key_prefix="prod_",
)
```

### Database Migrations

The backend will create the necessary tables automatically, or you can use Alembic:

```python
# In your Alembic env.py
from litestar_api_auth.models import APIKeyModel

target_metadata = APIKeyModel.metadata
```

### Advanced Alchemy Integration

For applications using Advanced Alchemy:

```python
from litestar_api_auth.contrib.sqlalchemy import SQLAlchemyRepository, SQLAlchemyService

# Use the repository directly
repo = SQLAlchemyRepository(session=session)
keys = await repo.list_by_owner(owner_id="user-123")
```

## Redis Backend

The Redis backend provides high-performance key validation with optional caching:

```python
import redis.asyncio as redis
from litestar_api_auth import APIAuthConfig
from litestar_api_auth.backends.redis import RedisBackend

redis_client = redis.from_url("redis://localhost:6379/0")

config = APIAuthConfig(
    backend=RedisBackend(redis_client),
    key_prefix="api_",
)
```

### Caching Layer

Use Redis as a cache in front of SQLAlchemy for high-traffic applications:

```python
from litestar_api_auth.backends.redis import RedisCacheBackend

config = APIAuthConfig(
    backend=RedisCacheBackend(
        redis=redis_client,
        primary=SQLAlchemyBackend(engine),
        ttl=300,  # Cache keys for 5 minutes
    ),
)
```

## Custom Backends

Implement the `Backend` protocol for custom storage:

```python
from typing import AsyncIterator
from litestar_api_auth.backends.base import Backend
from litestar_api_auth.models import APIKey

class MyCustomBackend(Backend):
    """Custom storage backend."""

    async def get_by_hash(self, key_hash: str) -> APIKey | None:
        """Retrieve a key by its hash."""
        ...

    async def create(self, api_key: APIKey) -> APIKey:
        """Store a new API key."""
        ...

    async def update(self, api_key: APIKey) -> APIKey:
        """Update an existing API key."""
        ...

    async def delete(self, key_id: str) -> None:
        """Delete an API key."""
        ...

    async def list_by_owner(self, owner_id: str) -> AsyncIterator[APIKey]:
        """List all keys for an owner."""
        ...
```
