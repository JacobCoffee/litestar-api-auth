# Getting Started

This guide covers installation, basic configuration, and your first steps with litestar-api-auth.

## Installation

### Base Package

Install the base package:

::::{tab-set}

:::{tab-item} uv
:sync: uv

```bash
uv add litestar-api-auth
```
:::

:::{tab-item} pip
:sync: pip

```bash
pip install litestar-api-auth
```
:::

:::{tab-item} pdm
:sync: pdm

```bash
pdm add litestar-api-auth
```
:::

::::

### With Storage Backends

Install optional dependencies for your preferred storage backend:

::::{tab-set}

:::{tab-item} uv
:sync: uv

**SQLAlchemy (Recommended)** - Persistent storage with your existing database:
```bash
uv add litestar-api-auth[sqlalchemy]
```

**Redis** - High-performance caching with fast key lookups:
```bash
uv add litestar-api-auth[redis]
```

**All Backends** - Install everything:
```bash
uv add litestar-api-auth[all]
```
:::

:::{tab-item} pip
:sync: pip

**SQLAlchemy (Recommended)** - Persistent storage with your existing database:
```bash
pip install litestar-api-auth[sqlalchemy]
```

**Redis** - High-performance caching with fast key lookups:
```bash
pip install litestar-api-auth[redis]
```

**All Backends** - Install everything:
```bash
pip install litestar-api-auth[all]
```
:::

:::{tab-item} pdm
:sync: pdm

**SQLAlchemy (Recommended)** - Persistent storage with your existing database:
```bash
pdm add litestar-api-auth[sqlalchemy]
```

**Redis** - High-performance caching with fast key lookups:
```bash
pdm add litestar-api-auth[redis]
```

**All Backends** - Install everything:
```bash
pdm add litestar-api-auth[all]
```
:::

::::

## Quick Start

### 1. Configure the Plugin

Add the `APIAuthPlugin` to your Litestar application:

```python
from litestar import Litestar
from litestar_api_auth import APIAuthPlugin, APIAuthConfig
from litestar_api_auth.backends.memory import MemoryBackend

# For development/testing, use the memory backend
app = Litestar(
    plugins=[
        APIAuthPlugin(
            config=APIAuthConfig(
                backend=MemoryBackend(),
                key_prefix="dev_",
                header_name="X-API-Key",
            )
        )
    ],
)
```

### 2. Protect Routes

Use guards to require API key authentication:

```python
from litestar import get
from litestar_api_auth import require_api_key

@get("/api/data", guards=[require_api_key])
async def get_data() -> dict:
    """This route requires a valid API key."""
    return {"message": "You have access!"}
```

### 3. Create API Keys

Use the service to create and manage API keys:

```python
from litestar_api_auth import generate_api_key
from litestar_api_auth.backends.base import APIKeyInfo

# Generate a new API key
raw_key, hashed_key = generate_api_key(prefix="myapp_")

# Create key info for storage
key_info = APIKeyInfo(
    key_id="unique-id",
    key_hash=hashed_key,
    name="My API Key",
    scopes=["read:users", "write:posts"],
)

# Store in backend
await backend.create(hashed_key, key_info)

# Return raw_key to the user - this is the only time it's visible!
print(f"Your API key: {raw_key}")
```

## Production Setup

For production, use the SQLAlchemy backend with your existing database:

```python
from sqlalchemy.ext.asyncio import create_async_engine
from litestar import Litestar
from litestar_api_auth import APIAuthPlugin, APIAuthConfig
from litestar_api_auth.backends.sqlalchemy import SQLAlchemyBackend, SQLAlchemyConfig

# Create engine (use your actual database URL)
engine = create_async_engine("postgresql+asyncpg://user:pass@localhost/myapp")

# Configure the plugin
app = Litestar(
    plugins=[
        APIAuthPlugin(
            config=APIAuthConfig(
                backend=SQLAlchemyBackend(
                    config=SQLAlchemyConfig(engine=engine)
                ),
                key_prefix="prod_",
                auto_routes=True,
                route_prefix="/api/v1/api-keys",
            )
        )
    ],
)
```

## Configuration Options

The `APIAuthConfig` class accepts the following options:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `backend` | `APIKeyBackend` | Required | Storage backend for API keys |
| `key_prefix` | `str` | `"pyorg_"` | Prefix for generated keys |
| `header_name` | `str` | `"X-API-Key"` | HTTP header for API key |
| `auto_routes` | `bool` | `True` | Auto-register management routes |
| `route_prefix` | `str` | `"/api-keys"` | Prefix for auto-registered routes |
| `enable_openapi` | `bool` | `True` | Include auth in OpenAPI schema |
| `track_usage` | `bool` | `True` | Update last_used_at on requests |

## Environment Variables

For sensitive configuration, use environment variables:

```python
import os
from litestar_api_auth import APIAuthConfig
from litestar_api_auth.backends.sqlalchemy import SQLAlchemyBackend, SQLAlchemyConfig

config = APIAuthConfig(
    backend=SQLAlchemyBackend(config=SQLAlchemyConfig(engine=engine)),
    key_prefix=os.environ.get("API_KEY_PREFIX", "api_"),
)
```

## Next Steps

- Learn about [guards and authentication](usage/guards.md)
- Configure [storage backends](usage/backends.md)
- Implement [scopes and permissions](usage/scopes.md)
- Browse the [API reference](api/index.rst)
