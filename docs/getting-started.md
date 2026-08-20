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
from litestar_api_auth import mint_api_key

# Generate the key, build its record, and persist it in one call
raw_key, key_info = await mint_api_key(
    backend,
    name="My API Key",
    scopes=["read:users", "write:posts"],
    prefix="myapp_",
)

# Return raw_key to the user - this is the only time it's visible!
print(f"Your API key: {raw_key}")
```

`mint_api_key()` generates the key with the same hashing scheme the middleware
verifies against, derives a `key_id`, and calls `backend.create()` for you.
Building the `APIKeyInfo` record by hand and hashing yourself is possible (see
{func}`~litestar_api_auth.service.generate_api_key`) but is the usual source of
keys that never authenticate.

Optional expiry and metadata are passed through:

```python
from datetime import datetime, timedelta, timezone

raw_key, key_info = await mint_api_key(
    backend,
    name="Temporary key",
    scopes=["read:users"],
    prefix="myapp_",
    expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    metadata={"owner": "someone@example.com"},
)
```

## Production Setup

For production, use the SQLAlchemy backend with your existing database:

```python
from sqlalchemy.ext.asyncio import create_async_engine
from litestar import Litestar
from litestar_api_auth import APIAuthPlugin, APIAuthConfig
from litestar_api_auth.backends.sqlalchemy import SQLAlchemyBackend, SQLAlchemyConfig

# Create engine (use your actual database URL). hide_parameters=True keeps
# the stored key hash out of SQL logs if you ever enable echo/INFO-level
# engine logging -- see "Sensitive Data in SQL Logs" in the backends guide.
engine = create_async_engine(
    "postgresql+asyncpg://user:pass@localhost/myapp",
    hide_parameters=True,
)

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
| `auth_scheme` | `str \| None` | `None` | Scheme prefix required on the header value, e.g. `"Bearer"`. `None` means the whole header value is the key |
| `auto_routes` | `bool` | `True` | Auto-register management routes |
| `route_prefix` | `str` | `"/api-keys"` | Prefix for auto-registered routes |
| `management_guards` | `list[Guard]` | requires `api_keys:admin` scope | Guards applied to auto-registered management routes |
| `enable_openapi` | `bool` | `True` | Include auth in OpenAPI schema |
| `openapi_global_security` | `bool` | `False` | Also advertise the scheme as a document-wide security requirement, marking *every* documented route as key-authed |
| `track_usage` | `bool` | `True` | Update last_used_at on requests |

### Bearer Tokens

By default the entire value of `header_name` is treated as the key, which is
what `X-API-Key: <key>` needs. To accept a scheme-prefixed header instead, set
`auth_scheme`:

```python
APIAuthConfig(
    backend=backend,
    header_name="Authorization",
    auth_scheme="Bearer",  # accepts "Authorization: Bearer <key>"
)
```

The scheme match is case-insensitive. A header value *without* the prefix is
ignored entirely rather than being hashed and looked up, so a credential
belonging to another scheme in the same header (`Basic ...`, a JWT) is never
mistaken for an API key. The OpenAPI schema documents this configuration as an
HTTP bearer scheme rather than an `apiKey` header.

### OpenAPI Security Requirements

By default the plugin registers the `APIKeyAuth` security *scheme* and attaches
the security *requirement* only to the routes it actually guards (the
auto-registered management routes). Guards are opt-in per handler and the
middleware itself is fail-open, so marking every documented route as key-authed
would misrepresent an app whose routes are mostly public. If every route in your
app really does require a key, set `openapi_global_security=True` to also emit a
document-wide requirement.

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
