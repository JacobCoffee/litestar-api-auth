# litestar-api-auth

> Pluggable API key authentication for Litestar applications

[![PyPI version](https://img.shields.io/pypi/v/litestar-api-auth.svg)](https://pypi.org/project/litestar-api-auth/)
[![Python versions](https://img.shields.io/pypi/pyversions/litestar-api-auth.svg)](https://pypi.org/project/litestar-api-auth/)
[![License](https://img.shields.io/github/license/JacobCoffee/litestar-api-auth.svg)](https://github.com/JacobCoffee/litestar-api-auth/blob/main/LICENSE)
[![Documentation](https://img.shields.io/badge/docs-latest-blue.svg)](https://jacobcoffee.github.io/litestar-api-auth)

## Features

- **Secure Key Generation**: API key generation with SHA-256 hashing
- **Configurable Prefixes**: Customizable key prefixes (e.g., `pyorg_`, `myapp_`)
- **Key Lifecycle Management**: Expiration and revocation support
- **Usage Tracking**: Last-used timestamp tracking for keys
- **Pluggable Backends**: SQLAlchemy, Redis, and in-memory storage backends
- **Route Protection**: Pre-built guards for securing endpoints
- **Auto-Registration**: Automatic management route registration
- **Scopes & Permissions**: Fine-grained key scopes and permissions system
- **OpenAPI Integration**: Automatic OpenAPI schema generation

## Installation

```bash
# Using uv (recommended)
uv add litestar-api-auth

# Using pip
pip install litestar-api-auth
```

### With Optional Dependencies

```bash
# With SQLAlchemy support
uv add litestar-api-auth[sqlalchemy]

# With Redis support
uv add litestar-api-auth[redis]

# All optional dependencies
uv add litestar-api-auth[all]
```

## Quick Start

### Basic Configuration

```python
from litestar import Litestar
from litestar_api_auth import APIAuthPlugin, APIAuthConfig
from litestar_api_auth.backends.memory import MemoryBackend

app = Litestar(
    plugins=[
        APIAuthPlugin(
            config=APIAuthConfig(
                backend=MemoryBackend(),  # Use SQLAlchemyBackend for production
                key_prefix="myapp_",
                header_name="X-API-Key",
                auto_routes=True,
                route_prefix="/api/v1/api-keys",
            )
        )
    ]
)
```

### Protecting Routes with Guards

```python
from litestar import get
from litestar_api_auth import require_api_key, require_scope

@get("/protected", guards=[require_api_key])
async def protected_route() -> dict:
    """Requires any valid API key."""
    return {"status": "authenticated"}

@get("/admin", guards=[require_scope("admin:write")])
async def admin_route() -> dict:
    """Requires an API key with the 'admin:write' scope."""
    return {"status": "admin access"}
```

### Working with API Keys

```python
from datetime import datetime, timedelta, timezone
from litestar_api_auth.types import APIKeyInfo

# API key information is available after authentication
key_info = APIKeyInfo(
    key_id="abc123",
    prefix="myapp_",
    name="Production API Key",
    scopes=["read:users", "write:posts"],
    created_at=datetime.now(timezone.utc),
    expires_at=datetime.now(timezone.utc) + timedelta(days=365),
    last_used_at=None,
    is_active=True,
    metadata={"owner": "admin@example.com"},
)

# Check key validity
if key_info.is_valid:
    print("Key is active and not expired")

# Check for specific scopes
if key_info.has_scope("read:users"):
    print("Key has read:users scope")

# Check for multiple scopes
if key_info.has_scopes(["read:users", "write:users"], requirement="all"):
    print("Key has all required scopes")
```

### Key States

API keys can be in one of three states:

| State | Description |
|-------|-------------|
| `ACTIVE` | Key is active and can be used for authentication |
| `EXPIRED` | Key has passed its expiration date |
| `REVOKED` | Key has been manually revoked |

## Storage Backends

### SQLAlchemy Backend

```python
from sqlalchemy.ext.asyncio import create_async_engine
from litestar_api_auth.backends.sqlalchemy import SQLAlchemyBackend

engine = create_async_engine("postgresql+asyncpg://user:pass@localhost/db")
backend = SQLAlchemyBackend(engine)
```

### Redis Backend

```python
from litestar_api_auth.backends.redis import RedisBackend

backend = RedisBackend(url="redis://localhost:6379/0")
```

### In-Memory Backend (Testing)

```python
from litestar_api_auth.backends.memory import MemoryBackend

backend = MemoryBackend()
```

## Error Handling

The library provides a comprehensive exception hierarchy:

```python
from litestar_api_auth.exceptions import (
    APIAuthError,           # Base exception for all auth errors
    APIKeyNotFoundError,    # Key does not exist
    APIKeyExpiredError,     # Key has expired
    APIKeyRevokedError,     # Key has been revoked
    InsufficientScopesError, # Key lacks required scopes
    InvalidAPIKeyError,     # Key format is invalid
    ConfigurationError,     # Plugin misconfiguration
)
```

### Example Error Handling

```python
from litestar import get
from litestar.exceptions import HTTPException
from litestar_api_auth.exceptions import (
    APIKeyExpiredError,
    InsufficientScopesError,
)

@get("/resource")
async def get_resource() -> dict:
    try:
        # ... authentication logic
        pass
    except APIKeyExpiredError as e:
        raise HTTPException(status_code=401, detail="API key has expired")
    except InsufficientScopesError as e:
        raise HTTPException(
            status_code=403,
            detail=f"Missing required scopes: {e.required_scopes}"
        )
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `backend` | `APIKeyBackend` | Required | Storage backend instance |
| `key_prefix` | `str` | `"pyorg_"` | Prefix for generated keys |
| `header_name` | `str` | `"X-API-Key"` | HTTP header name for API key |
| `auto_routes` | `bool` | `True` | Auto-register management routes |
| `route_prefix` | `str` | `"/api-keys"` | Prefix for management routes |
| `enable_openapi` | `bool` | `True` | Include auth in OpenAPI schema |
| `track_usage` | `bool` | `True` | Update last_used_at on requests |

## Documentation

Full documentation is available at [https://jacobcoffee.github.io/litestar-api-auth](https://jacobcoffee.github.io/litestar-api-auth)

## Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

MIT License - see [LICENSE](LICENSE) for details.
