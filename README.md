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

The auto-registered management routes (create/list/get/revoke/delete under
`route_prefix`) require the `api_keys:admin` scope by default -- they let a
caller mint keys with arbitrary scopes, so they must never be open to
anonymous or low-privilege callers. Since a fresh deployment has no keys yet,
seed the first admin key out-of-band before relying on the API, e.g.:

```python
from litestar_api_auth import mint_api_key

raw_key, key_info = await mint_api_key(
    backend,
    name="bootstrap admin",
    scopes=["api_keys:admin"],
    prefix="myapp_",
)
# Store `raw_key` securely -- it is never retrievable again.
```

`mint_api_key()` is the single entry point for minting a key: it generates the
key, derives the `key_id`, builds the `APIKeyInfo` record and persists it via
`backend.create()`. Application code should never assemble the hash or the
struct by hand -- that is how a caller ends up hashing with a scheme the
middleware does not verify against.

To use a different policy, pass `management_guards=[...]` to `APIAuthConfig`.

### Bearer Tokens

Set `auth_scheme` to accept a scheme-prefixed header such as
`Authorization: Bearer <key>`:

```python
APIAuthConfig(
    backend=backend,
    header_name="Authorization",
    auth_scheme="Bearer",
)
```

The prefix match is case-insensitive, and a header value *without* the prefix
is ignored entirely rather than treated as a key -- so an unrelated credential
sharing the same header (`Basic ...`, a JWT under another scheme) can never
authenticate. The generated OpenAPI schema documents this as an HTTP bearer
scheme instead of an `apiKey` header. Leaving `auth_scheme` unset (the
default) keeps the plain `X-API-Key` behavior, where the whole header value is
the key.

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

# `APIKeyInfo` is the one record type the library uses: backends store it,
# the middleware puts it in `request.state.api_key`, and guards read it.
# `litestar_api_auth.types.APIKeyInfo` and
# `litestar_api_auth.backends.base.APIKeyInfo` are the same class.
key_info = APIKeyInfo(
    key_id="abc123",
    name="Production API Key",
    scopes=["read:users", "write:posts"],
    key_hash="...",  # sensitive: the stored verifier
    prefix="myapp_",
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
from litestar_api_auth.backends.sqlalchemy import SQLAlchemyBackend, SQLAlchemyConfig

engine = create_async_engine("postgresql+asyncpg://user:pass@localhost/db")
backend = SQLAlchemyBackend(config=SQLAlchemyConfig(engine=engine))
```

If the engine is owned and shared by the host application, pass
`dispose_engine=False` so closing the backend on shutdown does not tear down
connections the rest of the application still uses:

```python
backend = SQLAlchemyBackend(
    config=SQLAlchemyConfig(engine=app_engine, dispose_engine=False)
)
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
| `auth_scheme` | `str \| None` | `None` | Scheme prefix required on the header value, e.g. `"Bearer"`. `None` means the whole value is the key |
| `auto_routes` | `bool` | `True` | Auto-register management routes |
| `route_prefix` | `str` | `"/api-keys"` | Prefix for management routes |
| `management_guards` | `list[Guard]` | requires `api_keys:admin` scope | Guards applied to auto-registered management routes |
| `enable_openapi` | `bool` | `True` | Include auth in OpenAPI schema |
| `openapi_global_security` | `bool` | `False` | Also advertise the scheme as a document-wide security requirement (marks *every* route as key-authed) |
| `track_usage` | `bool` | `True` | Update last_used_at on requests |

## Documentation

Full documentation is available at [https://jacobcoffee.github.io/litestar-api-auth](https://jacobcoffee.github.io/litestar-api-auth)

## Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

MIT License - see [LICENSE](LICENSE) for details.
