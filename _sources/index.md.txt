# litestar-api-auth

Pluggable API key authentication for [Litestar](https://litestar.dev/) applications.

## What is litestar-api-auth?

litestar-api-auth provides a complete, production-ready API key authentication system for Litestar applications. It handles key generation, validation, storage, and access control so you can focus on building your API.

```python
from litestar import Litestar, get
from litestar_api_auth import APIAuthPlugin, APIAuthConfig, require_api_key

@get("/protected", guards=[require_api_key])
async def protected_route() -> dict:
    return {"status": "authenticated"}

app = Litestar(
    route_handlers=[protected_route],
    plugins=[APIAuthPlugin(config=APIAuthConfig())],
)
```

## Key Features

### Secure Key Generation

API keys are generated with cryptographic security and stored using SHA-256 hashing. Keys are only shown once at creation time.

```python
from litestar_api_auth import APIKeyService

service = APIKeyService(backend=backend)
api_key = await service.create_key(
    name="Production API Key",
    owner_id="user-123",
    scopes=["read", "write"],
)
# api_key.key is only available at creation time
print(f"Your API key: {api_key.key}")
```

### Configurable Key Prefixes

Identify your API keys at a glance with customizable prefixes:

```python
config = APIAuthConfig(
    key_prefix="myapp_",  # Keys look like: myapp_abc123...
)
```

### Multiple Storage Backends

Choose the backend that fits your architecture:

- **SQLAlchemy**: Production-ready with Advanced Alchemy integration
- **Redis**: High-performance caching and validation
- **Memory**: Perfect for testing and development

### Flexible Guards

Protect routes with simple guards or fine-grained scope requirements:

```python
from litestar_api_auth import require_api_key, require_scope

# Basic authentication
@get("/api/data", guards=[require_api_key])
async def get_data() -> dict:
    return {"data": "sensitive"}

# Scope-based authorization
@delete("/api/admin/users/{user_id:str}", guards=[require_scope("admin:delete")])
async def delete_user(user_id: str) -> None:
    ...
```

### Auto-Registered Routes

Get a complete API key management API out of the box:

```python
config = APIAuthConfig(
    auto_routes=True,
    route_prefix="/api/v1/api-keys",
)
# Automatically registers:
# POST   /api/v1/api-keys      - Create new key
# GET    /api/v1/api-keys      - List keys
# GET    /api/v1/api-keys/{id} - Get key details
# DELETE /api/v1/api-keys/{id} - Revoke key
```

### Expiration and Revocation

Built-in support for key lifecycle management:

```python
from datetime import timedelta

# Create key that expires in 30 days
api_key = await service.create_key(
    name="Temporary Access",
    owner_id="user-123",
    expires_in=timedelta(days=30),
)

# Revoke a key immediately
await service.revoke_key(key_id=api_key.id)
```

### Last-Used Tracking

Monitor API key usage for security auditing:

```python
key_info = await service.get_key(key_id)
print(f"Last used: {key_info.last_used_at}")
print(f"Total requests: {key_info.request_count}")
```

## Documentation Contents

```{toctree}
:maxdepth: 2
:caption: Getting Started

getting-started
```

```{toctree}
:maxdepth: 2
:caption: Usage

usage/guards
usage/backends
usage/scopes
```

```{toctree}
:maxdepth: 2
:caption: Reference

API Reference <api/index>
changelog
```

## Quick Links

- [Installation and Setup](getting-started.md)
- [Guards and Authentication](usage/guards.md)
- [Storage Backends](usage/backends.md)
- [Scopes and Permissions](usage/scopes.md)
- [API Reference](api/index.rst)
- [GitHub Repository](https://github.com/JacobCoffee/litestar-api-auth)
