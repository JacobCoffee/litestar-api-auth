# Scopes and Permissions

Scopes provide fine-grained access control for API keys.

## Scope Naming Conventions

Use a consistent naming pattern for scopes:

```
resource:action
```

Examples:
- `users:read` - Read user data
- `users:write` - Create or update users
- `users:delete` - Delete users
- `admin` - Administrative access
- `reports:generate` - Generate reports

## Creating Keys with Scopes

Assign scopes when creating API keys:

```python
from litestar_api_auth import APIKeyService

service = APIKeyService(backend=backend)

# Read-only key
read_key = await service.create_key(
    name="Read-Only Access",
    owner_id="user-123",
    scopes=["users:read", "reports:read"],
)

# Full access key
admin_key = await service.create_key(
    name="Admin Access",
    owner_id="admin-user",
    scopes=["admin", "users:read", "users:write", "users:delete"],
)
```

## Protecting Routes with Scopes

Use the `require_scope` guard:

```python
from litestar import get, post, delete
from litestar_api_auth import require_scope

@get("/api/users", guards=[require_scope("users:read")])
async def list_users() -> list:
    return []

@post("/api/users", guards=[require_scope("users:write")])
async def create_user(data: dict) -> dict:
    return data

@delete("/api/users/{user_id:str}", guards=[require_scope("users:delete")])
async def delete_user(user_id: str) -> None:
    pass
```

## Hierarchical Scopes

Implement hierarchical scopes where broader scopes include narrower ones:

```python
from litestar_api_auth import APIAuthConfig

config = APIAuthConfig(
    backend=backend,
    scope_hierarchy={
        "admin": ["users:read", "users:write", "users:delete", "reports:read"],
        "users:write": ["users:read"],  # write implies read
    },
)
```

With this configuration, a key with `admin` scope can access routes protected by `users:read`.

## Dynamic Scope Checking

Check scopes programmatically in your handlers:

```python
from litestar import get, Request
from litestar_api_auth import require_api_key, APIKey

@get("/api/data", guards=[require_api_key])
async def get_data(request: Request) -> dict:
    api_key: APIKey = request.state.api_key

    if "premium" in api_key.scopes:
        return {"data": "premium content", "extra": "bonus data"}

    return {"data": "basic content"}
```

## Scope Validation

Validate scopes against a predefined list:

```python
from litestar_api_auth import APIAuthConfig

VALID_SCOPES = {
    "users:read",
    "users:write",
    "users:delete",
    "reports:read",
    "reports:generate",
    "admin",
}

config = APIAuthConfig(
    backend=backend,
    valid_scopes=VALID_SCOPES,  # Raises error for unknown scopes
)
```

## Listing Available Scopes

Expose available scopes for API consumers:

```python
from litestar import get
from litestar_api_auth import require_scope

SCOPES = {
    "users:read": "Read user information",
    "users:write": "Create and update users",
    "users:delete": "Delete users",
    "reports:read": "View reports",
    "reports:generate": "Generate new reports",
    "admin": "Full administrative access",
}

@get("/api/scopes")
async def list_scopes() -> dict:
    """List all available API scopes."""
    return {"scopes": SCOPES}
```
