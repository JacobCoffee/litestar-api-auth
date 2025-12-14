# Guards and Authentication

This guide covers how to protect your routes using litestar-api-auth guards.

## Basic Authentication

The `require_api_key` guard ensures that a valid API key is present in the request:

```python
from litestar import get
from litestar_api_auth import require_api_key

@get("/api/data", guards=[require_api_key])
async def get_data() -> dict:
    """This route requires a valid API key."""
    return {"message": "Authenticated!"}
```

## Scope-Based Authorization

Use `require_scope` for fine-grained access control:

```python
from litestar import get, post, delete
from litestar_api_auth import require_scope

@get("/api/users", guards=[require_scope("users:read")])
async def list_users() -> list:
    """Requires 'users:read' scope."""
    return []

@post("/api/users", guards=[require_scope("users:write")])
async def create_user(data: dict) -> dict:
    """Requires 'users:write' scope."""
    return data

@delete("/api/users/{user_id:str}", guards=[require_scope("users:delete")])
async def delete_user(user_id: str) -> None:
    """Requires 'users:delete' scope."""
    pass
```

## Multiple Scopes

Require multiple scopes for a single route:

```python
from litestar_api_auth import require_all_scopes, require_any_scope

# Require ALL scopes
@delete("/api/admin/purge", guards=[require_all_scopes("admin", "dangerous:write")])
async def purge_data() -> None:
    """Requires both 'admin' AND 'dangerous:write' scopes."""
    pass

# Require ANY scope
@get("/api/reports", guards=[require_any_scope("reports:read", "admin")])
async def get_reports() -> list:
    """Requires either 'reports:read' OR 'admin' scope."""
    return []
```

## Accessing the API Key

Access the authenticated API key in your route handler:

```python
from litestar import get, Request
from litestar_api_auth import require_api_key, APIKey

@get("/api/whoami", guards=[require_api_key])
async def whoami(request: Request) -> dict:
    """Return information about the authenticated API key."""
    api_key: APIKey = request.state.api_key
    return {
        "key_id": api_key.id,
        "name": api_key.name,
        "owner_id": api_key.owner_id,
        "scopes": api_key.scopes,
    }
```

## Custom Guards

Create custom guards for specialized authentication logic:

```python
from litestar import Request
from litestar.connection import ASGIConnection
from litestar.handlers import BaseRouteHandler
from litestar_api_auth import APIKey
from litestar_api_auth.exceptions import InsufficientScopeError

def require_owner(connection: ASGIConnection, handler: BaseRouteHandler) -> None:
    """Ensure the API key owner matches the requested resource owner."""
    api_key: APIKey = connection.state.api_key
    resource_owner_id = connection.path_params.get("owner_id")

    if api_key.owner_id != resource_owner_id:
        raise InsufficientScopeError("You can only access your own resources")

@get("/api/users/{owner_id:str}/data", guards=[require_api_key, require_owner])
async def get_user_data(owner_id: str) -> dict:
    """Only accessible by the resource owner."""
    return {"owner_id": owner_id}
```

## Error Handling

Guards raise specific exceptions that you can handle:

```python
from litestar import Litestar, Response
from litestar_api_auth.exceptions import (
    InvalidAPIKeyError,
    ExpiredAPIKeyError,
    RevokedAPIKeyError,
    InsufficientScopeError,
)

async def handle_invalid_key(request, exc: InvalidAPIKeyError) -> Response:
    return Response(
        {"error": "Invalid API key"},
        status_code=401,
    )

async def handle_expired_key(request, exc: ExpiredAPIKeyError) -> Response:
    return Response(
        {"error": "API key has expired"},
        status_code=401,
    )

async def handle_insufficient_scope(request, exc: InsufficientScopeError) -> Response:
    return Response(
        {"error": "Insufficient permissions", "required": exc.required_scope},
        status_code=403,
    )

app = Litestar(
    exception_handlers={
        InvalidAPIKeyError: handle_invalid_key,
        ExpiredAPIKeyError: handle_expired_key,
        InsufficientScopeError: handle_insufficient_scope,
    },
)
```
