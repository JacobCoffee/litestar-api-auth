# Litestar API Auth Plugin Implementation

Complete implementation of the Litestar plugin for API key authentication.

## Files Created/Modified

### Core Plugin Files

1. **src/litestar_api_auth/plugin.py**
   - `APIAuthConfig` - Configuration dataclass for the plugin
   - `APIAuthPlugin` - Main plugin class implementing `InitPluginProtocol`
   - Handles middleware registration, route registration, dependency injection, lifespan hooks, and OpenAPI configuration

2. **src/litestar_api_auth/controllers.py**
   - `APIKeyController` - REST controller for API key management
   - Auto-registered routes for CRUD operations:
     - `POST /api-keys` - Create new API key
     - `GET /api-keys` - List all API keys (with pagination)
     - `GET /api-keys/{key_id}` - Get specific API key
     - `POST /api-keys/{key_id}/revoke` - Revoke a key
     - `DELETE /api-keys/{key_id}` - Delete a key
   - Request/Response models for API operations

3. **src/litestar_api_auth/__init__.py** (updated)
   - Added plugin, guards, middleware, and controller exports
   - Comprehensive public API

## Plugin Architecture

### 1. Configuration (`APIAuthConfig`)

```python
@dataclass
class APIAuthConfig:
    backend: APIKeyBackend              # Required: Storage backend
    key_prefix: str = "pyorg_"          # API key prefix
    header_name: str = "X-API-Key"      # Header to extract keys from
    auto_routes: bool = True            # Auto-register CRUD routes
    route_prefix: str = "/api-keys"     # URL prefix for routes
    exclude_paths: list[str] = [...]    # Paths to skip auth
    route_handlers: list = []           # Custom route handlers
    dependencies: dict = {}             # Custom dependencies
    enable_openapi: bool = True         # OpenAPI integration
    track_usage: bool = True            # Update last_used_at
```

### 2. Plugin Integration (`APIAuthPlugin`)

The plugin implements `InitPluginProtocol` and hooks into Litestar's application lifecycle via `on_app_init()`:

#### a) Dependency Registration

```python
def _register_dependencies(self, app_config: AppConfig) -> None:
    """Register backend as a dependency for injection."""
    # Makes backend available to route handlers
    app_config.dependencies["api_auth_backend"] = Provide(provide_backend)
```

#### b) Middleware Registration

```python
def _register_middleware(self, app_config: AppConfig) -> None:
    """Register API key extraction and validation middleware."""
    # Uses DefineMiddleware for proper ASGI middleware setup
    middleware = DefineMiddleware(
        APIKeyMiddleware,
        backend=self.config.backend,
        header_name=self.config.header_name,
        update_last_used=self.config.track_usage,
    )
    app_config.middleware.append(middleware)
```

The middleware:
- Extracts API keys from the configured header (default: `X-API-Key`)
- Validates keys against the backend
- Injects `APIKeyInfo` into `request.state.api_key`
- Updates `last_used_at` timestamp if enabled
- Does NOT enforce authentication (that's the guards' job)

#### c) Route Registration

```python
def _register_routes(self, app_config: AppConfig) -> None:
    """Register auto-generated CRUD routes."""
    controller = APIKeyController(
        backend=self.config.backend,
        route_prefix=self.config.route_prefix,
    )
    app_config.route_handlers.append(controller)
```

#### d) Lifespan Handlers

```python
def _register_lifespan_handlers(self, app_config: AppConfig) -> None:
    """Set up backend startup/shutdown hooks."""
    # Calls backend.startup() on app startup
    # Calls backend.close() on app shutdown
    # Preserves existing lifespan hooks
```

#### e) OpenAPI Configuration

```python
def _configure_openapi(self, app_config: AppConfig) -> None:
    """Configure OpenAPI security scheme."""
    # Adds API key security scheme to OpenAPI spec
    # Documents the X-API-Key header requirement
    # Adds security requirement to all routes
```

### 3. Controller Routes (`APIKeyController`)

Auto-registered REST endpoints for key management:

```python
POST /api-keys
  Request:  { name, scopes, prefix?, expires_at?, metadata? }
  Response: { key_id, key, name, scopes, created_at, expires_at }
  Note: Plaintext key only returned once!

GET /api-keys?limit=50&offset=0
  Response: { items: [...], total, limit, offset }

GET /api-keys/{key_id}
  Response: { key_id, name, scopes, is_active, created_at, expires_at, last_used_at, metadata }

POST /api-keys/{key_id}/revoke
  Response: 204 No Content

DELETE /api-keys/{key_id}
  Response: 204 No Content
```

## Usage Examples

### Basic Setup

```python
from litestar import Litestar, get
from litestar_api_auth import APIAuthPlugin, APIAuthConfig, require_api_key
from litestar_api_auth.backends.memory import MemoryBackend

@get("/protected", guards=[require_api_key])
async def protected_route() -> dict:
    return {"status": "authenticated"}

app = Litestar(
    route_handlers=[protected_route],
    plugins=[
        APIAuthPlugin(
            config=APIAuthConfig(
                backend=MemoryBackend(),
                key_prefix="myapp_",
                auto_routes=True,  # Enables /api-keys/* routes
            )
        )
    ],
)
```

### With Scope-Based Authorization

```python
from litestar_api_auth import require_scope, require_scopes

@get("/admin", guards=[require_scope("admin:write")])
async def admin_route() -> dict:
    return {"status": "admin access"}

@get("/data", guards=[require_scopes("read:public", "read:private", match="any")])
async def data_route() -> dict:
    return {"data": [...]}
```

### Accessing API Key Info in Handlers

```python
from litestar import Request
from litestar_api_auth import get_api_key_info, require_api_key

@get("/me", guards=[require_api_key])
async def get_current_key(request: Request) -> dict:
    key_info = get_api_key_info(request)
    return {
        "key_id": key_info.key_id,
        "scopes": key_info.scopes,
        "name": key_info.name,
    }
```

### Custom Configuration

```python
config = APIAuthConfig(
    backend=SQLAlchemyBackend(engine),
    key_prefix="prod_",
    header_name="X-API-Key",
    auto_routes=False,  # Disable auto-routes
    route_prefix="/api/v1/keys",  # Custom route prefix
    exclude_paths=["/health", "/metrics", "/schema"],
    track_usage=True,
    enable_openapi=True,
)
```

## Integration Points

### Backend Protocol

Backends must implement the `APIKeyBackend` protocol from `backends/base.py`:

```python
class APIKeyBackend(Protocol):
    async def create(key_hash: str, info: APIKeyInfo) -> APIKeyInfo
    async def get(key_hash: str) -> APIKeyInfo | None
    async def get_by_id(key_id: str) -> APIKeyInfo | None
    async def update(key_hash: str, **updates) -> APIKeyInfo | None
    async def delete(key_hash: str) -> bool
    async def list(limit: int, offset: int) -> list[APIKeyInfo]
    async def revoke(key_hash: str) -> bool
    async def update_last_used(key_hash: str) -> None
    async def close() -> None
```

### Middleware Integration

The middleware integrates with existing middleware:
- Extracts API keys from headers
- Validates against backend
- Stores result in `request.state.api_key`
- Does not block requests (guards handle enforcement)

### Guard Integration

Guards work with the middleware:
- `require_api_key` - Ensures valid API key present
- `require_scope(scope)` - Ensures specific scope
- `require_scopes(*scopes, match="all"|"any")` - Multiple scopes

### OpenAPI Integration

Automatically adds to OpenAPI spec:
- Security scheme: `apiKey` in `header`
- Security requirement on all routes
- Documented in Swagger UI

## Design Patterns

### 1. Plugin Pattern
- Implements `InitPluginProtocol`
- Hooks into `on_app_init` lifecycle
- Modifies `AppConfig` before app creation

### 2. Dependency Injection
- Backend registered as dependency
- Available to all route handlers
- Custom dependencies supported

### 3. Middleware Chain
- Uses `DefineMiddleware` for proper ASGI setup
- Non-blocking (doesn't enforce auth)
- Injects state for guards

### 4. Guard Pattern
- Separation of concerns (extraction vs enforcement)
- Reusable guards for common patterns
- Factory functions for parameterized guards

### 5. Lifespan Management
- Backend startup/shutdown hooks
- Preserves existing lifespan handlers
- Proper resource cleanup

## Backend Compatibility

The plugin is designed to work with any backend implementing the `APIKeyBackend` protocol:

- **MemoryBackend** - In-memory storage (testing)
- **SQLAlchemyBackend** - Database storage with Advanced Alchemy
- **RedisBackend** - Redis storage for distributed systems
- **Custom backends** - Any class implementing the protocol

## Testing

The plugin can be tested with the in-memory backend:

```python
from litestar.testing import TestClient
from litestar_api_auth import APIAuthPlugin, APIAuthConfig
from litestar_api_auth.backends.memory import MemoryBackend

def test_plugin():
    backend = MemoryBackend()

    app = Litestar(
        route_handlers=[...],
        plugins=[APIAuthPlugin(config=APIAuthConfig(backend=backend))],
    )

    with TestClient(app=app) as client:
        # Create key
        response = client.post("/api-keys", json={
            "name": "Test Key",
            "scopes": ["read", "write"],
        })
        key = response.json()["key"]

        # Use key
        response = client.get("/protected", headers={"X-API-Key": key})
        assert response.status_code == 200
```

## Security Considerations

1. **Key Storage**: Always store hashed keys (SHA-256)
2. **Key Transmission**: Use HTTPS in production
3. **Plaintext Exposure**: Keys only returned once at creation
4. **Scope Validation**: Guards enforce scope requirements
5. **Expiration**: Keys can have expiration dates
6. **Revocation**: Soft delete (revoke) vs hard delete
7. **Usage Tracking**: Optional last_used_at tracking

## Next Steps

1. Create backend implementations:
   - SQLAlchemy backend with Advanced Alchemy
   - Redis backend for distributed systems
   - In-memory backend for testing

2. Add service layer:
   - Key generation utilities
   - Key validation helpers
   - Hash utilities

3. Add tests:
   - Unit tests for plugin
   - Integration tests with backends
   - End-to-end tests

4. Documentation:
   - API reference
   - Usage guides
   - Backend implementation guide

## File Locations

All files are in `/Users/coffee/git/public/JacobCoffee/litestar-api-auth/src/litestar_api_auth/`:

- `plugin.py` - Main plugin implementation
- `controllers.py` - Auto-registered CRUD routes
- `middleware.py` - API key extraction middleware (existing)
- `guards.py` - Route protection guards (existing)
- `backends/base.py` - Backend protocol (existing)
- `types.py` - Type definitions (existing)
- `exceptions.py` - Exception hierarchy (existing)
- `__init__.py` - Public API exports (updated)
