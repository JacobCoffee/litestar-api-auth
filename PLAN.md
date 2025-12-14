# litestar-api-auth - API Key Authentication for Litestar

> Pluggable API key authentication for Litestar applications

## Overview

A Litestar plugin that provides API key authentication with:
- Automatic model generation (SQLAlchemy/Advanced Alchemy)
- Pre-built controllers and routes
- Configurable guards
- Multiple storage backends
- Key scoping and permissions
- Rate limiting support

## Features

### Core
- [x] API key generation with secure hashing (SHA-256)
- [x] Key prefix for identification (`pyorg_`, configurable)
- [x] Expiration support
- [x] Key revocation
- [x] Last-used tracking

### Plugin Features
- [ ] Pluggable storage backends (SQLAlchemy, Redis, in-memory)
- [ ] Auto-registered routes (`/api-keys/*`)
- [ ] Configurable guards (`require_api_key`, `require_api_key_with_scope`)
- [ ] Middleware for `X-API-Key` header parsing
- [ ] Key scopes/permissions system
- [ ] Rate limiting per key
- [ ] OpenAPI schema generation

### Advanced
- [ ] Key rotation support
- [ ] Audit logging
- [ ] Webhook notifications (key created/revoked)
- [ ] Admin UI components (optional)

---

## Project Structure

> Follow the pattern from `litestar-storages`, `litestar-workflows`, and `pytest-routes`

```
litestar-api-auth/
├── src/
│   └── litestar_api_auth/
│       ├── __init__.py           # Public API exports
│       ├── __metadata__.py       # Version info
│       ├── base.py               # Base classes, protocols
│       ├── config.py             # APIAuthConfig plugin config
│       ├── exceptions.py         # Custom exceptions
│       ├── guards.py             # Litestar guards
│       ├── middleware.py         # X-API-Key middleware
│       ├── models.py             # SQLAlchemy models (APIKey)
│       ├── schemas.py            # Pydantic schemas
│       ├── service.py            # Key generation, validation
│       ├── types.py              # Type aliases
│       ├── backends/
│       │   ├── __init__.py
│       │   ├── base.py           # Abstract backend protocol
│       │   ├── sqlalchemy.py     # SQLAlchemy backend
│       │   ├── redis.py          # Redis backend
│       │   └── memory.py         # In-memory backend (testing)
│       └── contrib/
│           ├── __init__.py
│           └── sqlalchemy/
│               ├── __init__.py
│               ├── repository.py  # Advanced Alchemy repository
│               └── service.py     # Repository service
├── tests/
│   ├── unit/
│   └── integration/
├── docs/
├── pyproject.toml
├── README.md
└── PLAN.md
```

---

## Configuration

```python
from litestar import Litestar
from litestar_api_auth import APIAuthPlugin, APIAuthConfig
from litestar_api_auth.backends.sqlalchemy import SQLAlchemyBackend

app = Litestar(
    plugins=[
        APIAuthPlugin(
            config=APIAuthConfig(
                backend=SQLAlchemyBackend(engine),
                key_prefix="myapp_",
                header_name="X-API-Key",
                auto_routes=True,
                route_prefix="/api/v1/api-keys",
            )
        )
    ]
)
```

---

## Guard Usage

```python
from litestar import get
from litestar_api_auth import require_api_key, require_scope

@get("/protected", guards=[require_api_key])
async def protected_route() -> dict:
    return {"status": "authenticated"}

@get("/admin", guards=[require_scope("admin:write")])
async def admin_route() -> dict:
    return {"status": "admin access"}
```

---

## Build System

Use `uv_build` as the build backend (consistent with other libs):

```toml
[build-system]
requires = ["hatchling", "uv_build"]
build-backend = "hatchling.build"

[project]
name = "litestar-api-auth"
dynamic = ["version"]
# ...

[tool.hatch.version]
path = "src/litestar_api_auth/__metadata__.py"
```

---

## Dependencies

```toml
dependencies = [
    "litestar>=2.0",
]

[project.optional-dependencies]
sqlalchemy = ["sqlalchemy>=2.0", "advanced-alchemy>=0.10"]
redis = ["redis>=5.0"]
all = ["litestar-api-auth[sqlalchemy,redis]"]
```

---

## Implementation Phases

### Phase 1: Core (MVP)
- [ ] Project scaffolding (pyproject.toml, src layout)
- [ ] Base models and schemas
- [ ] Key generation service
- [ ] SQLAlchemy backend
- [ ] Basic guards
- [ ] Middleware
- [ ] Unit tests

### Phase 2: Plugin Integration
- [ ] Litestar plugin class
- [ ] Auto-route registration
- [ ] OpenAPI integration
- [ ] Config validation

### Phase 3: Advanced Features
- [ ] Redis backend
- [ ] Key scopes/permissions
- [ ] Rate limiting
- [ ] Audit logging

### Phase 4: Polish
- [ ] Documentation (Sphinx)
- [ ] Examples
- [ ] Integration tests
- [ ] CI/CD

---

## Reference Implementation

Based on the API key system implemented in `litestar-pydotorg`:
- `src/pydotorg/domains/users/api_keys.py` - Model and service
- `src/pydotorg/core/auth/middleware.py` - X-API-Key middleware
- `src/pydotorg/core/auth/guards.py` - Guards
- `tests/unit/domains/users/test_api_keys.py` - Tests

---

*Last updated: 2025-12-13*
