"""Full example Litestar app with scoped API key authentication.

Demonstrates guards, scopes, backend selection, and the auto-generated
key management routes.

Run with:
    make example-full
    # or: uv run uvicorn examples.full.app:app --reload --port 8001

Backend selection via BACKEND env var:
    BACKEND=memory  uv run uvicorn examples.full.app:app --port 8001  (default)
    BACKEND=sqlite  uv run uvicorn examples.full.app:app --port 8001
    BACKEND=redis   uv run uvicorn examples.full.app:app --port 8001
"""

from __future__ import annotations

import os
from typing import Any

from litestar import Litestar, Request, get
from litestar.openapi.config import OpenAPIConfig

from litestar_api_auth import (
    APIAuthConfig,
    APIAuthPlugin,
    get_api_key_info,
    require_api_key,
    require_scope,
    require_scopes,
)

# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------


def _build_backend() -> Any:
    """Build the appropriate backend based on the BACKEND env var.

    Supported values:
        memory  - In-memory (default, no dependencies)
        sqlite  - SQLAlchemy with async SQLite (requires: pip install litestar-api-auth[sqlalchemy] aiosqlite)
        redis   - Redis (requires: pip install litestar-api-auth[redis] and a running Redis server)
    """
    choice = os.environ.get("BACKEND", "memory").lower()

    if choice == "sqlite":
        from sqlalchemy.ext.asyncio import create_async_engine

        from litestar_api_auth.backends.sqlalchemy import SQLAlchemyBackend, SQLAlchemyConfig

        engine = create_async_engine("sqlite+aiosqlite:///example_keys.db", echo=False)
        return SQLAlchemyBackend(config=SQLAlchemyConfig(engine=engine, create_tables=True))

    if choice == "redis":
        from redis.asyncio import Redis

        from litestar_api_auth.backends.redis import RedisBackend, RedisConfig

        client = Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"))
        return RedisBackend(config=RedisConfig(client=client, key_prefix="example:"))

    # Default: in-memory
    from litestar_api_auth.backends.memory import MemoryBackend

    return MemoryBackend()


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------


@get("/", exclude_from_auth=True)
async def index() -> dict[str, str]:
    """Public health check endpoint."""
    return {"status": "ok"}


@get("/protected", guards=[require_api_key])
async def protected() -> dict[str, str]:
    """Endpoint that requires any valid API key."""
    return {"message": "Hello, authenticated user!"}


@get("/me", guards=[require_api_key])
async def whoami(request: Request) -> dict[str, Any]:
    """Return information about the current API key."""
    key_info = get_api_key_info(request)
    return {
        "key_id": key_info.key_id,
        "name": key_info.name,
        "scopes": key_info.scopes,
        "is_active": key_info.is_active,
        "is_expired": key_info.is_expired,
    }


@get("/admin", guards=[require_scope("admin:write")])
async def admin_only() -> dict[str, str]:
    """Endpoint requiring the ``admin:write`` scope."""
    return {"message": "Welcome, admin!"}


@get(
    "/reports",
    guards=[require_scopes("read:reports", "read:analytics", match="all")],
)
async def reports() -> dict[str, str]:
    """Endpoint requiring **both** ``read:reports`` AND ``read:analytics``."""
    return {"message": "Here are your reports."}


@get(
    "/data",
    guards=[require_scopes("read:public", "read:internal", match="any")],
)
async def data() -> dict[str, str]:
    """Endpoint requiring **either** ``read:public`` OR ``read:internal``."""
    return {"message": "Here is your data."}


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

backend = _build_backend()

app = Litestar(
    route_handlers=[index, protected, whoami, admin_only, reports, data],
    plugins=[
        APIAuthPlugin(
            config=APIAuthConfig(
                backend=backend,
                key_prefix="full_",
                auto_routes=True,
                route_prefix="/api-keys",
                exclude_paths=["/", "/schema"],
                track_usage=True,
            )
        )
    ],
    openapi_config=OpenAPIConfig(
        title="litestar-api-auth Full Example",
        version="0.1.0",
    ),
)
