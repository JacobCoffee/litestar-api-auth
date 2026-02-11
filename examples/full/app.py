"""Full example Litestar app with scoped API key authentication.

Demonstrates guards, scopes, and the auto-generated key management routes.

Run with:
    make example-full
    # or: uv run uvicorn examples.full.app:app --reload --port 8001
"""

from __future__ import annotations

from typing import Any

from litestar import Litestar, Request, get

from litestar_api_auth import (
    APIAuthConfig,
    APIAuthPlugin,
    get_api_key_info,
    require_api_key,
    require_scope,
    require_scopes,
)
from litestar_api_auth.backends.memory import MemoryBackend


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
    """Endpoint requiring the admin:write scope."""
    return {"message": "Welcome, admin!"}


@get("/reports", guards=[require_scopes("read:reports", "read:analytics", match="all")])
async def reports() -> dict[str, str]:
    """Endpoint requiring both read:reports AND read:analytics scopes."""
    return {"message": "Here are your reports."}


@get("/data", guards=[require_scopes("read:public", "read:internal", match="any")])
async def data() -> dict[str, str]:
    """Endpoint requiring either read:public OR read:internal scope."""
    return {"message": "Here is your data."}


app = Litestar(
    route_handlers=[index, protected, whoami, admin_only, reports, data],
    plugins=[
        APIAuthPlugin(
            config=APIAuthConfig(
                backend=MemoryBackend(),
                key_prefix="full_",
                auto_routes=True,
                route_prefix="/api-keys",
            )
        )
    ],
)
