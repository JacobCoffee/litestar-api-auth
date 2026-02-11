"""Minimal example Litestar app with API key authentication.

Run with:
    make example-minimal
    # or: uv run uvicorn examples.minimal.app:app --reload --port 8005
"""

from __future__ import annotations

from litestar import Litestar, get

from litestar_api_auth import APIAuthConfig, APIAuthPlugin, require_api_key
from litestar_api_auth.backends.memory import MemoryBackend


@get("/", exclude_from_auth=True)
async def index() -> dict[str, str]:
    """Public health check endpoint."""
    return {"status": "ok"}


@get("/protected", guards=[require_api_key])
async def protected() -> dict[str, str]:
    """Endpoint that requires a valid API key."""
    return {"message": "Hello, authenticated user!"}


app = Litestar(
    route_handlers=[index, protected],
    plugins=[
        APIAuthPlugin(
            config=APIAuthConfig(
                backend=MemoryBackend(),
                key_prefix="demo_",
                auto_routes=True,
            )
        )
    ],
)
