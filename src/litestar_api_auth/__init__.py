"""Litestar API Authentication - API key authentication plugin for Litestar.

This package provides a pluggable API key authentication system for Litestar
applications with support for multiple storage backends, key scoping, and
comprehensive security features.

Example:
    >>> from litestar import Litestar, get
    >>> from litestar_api_auth import (
    ...     APIAuthPlugin,
    ...     APIAuthConfig,
    ...     require_api_key,
    ...     require_scope,
    ... )
    >>> from litestar_api_auth.backends.memory import MemoryBackend
    >>>
    >>> @get("/protected", guards=[require_api_key])
    >>> async def protected_route() -> dict:
    ...     return {"status": "authenticated"}
    >>>
    >>> app = Litestar(
    ...     route_handlers=[protected_route],
    ...     plugins=[
    ...         APIAuthPlugin(
    ...             config=APIAuthConfig(
    ...                 backend=MemoryBackend(),
    ...                 key_prefix="myapp_",
    ...                 auto_routes=True,
    ...             )
    ...         )
    ...     ],
    ... )
"""

from __future__ import annotations

from litestar_api_auth.__metadata__ import __version__
from litestar_api_auth.controllers import APIKeyController

# Exceptions
from litestar_api_auth.exceptions import (
    APIAuthError,
    APIKeyExpiredError,
    APIKeyNotFoundError,
    APIKeyRevokedError,
    ConfigurationError,
    InsufficientScopesError,
    InvalidAPIKeyError,
)

# Guards for route protection
from litestar_api_auth.guards import (
    get_api_key_info,
    require_api_key,
    require_scope,
    require_scopes,
)

# Middleware and controllers (for manual setup)
from litestar_api_auth.middleware import APIKeyMiddleware

# Core plugin exports
from litestar_api_auth.plugin import APIAuthConfig, APIAuthPlugin

# Service functions
from litestar_api_auth.service import (
    extract_key_id,
    generate_api_key,
    hash_api_key,
    verify_api_key,
)

# Types
from litestar_api_auth.types import (
    APIKeyInfo,
    APIKeyState,
    ScopeRequirement,
)

__all__ = [
    # Version
    "__version__",
    # Plugin
    "APIAuthPlugin",
    "APIAuthConfig",
    # Guards
    "get_api_key_info",
    "require_api_key",
    "require_scope",
    "require_scopes",
    # Exceptions
    "APIAuthError",
    "APIKeyExpiredError",
    "APIKeyNotFoundError",
    "APIKeyRevokedError",
    "ConfigurationError",
    "InsufficientScopesError",
    "InvalidAPIKeyError",
    # Service functions
    "extract_key_id",
    "generate_api_key",
    "hash_api_key",
    "verify_api_key",
    # Types
    "APIKeyInfo",
    "APIKeyState",
    "ScopeRequirement",
    # Advanced (for manual setup)
    "APIKeyMiddleware",
    "APIKeyController",
]
