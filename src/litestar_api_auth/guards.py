"""Guard functions for API key authentication and authorization.

This module provides Litestar guard factory functions for protecting routes
with API key authentication and scope-based authorization.

Guards work in conjunction with the APIKeyMiddleware, which extracts and
validates the API key and stores it in request.state.api_key.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from litestar.connection import ASGIConnection
from litestar.exceptions import NotAuthorizedException, PermissionDeniedException
from litestar.handlers import BaseRouteHandler

from litestar_api_auth.types import APIKeyInfo, ScopeRequirement

if TYPE_CHECKING:
    from litestar.types import Guard

__all__ = [
    "require_api_key",
    "require_scope",
    "require_scopes",
    "get_api_key_info",
]


def get_api_key_info(connection: ASGIConnection) -> APIKeyInfo:
    """Extract the API key info from request state.

    This is a helper function that guards and route handlers can use to
    retrieve the validated API key information from the request state.

    Args:
        connection: The ASGI connection.

    Returns:
        The APIKeyInfo from request state.

    Raises:
        NotAuthorizedException: If no API key is present in the request state.

    Example:
        >>> from litestar import get, Request
        >>> from litestar_api_auth.guards import require_api_key, get_api_key_info
        >>>
        >>> @get("/me", guards=[require_api_key])
        >>> async def get_current_key(request: Request) -> dict:
        ...     key_info = get_api_key_info(request)
        ...     return {
        ...         "key_id": key_info.key_id,
        ...         "scopes": key_info.scopes,
        ...     }
    """
    api_key = connection.state.get("api_key")

    if api_key is None:
        raise NotAuthorizedException(
            detail="No API key found in request. Ensure APIKeyMiddleware is configured and a valid API key is provided."
        )

    return api_key


def require_api_key(connection: ASGIConnection, _: BaseRouteHandler) -> None:
    """Guard that requires a valid API key.

    This guard ensures that the request has a valid, active, and non-expired
    API key. The APIKeyMiddleware must be configured for this guard to work.

    Args:
        connection: The ASGI connection.
        _: The route handler (unused, required by Litestar's Guard protocol).

    Raises:
        NotAuthorizedException: If no valid API key is present.

    Example:
        >>> from litestar import get
        >>> from litestar_api_auth.guards import require_api_key
        >>>
        >>> @get("/protected", guards=[require_api_key])
        >>> async def protected_route() -> dict:
        ...     return {"status": "authenticated"}
    """
    # This will raise NotAuthorizedException if no key is present
    get_api_key_info(connection)


def require_scope(scope: str) -> Guard:
    """Create a guard that requires a specific scope.

    This factory function returns a guard that checks if the API key
    has the specified scope.

    Args:
        scope: The required scope.

    Returns:
        A guard function that can be used in route handlers.

    Example:
        >>> from litestar import get
        >>> from litestar_api_auth.guards import require_scope
        >>>
        >>> @get("/admin", guards=[require_scope("admin:write")])
        >>> async def admin_route() -> dict:
        ...     return {"status": "admin access"}
    """

    def guard(connection: ASGIConnection, _: BaseRouteHandler) -> None:
        """Guard implementation that checks for the required scope.

        Args:
            connection: The ASGI connection.
            _: The route handler (unused).

        Raises:
            NotAuthorizedException: If no valid API key is present.
            PermissionDeniedException: If the API key lacks the required scope.
        """
        key_info = get_api_key_info(connection)

        if not key_info.has_scope(scope):
            raise PermissionDeniedException(
                detail=f"API key lacks required scope: {scope}. Available scopes: {key_info.scopes}"
            )

    return guard


def require_scopes(*scopes: str, match: ScopeRequirement = "all") -> Guard:
    """Create a guard that requires multiple scopes.

    This factory function returns a guard that checks if the API key
    has the required scopes. The `match` parameter controls whether
    all scopes must be present or just any one of them.

    Args:
        *scopes: The required scopes.
        match: Scope matching requirement - "all" or "any". Defaults to "all".

    Returns:
        A guard function that can be used in route handlers.

    Raises:
        ValueError: If no scopes are provided or if match is invalid.

    Example:
        >>> from litestar import get
        >>> from litestar_api_auth.guards import require_scopes
        >>>
        >>> # Require all scopes
        >>> @get("/admin/users", guards=[require_scopes("admin:read", "users:write")])
        >>> async def manage_users() -> dict:
        ...     return {"status": "admin user management"}
        >>>
        >>> # Require any scope
        >>> @get("/data", guards=[require_scopes("read:public", "read:private", match="any")])
        >>> async def get_data() -> dict:
        ...     return {"status": "data access"}
    """
    if not scopes:
        raise ValueError("At least one scope must be specified")

    if match not in ("all", "any"):
        raise ValueError(f"Invalid match parameter: {match}. Must be 'all' or 'any'")

    scopes_list = list(scopes)

    def guard(connection: ASGIConnection, _: BaseRouteHandler) -> None:
        """Guard implementation that checks for the required scopes.

        Args:
            connection: The ASGI connection.
            _: The route handler (unused).

        Raises:
            NotAuthorizedException: If no valid API key is present.
            PermissionDeniedException: If the API key lacks the required scopes.
        """
        key_info = get_api_key_info(connection)

        if not key_info.has_scopes(scopes_list, requirement=match):
            if match == "all":
                detail = f"API key lacks required scopes. Required: {scopes_list}, Available: {key_info.scopes}"
            else:
                detail = (
                    f"API key lacks at least one required scope. "
                    f"Required (any): {scopes_list}, Available: {key_info.scopes}"
                )

            raise PermissionDeniedException(detail=detail)

    return guard
