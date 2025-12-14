"""Litestar plugin for API key authentication.

This module provides the main plugin class that integrates API key authentication
into Litestar applications, including middleware, routes, guards, and dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from litestar.plugins import InitPluginProtocol

from litestar_api_auth.backends.base import APIKeyBackend

if TYPE_CHECKING:
    from litestar.config.app import AppConfig
    from litestar.types import ControllerRouterHandler

__all__ = [
    "APIAuthConfig",
    "APIAuthPlugin",
]


@dataclass
class APIAuthConfig:
    """Configuration for the API key authentication plugin.

    This configuration object controls all aspects of the API auth system,
    including the storage backend, key format, routing, and security settings.

    Attributes:
        backend: The storage backend for API keys (required).
        key_prefix: Prefix for generated API keys (e.g., "pyorg_").
        header_name: HTTP header to extract API keys from.
        auto_routes: Whether to auto-register CRUD routes for key management.
        route_prefix: URL prefix for auto-registered routes.
        exclude_paths: Paths to exclude from API key authentication.
        route_handlers: Optional custom route handlers to register.
        dependencies: Optional custom dependencies to inject.
        enable_openapi: Whether to include auth in OpenAPI schema.
        track_usage: Whether to update last_used_at on each request.

    Example:
        >>> from litestar_api_auth import APIAuthConfig
        >>> from litestar_api_auth.backends.memory import MemoryBackend
        >>> config = APIAuthConfig(
        ...     backend=MemoryBackend(),
        ...     key_prefix="myapp_",
        ...     auto_routes=True,
        ... )
    """

    backend: APIKeyBackend
    key_prefix: str = "pyorg_"
    header_name: str = "X-API-Key"
    auto_routes: bool = True
    route_prefix: str = "/api-keys"
    exclude_paths: list[str] = field(default_factory=lambda: ["/schema", "/health"])
    route_handlers: list[ControllerRouterHandler] = field(default_factory=list)
    dependencies: dict[str, Any] = field(default_factory=dict)
    enable_openapi: bool = True
    track_usage: bool = True


class APIAuthPlugin(InitPluginProtocol):
    """Litestar plugin for API key authentication.

    This plugin provides complete API key authentication for Litestar applications:
    - Middleware for extracting and validating API keys from requests
    - Auto-registered routes for key management (create, list, revoke, delete)
    - Guards for protecting routes with scope-based permissions
    - Dependency injection for the backend and current API key
    - OpenAPI schema integration for documenting protected endpoints
    - Lifespan management for backend initialization and cleanup

    The plugin follows the InitPluginProtocol and integrates seamlessly with
    Litestar's application lifecycle.

    Example:
        >>> from litestar import Litestar
        >>> from litestar_api_auth import APIAuthPlugin, APIAuthConfig
        >>> from litestar_api_auth.backends.memory import MemoryBackend
        >>>
        >>> app = Litestar(
        ...     route_handlers=[],
        ...     plugins=[
        ...         APIAuthPlugin(
        ...             config=APIAuthConfig(
        ...                 backend=MemoryBackend(),
        ...                 key_prefix="app_",
        ...             )
        ...         )
        ...     ],
        ... )
    """

    __slots__ = ("_backend_dependency_key", "config")

    def __init__(self, config: APIAuthConfig) -> None:
        """Initialize the API auth plugin.

        Args:
            config: Configuration object for the plugin.
        """
        self.config = config
        self._backend_dependency_key = "api_auth_backend"

    def on_app_init(self, app_config: AppConfig) -> AppConfig:
        """Configure the application with API key authentication.

        This method is called during application initialization and performs:
        1. Registers the backend as a dependency
        2. Adds the authentication middleware
        3. Registers auto-routes if enabled
        4. Sets up lifespan handlers for backend startup/shutdown
        5. Configures OpenAPI security schemes

        Args:
            app_config: The Litestar application configuration.

        Returns:
            The modified application configuration.
        """
        # Register backend as a dependency
        self._register_dependencies(app_config)

        # Add middleware for API key extraction and validation
        self._register_middleware(app_config)

        # Register auto-routes if enabled
        if self.config.auto_routes:
            self._register_routes(app_config)

        # Add custom route handlers
        if self.config.route_handlers:
            app_config.route_handlers.extend(self.config.route_handlers)

        # Set up lifespan handlers for backend initialization
        self._register_lifespan_handlers(app_config)

        # Configure OpenAPI security
        if self.config.enable_openapi:
            self._configure_openapi(app_config)

        return app_config

    def _register_dependencies(self, app_config: AppConfig) -> None:
        """Register the backend as a dependency for injection.

        Args:
            app_config: The application configuration to modify.
        """
        from litestar.di import Provide

        def provide_backend() -> APIKeyBackend:
            """Provide the API key backend for dependency injection."""
            return self.config.backend

        # Register backend dependency
        if app_config.dependencies is None:
            app_config.dependencies = {}

        app_config.dependencies[self._backend_dependency_key] = Provide(
            provide_backend,
            sync_to_thread=False,
        )

        # Merge custom dependencies
        app_config.dependencies.update(self.config.dependencies)

    def _register_middleware(self, app_config: AppConfig) -> None:
        """Register the API key authentication middleware.

        Args:
            app_config: The application configuration to modify.
        """

        from litestar.middleware import DefineMiddleware

        from litestar_api_auth.middleware import APIKeyMiddleware

        # Create middleware configuration
        # The middleware expects: app, backend, header_name, update_last_used
        middleware = DefineMiddleware(
            APIKeyMiddleware,
            backend=self.config.backend,
            header_name=self.config.header_name,
            update_last_used=self.config.track_usage,
        )

        # Add to middleware list
        if app_config.middleware is None:
            app_config.middleware = []

        app_config.middleware.append(middleware)

    def _register_routes(self, app_config: AppConfig) -> None:
        """Register auto-generated routes for API key management.

        Args:
            app_config: The application configuration to modify.
        """
        from litestar_api_auth.controllers import APIKeyController

        # Create a dynamic controller class with the correct path
        class ConfiguredAPIKeyController(APIKeyController):
            path = self.config.route_prefix  # type: ignore[misc]

        # Store backend reference for dependency injection
        from litestar.di import Provide

        backend = self.config.backend

        def provide_controller_backend() -> APIKeyBackend:
            return backend

        # Register backend dependency for controller
        if app_config.dependencies is None:
            app_config.dependencies = {}
        app_config.dependencies["backend"] = Provide(provide_controller_backend, sync_to_thread=False)

        # Add to route handlers
        if app_config.route_handlers is None:
            app_config.route_handlers = []

        app_config.route_handlers.append(ConfiguredAPIKeyController)

    def _register_lifespan_handlers(self, app_config: AppConfig) -> None:
        """Register lifespan handlers for backend startup and shutdown.

        Args:
            app_config: The application configuration to modify.
        """

        from litestar import Litestar

        # Store original lifespan hooks
        original_on_startup = app_config.on_startup
        original_on_shutdown = app_config.on_shutdown

        async def on_startup(app: Litestar) -> None:
            """Initialize the backend on application startup."""
            # Call backend startup if it has one
            if hasattr(self.config.backend, "startup"):
                await self.config.backend.startup()  # type: ignore[attr-defined]

            # Call original startup hooks
            if original_on_startup:
                if callable(original_on_startup):
                    result = original_on_startup(app)
                    if hasattr(result, "__await__"):
                        await result
                else:
                    for hook in original_on_startup:
                        result = hook(app)  # type: ignore[call-arg]
                        if hasattr(result, "__await__"):
                            await result

        async def on_shutdown(app: Litestar) -> None:
            """Clean up the backend on application shutdown."""
            # Call backend cleanup
            if hasattr(self.config.backend, "close"):
                await self.config.backend.close()  # type: ignore[attr-defined]

            # Call original shutdown hooks
            if original_on_shutdown:
                if callable(original_on_shutdown):
                    result = original_on_shutdown(app)
                    if hasattr(result, "__await__"):
                        await result
                else:
                    for hook in original_on_shutdown:
                        result = hook(app)  # type: ignore[call-arg]
                        if hasattr(result, "__await__"):
                            await result

        # Replace lifespan hooks
        app_config.on_startup = [on_startup]  # type: ignore[list-item]
        app_config.on_shutdown = [on_shutdown]  # type: ignore[list-item]

    def _configure_openapi(self, app_config: AppConfig) -> None:
        """Configure OpenAPI security scheme for API key authentication.

        Args:
            app_config: The application configuration to modify.
        """
        from litestar.openapi.config import OpenAPIConfig
        from litestar.openapi.spec import Components, SecurityScheme

        # Create or get OpenAPI config
        if app_config.openapi_config is None:
            app_config.openapi_config = OpenAPIConfig(
                title="API",
                version="1.0.0",
            )

        openapi_config = app_config.openapi_config

        # Create security scheme for API key
        security_scheme = SecurityScheme(
            type="apiKey",
            name=self.config.header_name,
            security_scheme_in="header",
            description=f"API key authentication using {self.config.header_name} header",
        )

        # Add to components
        if openapi_config.components is None:
            openapi_config.components = Components(
                security_schemes={"APIKeyAuth": security_scheme},
            )
        # Check if components is a list or Components object
        elif isinstance(openapi_config.components, list):
            openapi_config.components.append(
                Components(
                    security_schemes={"APIKeyAuth": security_scheme},
                )
            )
        else:
            # It's a Components object
            if openapi_config.components.security_schemes is None:
                openapi_config.components.security_schemes = {}
            openapi_config.components.security_schemes["APIKeyAuth"] = security_scheme

        # Add security requirement
        if openapi_config.security is None:
            openapi_config.security = []

        openapi_config.security.append({"APIKeyAuth": []})
