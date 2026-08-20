"""Litestar plugin for API key authentication.

This module provides the main plugin class that integrates API key authentication
into Litestar applications, including middleware, routes, guards, and dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any

from litestar.plugins import InitPluginProtocol

from litestar_api_auth.backends.base import APIKeyBackend

if TYPE_CHECKING:
    from litestar.config.app import AppConfig
    from litestar.openapi.config import OpenAPIConfig
    from litestar.types import ControllerRouterHandler, Guard

__all__ = [
    "APIAuthConfig",
    "APIAuthPlugin",
]


def _default_management_guards() -> list[Guard]:
    """Return the default guards applied to auto-registered management routes.

    Mirrors ``APIKeyController``'s own default guards (a fresh list per call)
    so that auto-registered and manually-registered controllers stay in sync
    unless a caller explicitly overrides ``APIAuthConfig.management_guards``.
    """
    from litestar_api_auth.controllers import APIKeyController

    return list(APIKeyController.guards)


def _copy_openapi_config(openapi_config: OpenAPIConfig) -> OpenAPIConfig:
    """Return a per-app copy of an ``OpenAPIConfig`` that is safe to mutate.

    Litestar hands *every* app that doesn't pass its own ``openapi_config``
    the same module-level ``DEFAULT_OPENAPI_CONFIG`` instance, so registering
    this app's security scheme -- or, with ``openapi_global_security``, its
    document-wide security requirement -- directly on that object would leak
    into every other Litestar app in the same process. The nested
    ``Components`` (and its ``security_schemes`` dict) and the ``security``
    list are copied too, since ``dataclasses.replace`` alone would keep
    sharing them with the original.

    Args:
        openapi_config: The config to copy.

    Returns:
        A copy whose mutable members are not shared with the original.
    """
    from litestar.openapi.spec import Components

    components = openapi_config.components
    if isinstance(components, Components):
        components = replace(components)
        if components.security_schemes is not None:
            components.security_schemes = dict(components.security_schemes)
    elif isinstance(components, list):
        components = list(components)

    security = openapi_config.security
    return replace(
        openapi_config,
        components=components,
        security=list(security) if security is not None else None,
    )


@dataclass
class APIAuthConfig:
    """Configuration for the API key authentication plugin.

    This configuration object controls all aspects of the API auth system,
    including the storage backend, key format, routing, and security settings.

    Attributes:
        backend: The storage backend for API keys (required).
        key_prefix: Prefix for generated API keys (e.g., "pyorg_").
        header_name: HTTP header to extract API keys from.
        auth_scheme: Optional authentication scheme prefix expected on
            ``header_name``'s value -- e.g. ``auth_scheme="Bearer"`` with
            ``header_name="Authorization"`` accepts
            ``Authorization: Bearer <key>``. The match is case-insensitive,
            and a header value lacking the prefix is ignored entirely rather
            than being hashed and looked up as a key, so an unrelated
            credential sharing the same header (``Basic ...``, a JWT under
            another scheme) can never be mistaken for an API key. Defaults to
            None, meaning the whole header value is the key (the historical
            ``X-API-Key`` behavior).
        auto_routes: Whether to auto-register CRUD routes for key management.
        route_prefix: URL prefix for auto-registered routes.
        exclude_paths: Paths to exclude from API key authentication. Each entry
            is a regex pattern matched (unanchored) against the request path,
            per Litestar's ``AbstractMiddleware.exclude`` -- e.g. an unanchored
            "/health" would also match "/user/health-records". The defaults
            below are anchored (``r"^/schema(/|$)"``, ``r"^/health$"``) so they
            only ever match the OpenAPI schema routes and the literal
            "/health" path; anchor your own overrides the same way (e.g.
            ``r"^/health$"``) if that breadth is undesirable.
        route_handlers: Optional custom route handlers to register.
        dependencies: Optional custom dependencies to inject.
        enable_openapi: Whether to include auth in OpenAPI schema.
        openapi_global_security: Whether to also advertise the security
            scheme as a document-wide default requirement
            (``openapi_config.security``), marking *every* documented route as
            key-authed. Defaults to False: runtime enforcement is guard
            opt-in per handler and the middleware is fail-open, so in a host
            app whose routes are mostly unauthenticated a blanket default
            would misrepresent the app's security posture. The requirement is
            always attached to the routes this plugin actually guards (the
            auto-registered management controller) regardless of this
            setting. Set True only for an app where every route really does
            require an API key.
        track_usage: Whether to update last_used_at on each request.
        management_guards: Guards applied to the auto-registered key management
            routes. Defaults to requiring the ``api_keys:admin`` scope, since
            these routes can create keys with arbitrary scopes and must not be
            reachable by unauthenticated callers or by low-privilege keys.
            Passing an empty list explicitly disables authorization on these
            routes -- only do this if ``auto_routes`` is also disabled or the
            routes are guarded some other way.

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
    exclude_paths: list[str] = field(default_factory=lambda: [r"^/schema(/|$)", r"^/health$"])
    route_handlers: list[ControllerRouterHandler] = field(default_factory=list)
    dependencies: dict[str, Any] = field(default_factory=dict)
    enable_openapi: bool = True
    track_usage: bool = True
    # Appended last (rather than interleaved above) so adding these fields
    # doesn't shift the positional order of pre-existing fields.
    management_guards: list[Guard] = field(default_factory=_default_management_guards)
    auth_scheme: str | None = None
    openapi_global_security: bool = False


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

    # Fixed sentinel stored in ``app_config.opt`` (never ``None``, unlike
    # ``app_config.dependencies``) to detect a second instance. This is a
    # class attribute -- not derived from ``self._backend_dependency_key`` or
    # any other per-instance state -- so a subclass cannot bypass the check
    # by overriding an instance attribute; every ``APIAuthPlugin`` (and every
    # subclass that doesn't shadow this name) shares it.
    _SINGLE_INSTANCE_MARKER = "litestar_api_auth.plugin_registered"

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
        3. Adds custom route handlers
        4. Registers auto-routes if enabled
        5. Sets up lifespan handlers for backend startup/shutdown
        6. Configures OpenAPI security schemes

        Args:
            app_config: The Litestar application configuration.

        Returns:
            The modified application configuration.

        Raises:
            ConfigurationError: If another ``APIAuthPlugin`` is already
                registered on this app. See ``_check_single_instance`` for why
                running more than one instance per app is not supported.
        """
        # Refuse to silently cross-wire a second realm's auth into the first.
        self._check_single_instance(app_config)

        # Register backend as a dependency
        self._register_dependencies(app_config)

        # Add middleware for API key extraction and validation
        self._register_middleware(app_config)

        # Add custom route handlers *before* the auto-registered management
        # controller below. Litestar resolves an ambiguous dynamic path
        # (e.g. a user-supplied "/api-keys/{slug:str}" overlapping this
        # plugin's guarded "/api-keys/{key_id:str}") in favor of whichever
        # handler was registered last, so the guarded controller must always
        # be added after -- and therefore win over -- any user-supplied
        # handler, rather than risk an unguarded handler silently shadowing
        # it depending on registration order.
        if self.config.route_handlers:
            # Normalized here (rather than relying on _register_routes below
            # to do it first, as this block used to) since this now runs
            # ahead of that method.
            if app_config.route_handlers is None:
                app_config.route_handlers = []
            app_config.route_handlers.extend(self.config.route_handlers)

        # Register auto-routes if enabled
        if self.config.auto_routes:
            self._register_routes(app_config)

        # Set up lifespan handlers for backend initialization
        self._register_lifespan_handlers(app_config)

        # Configure OpenAPI security
        if self.config.enable_openapi:
            self._configure_openapi(app_config)

        return app_config

    def _check_single_instance(self, app_config: AppConfig) -> None:
        """Refuse to configure an app that already has an ``APIAuthPlugin``.

        Every instance writes to the same global slots regardless of which
        backend it wraps: ``request.state["api_key"]`` (see
        ``APIKeyMiddleware``) and the ``self._backend_dependency_key``
        dependency. A second instance wouldn't add a second, independent
        realm -- it would silently overwrite those slots with its own
        backend, so a key minted by realm A can satisfy guards meant for
        realm B. (The auto-registered management controller's own
        ``"backend"`` dependency is scoped to that controller rather than
        registered app-wide, so a second instance would instead fail loudly
        with a duplicate-route error if ``auto_routes`` and ``route_prefix``
        also collide -- but the request-state and dependency-key collisions
        above are silent, which is why this check exists.) Multi-realm auth
        therefore isn't supported by stacking plugin instances; raise
        instead of allowing that cross-wiring to happen quietly.

        Detection uses a fixed marker in ``app_config.opt`` rather than
        anything keyed off ``self`` (e.g. ``self._backend_dependency_key``,
        or the presence of an ``"api_auth_backend"`` dependency): a per-
        instance attribute could be overridden by a subclass to dodge
        detection while still sharing the same vulnerable request-state
        slot, and an unrelated app that happens to define its own
        ``"api_auth_backend"`` dependency would otherwise be misreported as
        a second plugin instance.

        Args:
            app_config: The application configuration being built.

        Raises:
            ConfigurationError: If ``_SINGLE_INSTANCE_MARKER`` is already set
                in ``app_config.opt``, meaning another ``APIAuthPlugin``
                instance already ran ``on_app_init`` for this same app.
        """
        from litestar_api_auth.exceptions import ConfigurationError

        if app_config.opt.get(self._SINGLE_INSTANCE_MARKER):
            raise ConfigurationError(
                "Multiple APIAuthPlugin instances were registered on the same "
                "Litestar app. Each instance shares the same "
                "request.state['api_key'] slot and dependency keys, so a "
                "second instance would silently authenticate requests "
                "against the wrong backend instead of adding an independent "
                "realm. Use a single APIAuthPlugin (with one backend) per app."
            )
        app_config.opt[self._SINGLE_INSTANCE_MARKER] = True

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
        # The middleware expects: app, backend, header_name, update_last_used,
        # exclude_paths, auth_scheme
        middleware = DefineMiddleware(
            APIKeyMiddleware,
            backend=self.config.backend,
            header_name=self.config.header_name,
            update_last_used=self.config.track_usage,
            exclude_paths=self.config.exclude_paths,
            auth_scheme=self.config.auth_scheme,
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
        from litestar.di import Provide

        from litestar_api_auth.controllers import APIKeyController

        backend = self.config.backend

        def provide_controller_backend() -> APIKeyBackend:
            return backend

        # Bound to a name (rather than a dict literal in the class body)
        # to keep ruff's RUF012 quiet, matching the ``path``/``guards``
        # pattern below.
        controller_dependencies = {"backend": Provide(provide_controller_backend, sync_to_thread=False)}

        # Advertise the OpenAPI security requirement only on these routes --
        # the ones this plugin actually guards -- rather than as a document-
        # wide default in ``_configure_openapi``. A document-wide default
        # would make every other, unguarded route in the app appear to
        # require an API key in the generated schema even though guards are
        # opt-in per handler and the middleware itself is fail-open. Omitted
        # entirely when there's nothing to advertise: no guards means these
        # routes aren't actually protected either, and disabling
        # ``enable_openapi`` means the "APIKeyAuth" scheme is never defined
        # for this to reference.
        controller_security = (
            [{"APIKeyAuth": []}] if self.config.enable_openapi and self.config.management_guards else None
        )

        # Create a dynamic controller class with the correct path and guards.
        # Key management is a privileged operation (a caller who can create
        # keys can mint arbitrary scopes), so it must be guarded even though
        # these routes are auto-registered.
        #
        # The "backend" dependency is set on the controller itself (scoped to
        # its own routes) rather than merged into app_config.dependencies --
        # the latter would register it app-wide, silently overwriting any
        # user-provided app-level "backend" dependency and injecting
        # APIKeyBackend into every unrelated handler that happens to declare
        # a "backend" parameter.
        class ConfiguredAPIKeyController(APIKeyController):
            path = self.config.route_prefix  # type: ignore[misc]
            guards = self.config.management_guards  # type: ignore[misc]
            dependencies = controller_dependencies  # type: ignore[misc]
            security = controller_security  # type: ignore[misc]

        # Add to route handlers
        if app_config.route_handlers is None:
            app_config.route_handlers = []

        app_config.route_handlers.append(ConfiguredAPIKeyController)

    def _register_lifespan_handlers(self, app_config: AppConfig) -> None:
        """Register lifespan handlers for backend startup and shutdown.

        Args:
            app_config: The application configuration to modify.
        """

        import inspect

        from litestar import Litestar

        # Store original lifespan hooks
        original_on_startup = app_config.on_startup
        original_on_shutdown = app_config.on_shutdown

        async def _call_hook(hook: Any, app: Litestar) -> None:
            """Call a lifespan hook, handling both (app) and () signatures."""
            try:
                sig = inspect.signature(hook)
                params = [p for p in sig.parameters.values() if p.default is inspect.Parameter.empty]
                result = hook(app) if params else hook()
            except TypeError:
                # If hook(app) failed (e.g. bound method that takes no args), retry without args
                result = hook()
            except ValueError:
                result = hook(app)
            if hasattr(result, "__await__"):
                await result

        async def on_startup(app: Litestar) -> None:
            """Initialize the backend on application startup."""
            if hasattr(self.config.backend, "startup"):
                await self.config.backend.startup()  # type: ignore[attr-defined]

            if original_on_startup:
                if callable(original_on_startup):
                    await _call_hook(original_on_startup, app)
                else:
                    for hook in original_on_startup:
                        await _call_hook(hook, app)

        async def on_shutdown(app: Litestar) -> None:
            """Clean up the backend on application shutdown."""
            if hasattr(self.config.backend, "close"):
                await self.config.backend.close()  # type: ignore[attr-defined]

            if original_on_shutdown:
                if callable(original_on_shutdown):
                    await _call_hook(original_on_shutdown, app)
                else:
                    for hook in original_on_shutdown:
                        await _call_hook(hook, app)

        # Replace lifespan hooks
        app_config.on_startup = [on_startup]  # type: ignore[list-item]
        app_config.on_shutdown = [on_shutdown]  # type: ignore[list-item]

    def _configure_openapi(self, app_config: AppConfig) -> None:
        """Register the ``APIKeyAuth`` OpenAPI security scheme.

        By default this only defines the scheme in
        ``components.securitySchemes`` -- it does not mark every operation (or
        the document as a whole) as requiring it. See ``_register_routes`` for
        where the requirement is attached, scoped to the routes this plugin
        guards. Set ``APIAuthConfig.openapi_global_security`` to True to
        *also* advertise it as a document-wide default.

        The scheme's own shape follows ``APIAuthConfig.auth_scheme``: with a
        ``"bearer"`` scheme configured it is an HTTP bearer scheme (which is
        what an ``Authorization: Bearer <key>`` setup actually is), otherwise
        an ``apiKey`` scheme named after ``header_name``.

        Args:
            app_config: The application configuration to modify.
        """
        from litestar.app import DEFAULT_OPENAPI_CONFIG
        from litestar.openapi.config import OpenAPIConfig
        from litestar.openapi.spec import Components, SecurityScheme

        # Create or get OpenAPI config
        if app_config.openapi_config is None:
            app_config.openapi_config = OpenAPIConfig(
                title="API",
                version="1.0.0",
            )
        elif app_config.openapi_config is DEFAULT_OPENAPI_CONFIG:
            app_config.openapi_config = _copy_openapi_config(app_config.openapi_config)

        openapi_config = app_config.openapi_config

        # Create security scheme for API key. An ``auth_scheme``-prefixed
        # header is an HTTP authentication scheme in OpenAPI terms, not an
        # apiKey-in-header one -- describing ``Authorization: Bearer <key>``
        # as ``type="apiKey", name="Authorization"`` would make generated
        # clients send the bare key with no scheme prefix, which the
        # middleware then ignores.
        if self.config.auth_scheme:
            security_scheme = SecurityScheme(
                type="http",
                scheme=self.config.auth_scheme.lower(),
                description=(
                    f"API key authentication using the {self.config.header_name} header "
                    f"with the {self.config.auth_scheme} scheme"
                ),
            )
        else:
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

        # A document-wide default requirement is opt-in via
        # ``openapi_global_security`` (default False). Runtime enforcement is
        # guard opt-in per handler and the middleware itself is fail-open, so
        # a blanket default would make every unguarded route in the app look
        # protected in the generated schema -- misleading in a host app whose
        # routes are mostly unauthenticated. Regardless of this setting,
        # ``_register_routes`` attaches the requirement to the routes this
        # plugin actually guards (the auto-registered management controller).
        if self.config.openapi_global_security:
            if openapi_config.security is None:
                openapi_config.security = []
            if {"APIKeyAuth": []} not in openapi_config.security:
                openapi_config.security.append({"APIKeyAuth": []})
