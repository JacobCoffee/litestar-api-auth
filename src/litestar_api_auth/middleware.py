"""Middleware for API key extraction and validation.

This module provides ASGI middleware for extracting API keys from request headers,
validating them against a backend storage, and storing the key information in
request state for use by guards.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Protocol

import msgspec
from litestar.middleware import AbstractMiddleware

from litestar_api_auth.backends.base import APIKeyInfo
from litestar_api_auth.exceptions import (
    APIKeyExpiredError,
    APIKeyNotFoundError,
    APIKeyRevokedError,
    InvalidAPIKeyError,
)
from litestar_api_auth.service import hash_api_key

if TYPE_CHECKING:
    from litestar.types import ASGIApp, Receive, Scope, Send

__all__ = [
    "APIKeyBackend",
    "APIKeyMiddleware",
]


class APIKeyBackend(Protocol):
    """Protocol defining the interface for API key storage backends.

    Any backend implementation must provide these methods to be compatible
    with the middleware.
    """

    async def get(self, key_hash: str) -> APIKeyInfo | None:
        """Retrieve API key information by its hash.

        Args:
            key_hash: The hashed API key value.

        Returns:
            APIKeyInfo if the key exists, None otherwise.
        """
        ...

    async def update_last_used(self, key_hash: str) -> None:
        """Update the last used timestamp for an API key.

        Args:
            key_hash: The hashed API key value.
        """
        ...


class APIKeyMiddleware(AbstractMiddleware):
    """ASGI middleware for API key extraction and validation.

    This middleware extracts API keys from request headers, validates them
    against a backend storage, and stores the key information in request state.

    The middleware performs the following steps:
    1. Extracts the API key from the configured header (default: X-API-Key)
    2. Hashes the key and looks it up in the backend
    3. Validates that the key is active and not expired
    4. Stores the APIKeyInfo in request.state.api_key
    5. Updates the last_used_at timestamp

    Guards can then check request.state.api_key to enforce authentication
    and authorization policies.

    Attributes:
        backend: The storage backend for API keys.
        header_name: The HTTP header name to extract the key from.
        update_last_used: Whether to update the last_used_at timestamp on each request.

    Example:
        >>> from litestar import Litestar
        >>> from litestar_api_auth.middleware import APIKeyMiddleware
        >>> from litestar_api_auth.backends.memory import MemoryBackend
        >>>
        >>> backend = MemoryBackend()
        >>> app = Litestar(
        ...     route_handlers=[...],
        ...     middleware=[APIKeyMiddleware(backend=backend)],
        ... )
    """

    def __init__(
        self,
        app: ASGIApp,
        backend: APIKeyBackend,
        header_name: str = "X-API-Key",
        update_last_used: bool = True,
        exclude_paths: str | list[str] | None = None,
    ) -> None:
        """Initialize the middleware.

        Args:
            app: The ASGI application.
            backend: The storage backend for API keys.
            header_name: The HTTP header name to extract the key from. Defaults to "X-API-Key".
            update_last_used: Whether to update the last_used_at timestamp. Defaults to True.
            exclude_paths: Regex pattern or list of regex patterns matched
                (unanchored) against the request path. Matching requests
                bypass this middleware entirely (see
                ``AbstractMiddleware.exclude``), so no lookup or usage-update
                is performed for them even if an API key header is present.
        """
        super().__init__(app=app, exclude=exclude_paths)
        self.backend = backend
        self.header_name = header_name.lower()  # HTTP headers are case-insensitive
        self.update_last_used = update_last_used

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Process the request through the middleware.

        Args:
            scope: The ASGI connection scope.
            receive: The ASGI receive channel.
            send: The ASGI send channel.
        """
        if "state" not in scope:
            scope["state"] = {}

        # Clear any pre-existing/stale state["api_key"] up front so a value
        # left over from another middleware (or a prior request) can never
        # be trusted as authenticated unless this middleware validates a key
        # on *this* request. This must happen before the HTTP-only check
        # below, since AbstractMiddleware also routes WebSocket scopes here.
        scope["state"]["api_key"] = None

        # Only process HTTP requests -- this middleware does not authenticate
        # WebSocket connections, but stale state has already been cleared above.
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Extract API key from headers
        api_key = self._extract_api_key(scope)

        # If an API key is present, validate it and store in state
        if api_key:
            try:
                key_info = await self._validate_api_key(api_key)

                # Update last used timestamp if enabled. This stays inside the
                # same try as validation -- and state["api_key"] is only ever
                # populated in the `else` clause below -- so a race-aware
                # custom backend raising APIKeyNotFoundError/APIKeyExpiredError/
                # APIKeyRevokedError/InvalidAPIKeyError here (e.g. detecting a
                # concurrent revocation or deletion) is handled the same way a
                # validation failure is, instead of leaving a just-invalidated
                # key authenticated because state was already set beforehand.
                if self.update_last_used:
                    key_hash = self._hash_api_key(api_key)
                    with contextlib.suppress(RuntimeError):
                        # Usage tracking is best-effort: a backend that raises
                        # RuntimeError here (e.g. Redis exhausting its
                        # WATCH/MULTI retries under heavy write contention on
                        # this key) must not turn an otherwise valid,
                        # already-authenticated request into a failure.
                        await self.backend.update_last_used(key_hash)
            except (
                APIKeyNotFoundError,
                APIKeyExpiredError,
                APIKeyRevokedError,
                InvalidAPIKeyError,
            ):
                # state["api_key"] stays None (cleared above) if validation
                # (or a race-aware update_last_used()) fails.
                # Guards will handle the missing key appropriately
                pass
            except BaseException:
                # An *unexpected* error (a backend bug/outage, not one of the
                # known validation-failure types above) is about to propagate
                # out of this frame while it still holds the raw api_key (and
                # possibly key_hash/key_info). Scrub them first so a
                # monitoring tool that captures frame locals on unhandled
                # exceptions (e.g. Sentry's include_local_variables) cannot
                # recover them from this frame's traceback entry.
                api_key = key_hash = key_info = None
                raise
            else:
                # Store the APIKeyInfo in request state for guards to access.
                # key_hash is redacted first: it's the SHA-256 verifier used
                # for backend lookups only, and a route handler that returns
                # this object directly (see the Warning in
                # guards.get_api_key_info's docstring) would otherwise
                # serialize the hash into the HTTP response.
                scope["state"]["api_key"] = msgspec.structs.replace(key_info, key_hash="")

        # None of api_key/key_hash/key_info are needed past this point (the
        # key has already been hashed and, if valid, handed off via
        # scope["state"]["api_key"] above as a key_hash-redacted copy).
        # Clear them from this frame before awaiting the downstream app so
        # they can't be recovered from this frame's locals if a monitoring
        # tool captures them on an unhandled downstream exception (e.g.
        # Sentry's include_local_variables). This cannot, however, scrub the
        # raw header value out of scope["headers"] itself -- ASGI requires
        # the original headers to remain available to downstream
        # middleware/handlers, so a frame-locals capture of the *downstream*
        # app's own frame can still observe the raw key via scope.
        api_key = key_hash = key_info = None

        # Continue processing the request
        await self.app(scope, receive, send)

    def _extract_api_key(self, scope: Scope) -> str | None:
        """Extract the API key from request headers.

        Args:
            scope: The ASGI connection scope.

        Returns:
            The API key value if present, None otherwise.
        """
        headers = scope.get("headers", [])

        for header_name, header_value in headers:
            if header_name.decode("latin-1").lower() == self.header_name:
                return header_value.decode("latin-1").strip()

        return None

    async def _validate_api_key(self, api_key: str) -> APIKeyInfo:
        """Validate an API key against the backend.

        Args:
            api_key: The raw API key value from the request.

        Returns:
            The validated APIKeyInfo.

        Raises:
            APIKeyNotFoundError: If the key is not found in the backend.
            APIKeyExpiredError: If the key has expired.
            APIKeyRevokedError: If the key has been revoked.
            InvalidAPIKeyError: If the key format is invalid.
        """
        # Hash the API key (backends store hashes, not plaintext)
        key_hash = self._hash_api_key(api_key)

        # Look up the key in the backend
        try:
            key_info = await self.backend.get(key_hash)
        except BaseException:
            # An *unexpected* error here (a backend bug/outage) is about to
            # propagate out of *this* frame while it still holds the raw
            # api_key local. The scrubbing in __call__'s own BaseException
            # handler only clears __call__'s frame, not this one, so a
            # monitoring tool that captures frame locals on unhandled
            # exceptions (e.g. Sentry's include_local_variables) could
            # otherwise recover the plaintext bearer key straight from this
            # frame's traceback entry. `del` (rather than assigning None) is
            # used here because api_key is a `str`-typed parameter, not a
            # plain local, so reassigning it to None would conflict with its
            # declared type.
            del api_key, key_hash
            raise

        if key_info is None:
            raise APIKeyNotFoundError()

        # Check if the key is revoked
        if not key_info.is_active:
            raise APIKeyRevokedError(key_id=key_info.key_id)

        # Check if the key is expired
        if key_info.is_expired:
            raise APIKeyExpiredError(
                key_id=key_info.key_id,
                expired_at=key_info.expires_at,
            )

        return key_info

    def _hash_api_key(self, api_key: str) -> str:
        """Hash an API key for backend lookup.

        Delegates to :func:`litestar_api_auth.service.hash_api_key` so the
        middleware always hashes with the same algorithm the key generation
        service uses, even if that algorithm changes later.

        Args:
            api_key: The raw API key value.

        Returns:
            The hashed API key.
        """
        return hash_api_key(api_key)
