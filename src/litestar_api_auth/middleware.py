"""Middleware for API key extraction and validation.

This module provides ASGI middleware for extracting API keys from request headers,
validating them against a backend storage, and storing the key information in
request state for use by guards.
"""

from __future__ import annotations

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
            except (
                APIKeyNotFoundError,
                APIKeyExpiredError,
                APIKeyRevokedError,
                InvalidAPIKeyError,
            ):
                # state["api_key"] stays None (cleared above) if validation fails
                # Guards will handle the missing key appropriately
                pass
            else:
                # Store the APIKeyInfo in request state for guards to access.
                # key_hash is redacted first: it's the SHA-256 verifier used
                # for backend lookups only, and a route handler that returns
                # this object directly (see the Warning in
                # guards.get_api_key_info's docstring) would otherwise
                # serialize the hash into the HTTP response.
                scope["state"]["api_key"] = msgspec.structs.replace(key_info, key_hash="")

                # Update last used timestamp if enabled. This is deliberately
                # outside the except above: it runs only after state["api_key"]
                # is already populated, so a race-aware custom backend raising
                # APIKeyRevokedError/APIKeyExpiredError here (e.g. detecting a
                # concurrent revocation) must clear that state itself instead
                # of being caught by the validation except block, which would
                # otherwise leave the just-revoked/expired key authenticated.
                if self.update_last_used:
                    key_hash = self._hash_api_key(api_key)
                    try:
                        await self.backend.update_last_used(key_hash)
                    except RuntimeError:
                        # Usage tracking is best-effort: a backend that raises
                        # RuntimeError here (e.g. Redis exhausting its
                        # WATCH/MULTI retries under heavy write contention on
                        # this key) must not turn an otherwise valid,
                        # already-authenticated request into a failure.
                        pass
                    except (APIKeyRevokedError, APIKeyExpiredError):
                        # A race-aware backend can detect concurrent
                        # revocation/expiry here, after already reporting the
                        # key as active from _validate_api_key. Clear the
                        # state so the request is not treated as
                        # authenticated.
                        scope["state"]["api_key"] = None

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
        key_info = await self.backend.get(key_hash)

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
