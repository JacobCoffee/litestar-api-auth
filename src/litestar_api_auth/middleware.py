"""Middleware for API key extraction and validation.

This module provides ASGI middleware for extracting API keys from request headers,
validating them against a backend storage, and storing the key information in
request state for use by guards.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from litestar.middleware import AbstractMiddleware

from litestar_api_auth.backends.base import APIKeyInfo
from litestar_api_auth.exceptions import (
    APIKeyExpiredError,
    APIKeyNotFoundError,
    APIKeyRevokedError,
    InvalidAPIKeyError,
)

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
    ) -> None:
        """Initialize the middleware.

        Args:
            app: The ASGI application.
            backend: The storage backend for API keys.
            header_name: The HTTP header name to extract the key from. Defaults to "X-API-Key".
            update_last_used: Whether to update the last_used_at timestamp. Defaults to True.
        """
        super().__init__(app=app)
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
        # Only process HTTP requests
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Extract API key from headers
        api_key = self._extract_api_key(scope)

        # If an API key is present, validate it and store in state
        if api_key:
            try:
                key_info = await self._validate_api_key(api_key)
                # Store the APIKeyInfo in request state for guards to access
                if "state" not in scope:
                    scope["state"] = {}
                scope["state"]["api_key"] = key_info

                # Update last used timestamp if enabled
                if self.update_last_used:
                    key_hash = self._hash_api_key(api_key)
                    await self.backend.update_last_used(key_hash)
            except (
                APIKeyNotFoundError,
                APIKeyExpiredError,
                APIKeyRevokedError,
                InvalidAPIKeyError,
            ):
                # Don't store anything in state if validation fails
                # Guards will handle the missing key appropriately
                pass

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

        This method should use the same hashing algorithm as the key generation
        service. SHA-256 is the standard for API key hashing.

        Args:
            api_key: The raw API key value.

        Returns:
            The hashed API key.

        Note:
            This is a placeholder implementation. In production, this should
            use the same hashing method as your key generation service
            (typically hashlib.sha256).
        """
        import hashlib

        return hashlib.sha256(api_key.encode()).hexdigest()
