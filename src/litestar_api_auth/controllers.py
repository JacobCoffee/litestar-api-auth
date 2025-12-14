"""Route controllers for API key management.

This module provides auto-registered REST endpoints for creating, listing,
revoking, and deleting API keys.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any, ClassVar

import msgspec
from litestar import Controller, delete, get, post
from litestar.params import Parameter
from litestar.status_codes import HTTP_201_CREATED, HTTP_204_NO_CONTENT

from litestar_api_auth.backends.base import APIKeyBackend

__all__ = ["APIKeyController"]


class APIKeyController(Controller):
    """REST controller for API key management operations.

    This controller provides CRUD endpoints for managing API keys:
    - POST /api-keys - Create a new API key
    - GET /api-keys - List all API keys
    - GET /api-keys/{key_id} - Get a specific API key
    - DELETE /api-keys/{key_id} - Delete an API key
    - POST /api-keys/{key_id}/revoke - Revoke an API key

    These routes are auto-registered when APIAuthConfig.auto_routes is True.

    Example:
        >>> from litestar import Litestar
        >>> from litestar_api_auth.controllers import APIKeyController
        >>> from litestar_api_auth.backends.memory import MemoryBackend
        >>>
        >>> class MyController(APIKeyController):
        ...     path = "/api-keys"
        >>>
        >>> app = Litestar(
        ...     route_handlers=[MyController],
        ...     dependencies={"backend": lambda: MemoryBackend()},
        ... )
    """

    path: ClassVar[str] = "/api-keys"  # type: ignore[misc]
    tags: ClassVar[list[str]] = ["API Keys"]  # type: ignore[misc]

    @post(
        "/",
        status_code=HTTP_201_CREATED,
        summary="Create API Key",
        description="Create a new API key with the specified name and scopes.",
    )
    async def create_api_key(
        self,
        data: CreateAPIKeyRequest,
        backend: APIKeyBackend,
    ) -> CreateAPIKeyResponse:
        """Create a new API key.

        Args:
            data: The request data containing name, scopes, and optional expiration.

        Returns:
            The created API key information including the plaintext key (only shown once).

        Note:
            The plaintext API key is only returned in this response and cannot be
            retrieved again. Store it securely.
        """
        import hashlib
        import secrets

        from litestar_api_auth.backends.base import APIKeyInfo

        # Generate a random API key
        plaintext_key = f"{data.prefix or 'pyorg_'}{secrets.token_urlsafe(32)}"

        # Hash the key for storage
        key_hash = hashlib.sha256(plaintext_key.encode()).hexdigest()

        # Create the key in the backend
        key_info = APIKeyInfo(
            key_id=secrets.token_urlsafe(16),
            key_hash=key_hash,
            name=data.name,
            scopes=data.scopes or [],
            is_active=True,
            created_at=datetime.now(timezone.utc),
            expires_at=data.expires_at,
            last_used_at=None,
            metadata=data.metadata or {},
        )

        created_key = await backend.create(key_hash, key_info)

        return CreateAPIKeyResponse(
            key_id=created_key.key_id,
            key=plaintext_key,  # Only time this is returned
            name=created_key.name,
            scopes=created_key.scopes,
            created_at=created_key.created_at,
            expires_at=created_key.expires_at,
        )

    @get(
        "/",
        summary="List API Keys",
        description="List all API keys with pagination support.",
    )
    async def list_api_keys(
        self,
        backend: APIKeyBackend,
        limit: Annotated[int, Parameter(ge=1, le=100, default=50)] = 50,
        offset: Annotated[int, Parameter(ge=0, default=0)] = 0,
    ) -> ListAPIKeysResponse:
        """List all API keys.

        Args:
            backend: The API key storage backend.
            limit: Maximum number of keys to return (1-100, default 50).
            offset: Number of keys to skip for pagination.

        Returns:
            List of API key information (without plaintext keys).
        """
        keys = await backend.list(limit=limit, offset=offset)

        return ListAPIKeysResponse(
            items=[
                APIKeyInfoResponse(
                    key_id=key.key_id,
                    name=key.name,
                    scopes=key.scopes,
                    is_active=key.is_active,
                    created_at=key.created_at,
                    expires_at=key.expires_at,
                    last_used_at=key.last_used_at,
                    metadata=key.metadata or {},
                )
                for key in keys
            ],
            total=len(keys),
            limit=limit,
            offset=offset,
        )

    @get(
        "/{key_id:str}",
        summary="Get API Key",
        description="Get information about a specific API key.",
    )
    async def get_api_key(
        self,
        key_id: str,
        backend: APIKeyBackend,
    ) -> APIKeyInfoResponse:
        """Get information about a specific API key.

        Args:
            key_id: The unique identifier of the API key.
            backend: The API key storage backend.

        Returns:
            API key information (without plaintext key).

        Raises:
            NotFoundException: If the key is not found.
        """
        from litestar.exceptions import NotFoundException

        key_info = await backend.get_by_id(key_id)

        if key_info is None:
            raise NotFoundException(detail=f"API key not found: {key_id}")

        return APIKeyInfoResponse(
            key_id=key_info.key_id,
            name=key_info.name,
            scopes=key_info.scopes,
            is_active=key_info.is_active,
            created_at=key_info.created_at,
            expires_at=key_info.expires_at,
            last_used_at=key_info.last_used_at,
            metadata=key_info.metadata or {},
        )

    @post(
        "/{key_id:str}/revoke",
        status_code=HTTP_204_NO_CONTENT,
        summary="Revoke API Key",
        description="Revoke an API key, making it inactive without deleting it.",
    )
    async def revoke_api_key(
        self,
        key_id: str,
        backend: APIKeyBackend,
    ) -> None:
        """Revoke an API key.

        This marks the key as inactive but retains it in the database for
        audit purposes.

        Args:
            key_id: The unique identifier of the API key.
            backend: The API key storage backend.

        Raises:
            NotFoundException: If the key is not found.
        """
        from litestar.exceptions import NotFoundException

        # Get the key to find its hash
        key_info = await backend.get_by_id(key_id)

        if key_info is None:
            raise NotFoundException(detail=f"API key not found: {key_id}")

        # Revoke the key
        await backend.revoke(key_info.key_hash)

    @delete(
        "/{key_id:str}",
        status_code=HTTP_204_NO_CONTENT,
        summary="Delete API Key",
        description="Permanently delete an API key from the system.",
    )
    async def delete_api_key(
        self,
        key_id: str,
        backend: APIKeyBackend,
    ) -> None:
        """Permanently delete an API key.

        Args:
            key_id: The unique identifier of the API key.
            backend: The API key storage backend.

        Raises:
            NotFoundException: If the key is not found.
        """
        from litestar.exceptions import NotFoundException

        # Get the key to find its hash
        key_info = await backend.get_by_id(key_id)

        if key_info is None:
            raise NotFoundException(detail=f"API key not found: {key_id}")

        # Delete the key
        success = await backend.delete(key_info.key_hash)

        if not success:
            raise NotFoundException(detail=f"API key not found: {key_id}")


# ============================================================================
# Request/Response Models (using msgspec for native Litestar integration)
# ============================================================================


class CreateAPIKeyRequest(msgspec.Struct):
    """Request model for creating a new API key.

    Attributes:
        name: Human-readable name for the key.
        scopes: List of permission scopes to grant.
        prefix: Optional custom prefix (default from config).
        expires_at: Optional expiration timestamp.
        metadata: Optional additional metadata.
    """

    name: str
    scopes: list[str] = msgspec.field(default_factory=list)
    prefix: str | None = None
    expires_at: datetime | None = None
    metadata: dict[str, str] = msgspec.field(default_factory=dict)


class CreateAPIKeyResponse(msgspec.Struct):
    """Response model for API key creation.

    Attributes:
        key_id: Unique identifier for the key.
        key: The plaintext API key (only shown once).
        name: Human-readable name for the key.
        scopes: List of permission scopes.
        created_at: When the key was created.
        expires_at: When the key expires (None if no expiration).
    """

    key_id: str
    key: str  # Plaintext key - only returned once
    name: str
    scopes: list[str]
    created_at: datetime | None
    expires_at: datetime | None = None


class APIKeyInfoResponse(msgspec.Struct):
    """Response model for API key information.

    Attributes:
        key_id: Unique identifier for the key.
        name: Human-readable name for the key.
        scopes: List of permission scopes.
        is_active: Whether the key is currently active.
        created_at: When the key was created.
        expires_at: When the key expires (None if no expiration).
        last_used_at: When the key was last used (None if never used).
        metadata: Additional custom metadata.
    """

    key_id: str
    name: str
    scopes: list[str]
    is_active: bool
    created_at: datetime | None
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    metadata: dict[str, Any] = msgspec.field(default_factory=dict)


class ListAPIKeysResponse(msgspec.Struct):
    """Response model for listing API keys.

    Attributes:
        items: List of API key information.
        total: Total number of items in this response.
        limit: Maximum number of items per page.
        offset: Number of items skipped.
    """

    items: list[APIKeyInfoResponse]
    total: int
    limit: int
    offset: int
