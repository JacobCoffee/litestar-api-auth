"""Msgspec schemas for API key request and response models.

This module provides msgspec Struct schemas for API key operations, including:
- Request schemas for creating and updating API keys
- Response schemas for API key data (with and without raw keys)
- Pagination and listing schemas

Using msgspec provides native Litestar integration with high performance
serialization and validation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import msgspec

__all__ = [
    "CreateAPIKeyRequest",
    "UpdateAPIKeyRequest",
    "APIKeyResponse",
    "APIKeyCreatedResponse",
    "APIKeyListResponse",
]


class CreateAPIKeyRequest(msgspec.Struct):
    """Request schema for creating a new API key.

    Attributes:
        name: Human-readable name for the API key. Must be between 1-255 characters.
        scopes: List of permission scopes to grant. Defaults to empty list (no scopes).
        expires_at: Optional expiration timestamp. If None, key never expires.
        metadata: Optional arbitrary key-value metadata. Keys and values must be strings.

    Example:
        >>> from datetime import datetime, timedelta
        >>> request = CreateAPIKeyRequest(
        ...     name="Production API Key",
        ...     scopes=["read:users", "write:posts"],
        ...     expires_at=datetime.utcnow() + timedelta(days=365),
        ...     metadata={"owner": "admin@example.com", "env": "production"},
        ... )
    """

    name: str
    scopes: list[str] = msgspec.field(default_factory=list)
    expires_at: datetime | None = None
    metadata: dict[str, str] = msgspec.field(default_factory=dict)


class UpdateAPIKeyRequest(msgspec.Struct):
    """Request schema for updating an existing API key.

    All fields are optional. Only provided fields will be updated.

    Attributes:
        name: New name for the API key.
        scopes: New list of scopes (completely replaces existing scopes).
        metadata: New metadata (completely replaces existing metadata).

    Note:
        - You cannot update expires_at or is_active through this schema.
        - Use dedicated endpoints for revoking keys or extending expiration.
        - Partial updates are supported; omitted fields remain unchanged.

    Example:
        >>> request = UpdateAPIKeyRequest(
        ...     name="Updated Production Key",
        ...     scopes=["read:users", "read:posts"],
        ... )
    """

    name: str | None = None
    scopes: list[str] | None = None
    metadata: dict[str, str] | None = None


class APIKeyResponse(msgspec.Struct):
    """Response schema for API key metadata (without the raw key).

    This schema is used for all API responses except initial creation.
    The raw API key is never included in this schema for security reasons.

    Attributes:
        id: Unique identifier for the API key.
        name: Human-readable name for the key.
        prefix: The prefix portion of the key (e.g., "pyorg_").
        scopes: List of permission scopes granted to this key.
        created_at: Timestamp when the key was created (UTC).
        is_active: Whether the key is currently active (not revoked).
        expires_at: Optional expiration timestamp (UTC).
        last_used_at: Optional timestamp of last successful authentication (UTC).
        metadata: Additional arbitrary metadata associated with the key.

    Example:
        >>> response = APIKeyResponse(
        ...     id="abc123",
        ...     name="Production API Key",
        ...     prefix="pyorg_",
        ...     scopes=["read:users"],
        ...     created_at=datetime.utcnow(),
        ...     is_active=True,
        ...     expires_at=None,
        ...     last_used_at=None,
        ...     metadata={"owner": "admin@example.com"},
        ... )
    """

    id: str
    name: str
    prefix: str
    scopes: list[str]
    created_at: datetime
    is_active: bool
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    metadata: dict[str, Any] = msgspec.field(default_factory=dict)


class APIKeyCreatedResponse(msgspec.Struct):
    """Response schema when creating a new API key.

    This schema includes the raw API key which is only shown ONCE during creation.
    The raw key should be stored securely by the client. It cannot be retrieved again.

    Attributes:
        id: Unique identifier for the API key.
        name: Human-readable name for the key.
        prefix: The prefix portion of the key (e.g., "pyorg_").
        scopes: List of permission scopes granted to this key.
        created_at: Timestamp when the key was created (UTC).
        is_active: Whether the key is currently active (not revoked).
        key: The raw API key. This is the only time it will be shown.
        expires_at: Optional expiration timestamp (UTC).
        last_used_at: Optional timestamp of last successful authentication (UTC).
        metadata: Additional arbitrary metadata associated with the key.

    Security Note:
        - Store this key securely immediately after receiving it.
        - The key cannot be retrieved again after this response.
        - If lost, a new key must be generated.

    Example:
        >>> response = APIKeyCreatedResponse(
        ...     id="abc123",
        ...     name="Production API Key",
        ...     prefix="pyorg_",
        ...     scopes=["read:users"],
        ...     created_at=datetime.utcnow(),
        ...     is_active=True,
        ...     key="pyorg_abc123def456ghi789jkl012mno345pqr678",
        ...     expires_at=None,
        ...     last_used_at=None,
        ...     metadata={},
        ... )
    """

    id: str
    name: str
    prefix: str
    scopes: list[str]
    created_at: datetime
    is_active: bool
    key: str
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    metadata: dict[str, Any] = msgspec.field(default_factory=dict)


class APIKeyListResponse(msgspec.Struct):
    """Response schema for paginated list of API keys.

    This schema provides paginated results with metadata about the total
    number of items and pagination parameters.

    Attributes:
        items: List of API key responses for the current page.
        total: Total number of API keys matching the query (across all pages).
        limit: Maximum number of items per page.
        offset: Number of items skipped (for pagination).

    Example:
        >>> response = APIKeyListResponse(
        ...     items=[...],  # List of APIKeyResponse objects
        ...     total=42,
        ...     limit=20,
        ...     offset=0,
        ... )
    """

    items: list[APIKeyResponse]
    total: int
    limit: int
    offset: int
