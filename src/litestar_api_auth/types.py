"""Type definitions for API key authentication.

This module provides core type definitions used throughout the litestar-api-auth library,
including API key metadata, state tracking, and scope requirements.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

import msgspec

__all__ = [
    "APIKeyInfo",
    "APIKeyState",
    "ScopeRequirement",
]


class APIKeyState(str, Enum):
    """Enumeration of possible API key states.

    Attributes:
        ACTIVE: Key is active and can be used for authentication.
        EXPIRED: Key has passed its expiration date.
        REVOKED: Key has been manually revoked and is no longer valid.
    """

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


ScopeRequirement = Literal["all", "any"]
"""Type definition for scope matching requirements.

- "all": All specified scopes must be present on the API key.
- "any": At least one of the specified scopes must be present.
"""


class APIKeyInfo(msgspec.Struct, frozen=True):
    """Immutable container for API key metadata and state.

    This struct represents the complete information about an API key,
    excluding the actual key value (which should only be shown once at creation).

    Attributes:
        key_id: Unique identifier for the API key.
        prefix: The prefix portion of the key (e.g., "pyorg_").
        name: Human-readable name/description for the key.
        scopes: List of permission scopes granted to this key.
        created_at: Timestamp when the key was created.
        expires_at: Optional expiration timestamp. None means no expiration.
        last_used_at: Optional timestamp of last successful authentication. None if never used.
        is_active: Whether the key is currently active (not revoked).
        metadata: Additional arbitrary metadata associated with the key.

    Example:
        >>> from datetime import datetime, timedelta
        >>> key_info = APIKeyInfo(
        ...     key_id="abc123",
        ...     prefix="pyorg_",
        ...     name="Production API Key",
        ...     scopes=["read:users", "write:posts"],
        ...     created_at=datetime.utcnow(),
        ...     expires_at=datetime.utcnow() + timedelta(days=365),
        ...     last_used_at=None,
        ...     is_active=True,
        ...     metadata={"owner": "admin@example.com"},
        ... )
    """

    key_id: str
    prefix: str
    name: str
    scopes: list[str]
    created_at: datetime
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    is_active: bool = True
    metadata: dict[str, Any] = msgspec.field(default_factory=dict)

    @property
    def state(self) -> APIKeyState:
        """Compute the current state of the API key.

        Returns:
            The current state based on is_active and expiration status.

        Note:
            This property computes state dynamically. If you need to filter
            by state at the database level, implement state checks in your query.
        """
        if not self.is_active:
            return APIKeyState.REVOKED

        if self.expires_at is not None and self._is_past_expiration():
            return APIKeyState.EXPIRED

        return APIKeyState.ACTIVE

    def _is_past_expiration(self) -> bool:
        """Check if the expiration time has passed, handling timezone differences."""
        if self.expires_at is None:
            return False

        from datetime import timezone

        now = datetime.now(timezone.utc)
        expires = self.expires_at

        # Make expires_at timezone-aware if it isn't already
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)

        return now > expires

    @property
    def is_expired(self) -> bool:
        """Check if the key has expired.

        Returns:
            True if the key has an expiration date and it has passed.
        """
        return self.expires_at is not None and self._is_past_expiration()

    @property
    def is_valid(self) -> bool:
        """Check if the key is valid for authentication.

        A key is valid if it is active and not expired.

        Returns:
            True if the key can be used for authentication.
        """
        return self.is_active and not self.is_expired

    def has_scope(self, scope: str) -> bool:
        """Check if the key has a specific scope.

        Args:
            scope: The scope to check for.

        Returns:
            True if the scope is present in the key's scopes list.
        """
        return scope in self.scopes

    def has_scopes(
        self,
        required_scopes: list[str],
        requirement: ScopeRequirement = "all",
    ) -> bool:
        """Check if the key has the required scopes.

        Args:
            required_scopes: List of scopes to check for.
            requirement: Whether "all" scopes must match or "any" scope is sufficient.

        Returns:
            True if the scope requirement is satisfied.

        Example:
            >>> key_info.has_scopes(["read:users", "write:users"], requirement="all")
            False
            >>> key_info.has_scopes(["read:users", "write:posts"], requirement="any")
            True
        """
        if requirement == "all":
            return all(scope in self.scopes for scope in required_scopes)
        # requirement == "any"
        return any(scope in self.scopes for scope in required_scopes)
