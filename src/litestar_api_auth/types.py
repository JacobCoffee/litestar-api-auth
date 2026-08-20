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


class APIKeyInfo(msgspec.Struct, kw_only=True):
    """Canonical container for API key metadata and state.

    This is the one struct the whole library uses: backends store and return
    it, ``APIKeyMiddleware`` places it in ``request.state.api_key``, and
    guards read it. It is re-exported as
    :class:`litestar_api_auth.backends.base.APIKeyInfo` for backwards
    compatibility -- both names refer to this exact class, so ``is`` and
    ``isinstance`` checks agree across the two import paths.

    It carries metadata about an API key, never the plaintext key value
    (which should only be shown once at creation). ``key_hash`` *is* the
    stored verifier and is therefore sensitive: the middleware blanks it on
    the copy it exposes through request state (see
    ``APIKeyMiddleware.__call__``).

    Attributes:
        key_id: Unique identifier for the API key.
        name: Human-readable name/description for the key.
        scopes: List of permission scopes granted to this key.
        key_hash: Hash of the API key as stored by the backend. Blanked to
            ``""`` on the copy the middleware exposes through request state.
        prefix: Optional prefix portion of the key (e.g., "pyorg_"). Purely
            informational -- the bundled backends do not persist it, so a
            record read back out of storage generally has ``None`` here.
        is_active: Whether the key is currently active (not revoked).
        created_at: Timestamp when the key was created.
        expires_at: Optional expiration timestamp. None means no expiration.
        last_used_at: Optional timestamp of last successful authentication. None if never used.
        metadata: Additional arbitrary metadata associated with the key.

    Example:
        >>> from datetime import datetime, timedelta, timezone
        >>> key_info = APIKeyInfo(
        ...     key_id="abc123",
        ...     name="Production API Key",
        ...     scopes=["read:users", "write:posts"],
        ...     key_hash="0" * 64,
        ...     prefix="pyorg_",
        ...     created_at=datetime.now(timezone.utc),
        ...     expires_at=datetime.now(timezone.utc) + timedelta(days=365),
        ...     metadata={"owner": "admin@example.com"},
        ... )
    """

    # Keyword-only on purpose. The two structs this consolidates had
    # *different* positional orders (``key_id, prefix, name, scopes,
    # created_at`` for the old public struct; ``key_id, key_hash, name,
    # scopes`` for the old backend one), and ``msgspec.Struct`` does not
    # validate field types on direct construction -- so any order chosen here
    # would let an old positional call silently build a corrupted record
    # (e.g. a hash landing in ``name``) instead of failing. Requiring
    # keywords turns that into an immediate ``TypeError``.
    key_id: str
    name: str
    scopes: list[str]
    key_hash: str = ""
    prefix: str | None = None
    is_active: bool = True
    created_at: datetime | None = None
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    metadata: dict[str, Any] | None = None

    @property
    def has_valid_types(self) -> bool:
        """Whether ``is_active`` and ``scopes`` actually match the types this class declares.

        ``msgspec.Struct`` does not enforce field types when a struct is built
        directly in Python (only decoding via ``msgspec.json.decode``/
        ``msgspec.convert`` does), so a custom/legacy backend, migrated or
        corrupted serialized data, or direct programmatic seeding can produce
        a record whose ``is_active`` is a truthy non-``bool`` (e.g. the string
        ``"false"``) or whose ``scopes`` is a ``str`` instead of a
        ``list[str]``. Both would silently fail open for a caller that trusts
        this record without checking this property first: ``not "false"`` is
        ``False``, so the "is the key active" checks in
        ``APIKeyMiddleware._validate_api_key`` and ``guards.get_api_key_info``
        would both pass, and ``"admin" in "api_keys:admin"`` is a substring
        match rather than a membership check, so ``has_scope``/``has_scopes``
        would too.

        Returns:
            True if ``is_active`` is actually a ``bool`` and ``scopes`` is
            actually a ``list`` of ``str``, False otherwise.
        """
        return (
            isinstance(self.is_active, bool)
            and isinstance(self.scopes, list)
            and all(isinstance(s, str) for s in self.scopes)
        )

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
        scopes: list[str] | None = None,
        requirement: ScopeRequirement = "all",
        *,
        required_scopes: list[str] | None = None,
    ) -> bool:
        """Check if the key has the required scopes.

        Every historical call convention of the two structs this consolidates
        keeps working: ``requirement`` is accepted positionally *and* by
        keyword (the backend struct made it keyword-only), and
        ``required_scopes`` is a backwards-compatible alias for ``scopes``
        (the name the old public struct used for its first parameter).

        Args:
            scopes: List of scopes to check for.
            requirement: Whether "all" scopes must match or "any" scope is sufficient.
            required_scopes: Legacy alias for ``scopes``.

        Returns:
            True if the scope requirement is satisfied.

        Raises:
            TypeError: If neither ``scopes`` nor ``required_scopes`` is given.
            ValueError: If requirement is not "all" or "any".

        Example:
            >>> key_info.has_scopes(["read:users", "write:users"], requirement="all")
            False
            >>> key_info.has_scopes(["read:users", "write:posts"], requirement="any")
            True
        """
        wanted = scopes if scopes is not None else required_scopes
        if wanted is None:
            msg = "has_scopes() missing required argument: 'scopes'"
            raise TypeError(msg)

        if requirement == "all":
            return all(scope in self.scopes for scope in wanted)
        if requirement == "any":
            return any(scope in self.scopes for scope in wanted)
        msg = f"Invalid requirement: {requirement!r}. Must be 'all' or 'any'"
        raise ValueError(msg)
