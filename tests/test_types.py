"""Tests for API key type definitions.

This module tests the core type definitions including APIKeyInfo,
APIKeyState, and scope checking functionality.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from litestar_api_auth.types import APIKeyInfo, APIKeyState


class TestAPIKeyInfo:
    """Tests for APIKeyInfo dataclass."""

    def test_api_key_info_creation(self, sample_api_key_info: APIKeyInfo) -> None:
        """Test that APIKeyInfo can be created with all fields."""
        assert sample_api_key_info.key_id == "test-key-id-123"
        assert sample_api_key_info.prefix == "test_"
        assert sample_api_key_info.name == "Test API Key"
        assert sample_api_key_info.scopes == ["read:users", "write:posts"]
        assert sample_api_key_info.is_active is True
        assert sample_api_key_info.created_at is not None
        assert sample_api_key_info.expires_at is not None
        assert sample_api_key_info.last_used_at is None
        assert sample_api_key_info.metadata == {"owner": "test@example.com"}

    def test_api_key_info_minimal_creation(self) -> None:
        """Test creating APIKeyInfo with minimal required fields."""
        now = datetime.now(timezone.utc)
        key_info = APIKeyInfo(
            key_id="minimal-key",
            prefix="min_",
            name="Minimal Key",
            scopes=[],
            created_at=now,
        )

        assert key_info.key_id == "minimal-key"
        assert key_info.scopes == []
        assert key_info.expires_at is None
        assert key_info.last_used_at is None
        assert key_info.is_active is True  # Default value
        assert key_info.metadata == {}  # Default value

    def test_api_key_info_immutability(self, sample_api_key_info: APIKeyInfo) -> None:
        """Test that APIKeyInfo is frozen and immutable."""
        with pytest.raises(Exception):  # FrozenInstanceError or AttributeError
            sample_api_key_info.name = "Modified Name"  # type: ignore[misc]

    def test_api_key_info_with_empty_metadata(self) -> None:
        """Test APIKeyInfo with empty metadata dictionary."""
        now = datetime.now(timezone.utc)
        key_info = APIKeyInfo(
            key_id="test-key",
            prefix="test_",
            name="Test",
            scopes=["read"],
            created_at=now,
            metadata={},
        )

        assert key_info.metadata == {}


class TestAPIKeyState:
    """Tests for APIKeyState property and state transitions."""

    def test_api_key_state_active(self, sample_api_key_info: APIKeyInfo) -> None:
        """Test that a valid, non-expired key has ACTIVE state."""
        assert sample_api_key_info.state == APIKeyState.ACTIVE
        assert sample_api_key_info.is_valid is True
        assert sample_api_key_info.is_expired is False

    def test_api_key_state_expired(self, expired_api_key_info: APIKeyInfo) -> None:
        """Test that an expired key has EXPIRED state."""
        assert expired_api_key_info.state == APIKeyState.EXPIRED
        assert expired_api_key_info.is_valid is False
        assert expired_api_key_info.is_expired is True

    def test_api_key_state_revoked(self, revoked_api_key_info: APIKeyInfo) -> None:
        """Test that a revoked key has REVOKED state."""
        assert revoked_api_key_info.state == APIKeyState.REVOKED
        assert revoked_api_key_info.is_valid is False
        # Note: Revoked keys may or may not be expired

    def test_api_key_state_no_expiration(self) -> None:
        """Test that a key with no expiration date is ACTIVE."""
        now = datetime.now(timezone.utc)
        key_info = APIKeyInfo(
            key_id="no-expiry",
            prefix="test_",
            name="Never Expires",
            scopes=["read"],
            created_at=now,
            expires_at=None,  # No expiration
            is_active=True,
        )

        assert key_info.state == APIKeyState.ACTIVE
        assert key_info.is_valid is True
        assert key_info.is_expired is False

    def test_api_key_state_future_expiration(self) -> None:
        """Test that a key with future expiration is ACTIVE."""
        now = datetime.now(timezone.utc)
        key_info = APIKeyInfo(
            key_id="future-expiry",
            prefix="test_",
            name="Future Expiry",
            scopes=["read"],
            created_at=now,
            expires_at=now + timedelta(days=365),
            is_active=True,
        )

        assert key_info.state == APIKeyState.ACTIVE
        assert key_info.is_valid is True
        assert key_info.is_expired is False

    def test_api_key_state_just_expired(self) -> None:
        """Test that a key that just expired is EXPIRED."""
        now = datetime.now(timezone.utc)
        key_info = APIKeyInfo(
            key_id="just-expired",
            prefix="test_",
            name="Just Expired",
            scopes=["read"],
            created_at=now - timedelta(days=1),
            expires_at=now - timedelta(seconds=1),  # Just expired
            is_active=True,
        )

        assert key_info.state == APIKeyState.EXPIRED
        assert key_info.is_valid is False
        assert key_info.is_expired is True

    def test_api_key_state_revoked_takes_precedence(self) -> None:
        """Test that REVOKED state takes precedence over EXPIRED."""
        now = datetime.now(timezone.utc)
        key_info = APIKeyInfo(
            key_id="revoked-and-expired",
            prefix="test_",
            name="Revoked and Expired",
            scopes=["read"],
            created_at=now - timedelta(days=60),
            expires_at=now - timedelta(days=30),  # Also expired
            is_active=False,  # Revoked
        )

        # REVOKED should take precedence
        assert key_info.state == APIKeyState.REVOKED
        assert key_info.is_valid is False


class TestHasScope:
    """Tests for has_scope method."""

    def test_has_scope_single_match(self, sample_api_key_info: APIKeyInfo) -> None:
        """Test checking for a single scope that exists."""
        assert sample_api_key_info.has_scope("read:users") is True
        assert sample_api_key_info.has_scope("write:posts") is True

    def test_has_scope_no_match(self, sample_api_key_info: APIKeyInfo) -> None:
        """Test checking for a scope that doesn't exist."""
        assert sample_api_key_info.has_scope("admin:all") is False
        assert sample_api_key_info.has_scope("delete:users") is False

    def test_has_scope_empty_scopes(self) -> None:
        """Test has_scope with a key that has no scopes."""
        now = datetime.now(timezone.utc)
        key_info = APIKeyInfo(
            key_id="no-scopes",
            prefix="test_",
            name="No Scopes",
            scopes=[],
            created_at=now,
        )

        assert key_info.has_scope("read:users") is False
        assert key_info.has_scope("any:scope") is False

    def test_has_scope_case_sensitive(self, sample_api_key_info: APIKeyInfo) -> None:
        """Test that scope checking is case-sensitive."""
        assert sample_api_key_info.has_scope("read:users") is True
        assert sample_api_key_info.has_scope("READ:USERS") is False
        assert sample_api_key_info.has_scope("Read:Users") is False


class TestHasScopesAll:
    """Tests for has_scopes method with 'all' requirement."""

    def test_has_scopes_all_match(self, sample_api_key_info: APIKeyInfo) -> None:
        """Test that all required scopes are present."""
        # Key has: ["read:users", "write:posts"]
        assert sample_api_key_info.has_scopes(["read:users", "write:posts"], requirement="all") is True

    def test_has_scopes_all_partial_match(self, sample_api_key_info: APIKeyInfo) -> None:
        """Test that partial match fails with 'all' requirement."""
        # Key has: ["read:users", "write:posts"]
        # Missing "admin:all"
        assert sample_api_key_info.has_scopes(["read:users", "admin:all"], requirement="all") is False

    def test_has_scopes_all_no_match(self, sample_api_key_info: APIKeyInfo) -> None:
        """Test that no match fails with 'all' requirement."""
        assert sample_api_key_info.has_scopes(["admin:all", "delete:users"], requirement="all") is False

    def test_has_scopes_all_single_scope(self, sample_api_key_info: APIKeyInfo) -> None:
        """Test checking a single scope with 'all' requirement."""
        assert sample_api_key_info.has_scopes(["read:users"], requirement="all") is True
        assert sample_api_key_info.has_scopes(["admin:all"], requirement="all") is False

    def test_has_scopes_all_empty_required(self, sample_api_key_info: APIKeyInfo) -> None:
        """Test that empty required scopes list returns True."""
        # Empty list means no requirements, so should pass
        assert sample_api_key_info.has_scopes([], requirement="all") is True

    def test_has_scopes_all_subset(self, sample_api_key_info: APIKeyInfo) -> None:
        """Test checking a subset of available scopes."""
        # Requesting only one of the available scopes
        assert sample_api_key_info.has_scopes(["read:users"], requirement="all") is True

    def test_has_scopes_all_default_requirement(self, sample_api_key_info: APIKeyInfo) -> None:
        """Test that default requirement is 'all'."""
        # Not specifying requirement should default to "all"
        assert sample_api_key_info.has_scopes(["read:users", "write:posts"]) is True
        assert sample_api_key_info.has_scopes(["read:users", "admin:all"]) is False


class TestHasScopesAny:
    """Tests for has_scopes method with 'any' requirement."""

    def test_has_scopes_any_single_match(self, sample_api_key_info: APIKeyInfo) -> None:
        """Test that a single matching scope passes with 'any' requirement."""
        # Key has: ["read:users", "write:posts"]
        assert sample_api_key_info.has_scopes(["read:users", "admin:all"], requirement="any") is True

    def test_has_scopes_any_multiple_matches(self, sample_api_key_info: APIKeyInfo) -> None:
        """Test that multiple matching scopes pass with 'any' requirement."""
        assert sample_api_key_info.has_scopes(["read:users", "write:posts"], requirement="any") is True

    def test_has_scopes_any_no_match(self, sample_api_key_info: APIKeyInfo) -> None:
        """Test that no matching scopes fail with 'any' requirement."""
        assert sample_api_key_info.has_scopes(["admin:all", "delete:users"], requirement="any") is False

    def test_has_scopes_any_first_match(self, sample_api_key_info: APIKeyInfo) -> None:
        """Test matching on first scope in the list."""
        assert sample_api_key_info.has_scopes(["read:users", "nonexistent"], requirement="any") is True

    def test_has_scopes_any_last_match(self, sample_api_key_info: APIKeyInfo) -> None:
        """Test matching on last scope in the list."""
        assert sample_api_key_info.has_scopes(["nonexistent", "write:posts"], requirement="any") is True

    def test_has_scopes_any_empty_required(self, sample_api_key_info: APIKeyInfo) -> None:
        """Test that empty required scopes list returns False with 'any'."""
        # Empty list with "any" requirement means no scope to match
        assert sample_api_key_info.has_scopes([], requirement="any") is False


class TestIntegration:
    """Integration tests combining multiple type features."""

    def test_key_lifecycle_states(self) -> None:
        """Test a key going through different states over time."""
        now = datetime.now(timezone.utc)

        # Create a new active key
        key_info = APIKeyInfo(
            key_id="lifecycle-test",
            prefix="test_",
            name="Lifecycle Test",
            scopes=["read", "write"],
            created_at=now,
            expires_at=now + timedelta(days=30),
            is_active=True,
        )

        # Initially active
        assert key_info.state == APIKeyState.ACTIVE
        assert key_info.is_valid is True

        # Simulate expiration (would need to create new instance in reality)
        expired_key = APIKeyInfo(
            key_id=key_info.key_id,
            prefix=key_info.prefix,
            name=key_info.name,
            scopes=key_info.scopes,
            created_at=key_info.created_at,
            expires_at=now - timedelta(days=1),  # Expired
            is_active=True,
        )
        assert expired_key.state == APIKeyState.EXPIRED
        assert expired_key.is_valid is False

        # Simulate revocation
        revoked_key = APIKeyInfo(
            key_id=key_info.key_id,
            prefix=key_info.prefix,
            name=key_info.name,
            scopes=key_info.scopes,
            created_at=key_info.created_at,
            expires_at=key_info.expires_at,
            is_active=False,  # Revoked
        )
        assert revoked_key.state == APIKeyState.REVOKED
        assert revoked_key.is_valid is False

    def test_scope_checking_patterns(self) -> None:
        """Test various scope checking patterns."""
        now = datetime.now(timezone.utc)
        key_info = APIKeyInfo(
            key_id="scope-test",
            prefix="test_",
            name="Scope Test",
            scopes=["read:users", "read:posts", "write:posts"],
            created_at=now,
        )

        # Check various patterns
        # Pattern 1: All read permissions
        assert key_info.has_scopes(["read:users", "read:posts"], requirement="all") is True

        # Pattern 2: Any write permission
        assert key_info.has_scopes(["write:users", "write:posts"], requirement="any") is True

        # Pattern 3: Mixed permissions (all required)
        assert key_info.has_scopes(["read:users", "write:posts"], requirement="all") is True

        # Pattern 4: Admin access (not granted)
        assert key_info.has_scope("admin:all") is False

        # Pattern 5: Partial match insufficient for "all"
        assert key_info.has_scopes(["read:users", "delete:posts"], requirement="all") is False

    def test_metadata_usage_patterns(self) -> None:
        """Test various metadata usage patterns."""
        now = datetime.now(timezone.utc)

        # Metadata with various types of information
        key_info = APIKeyInfo(
            key_id="metadata-test",
            prefix="test_",
            name="Metadata Test",
            scopes=["read"],
            created_at=now,
            metadata={
                "owner": "user@example.com",
                "department": "engineering",
                "environment": "production",
                "created_by_ip": "192.168.1.1",
            },
        )

        assert key_info.metadata["owner"] == "user@example.com"
        assert key_info.metadata["department"] == "engineering"
        assert "environment" in key_info.metadata
        assert len(key_info.metadata) == 4
