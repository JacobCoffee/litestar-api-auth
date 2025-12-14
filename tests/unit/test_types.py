"""Unit tests for API key type definitions."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from litestar_api_auth.types import APIKeyInfo, APIKeyState


class TestAPIKeyState:
    """Test suite for APIKeyState enum."""

    def test_enum_values(self) -> None:
        """Test that enum has expected values."""
        assert APIKeyState.ACTIVE == "active"
        assert APIKeyState.EXPIRED == "expired"
        assert APIKeyState.REVOKED == "revoked"

    def test_enum_membership(self) -> None:
        """Test that values are members of the enum."""
        assert "active" in [s.value for s in APIKeyState]
        assert "expired" in [s.value for s in APIKeyState]
        assert "revoked" in [s.value for s in APIKeyState]


class TestAPIKeyInfo:
    """Test suite for APIKeyInfo dataclass."""

    @pytest.fixture
    def base_key_info(self) -> APIKeyInfo:
        """Create a basic APIKeyInfo instance for testing."""
        return APIKeyInfo(
            key_id="abc123",
            prefix="pyorg_",
            name="Test Key",
            scopes=["read:users", "write:posts"],
            created_at=datetime.utcnow(),
        )

    def test_initialization_with_defaults(self, base_key_info: APIKeyInfo) -> None:
        """Test that APIKeyInfo initializes with default values."""
        assert base_key_info.key_id == "abc123"
        assert base_key_info.prefix == "pyorg_"
        assert base_key_info.name == "Test Key"
        assert base_key_info.scopes == ["read:users", "write:posts"]
        assert base_key_info.expires_at is None
        assert base_key_info.last_used_at is None
        assert base_key_info.is_active is True
        assert base_key_info.metadata == {}

    def test_initialization_with_all_fields(self) -> None:
        """Test APIKeyInfo initialization with all fields."""
        now = datetime.utcnow()
        expires = now + timedelta(days=365)
        last_used = now - timedelta(hours=1)

        key_info = APIKeyInfo(
            key_id="xyz789",
            prefix="myapp_",
            name="Production Key",
            scopes=["admin:*"],
            created_at=now,
            expires_at=expires,
            last_used_at=last_used,
            is_active=True,
            metadata={"owner": "admin@example.com", "environment": "production"},
        )

        assert key_info.key_id == "xyz789"
        assert key_info.expires_at == expires
        assert key_info.last_used_at == last_used
        assert key_info.metadata == {
            "owner": "admin@example.com",
            "environment": "production",
        }

    def test_frozen_dataclass(self, base_key_info: APIKeyInfo) -> None:
        """Test that APIKeyInfo is immutable."""
        with pytest.raises(AttributeError):
            base_key_info.name = "New Name"  # type: ignore[misc]

    def test_state_active(self, base_key_info: APIKeyInfo) -> None:
        """Test state property returns ACTIVE for active, non-expired key."""
        assert base_key_info.state == APIKeyState.ACTIVE

    def test_state_revoked(self) -> None:
        """Test state property returns REVOKED for inactive key."""
        key_info = APIKeyInfo(
            key_id="abc123",
            prefix="pyorg_",
            name="Revoked Key",
            scopes=[],
            created_at=datetime.utcnow(),
            is_active=False,
        )

        assert key_info.state == APIKeyState.REVOKED

    def test_state_expired(self) -> None:
        """Test state property returns EXPIRED for expired key."""
        key_info = APIKeyInfo(
            key_id="abc123",
            prefix="pyorg_",
            name="Expired Key",
            scopes=[],
            created_at=datetime.utcnow() - timedelta(days=2),
            expires_at=datetime.utcnow() - timedelta(days=1),
            is_active=True,
        )

        assert key_info.state == APIKeyState.EXPIRED

    def test_is_expired_property(self) -> None:
        """Test is_expired property."""
        # Not expired - no expiration date
        key_info = APIKeyInfo(
            key_id="abc123",
            prefix="pyorg_",
            name="No Expiration",
            scopes=[],
            created_at=datetime.utcnow(),
        )
        assert not key_info.is_expired

        # Not expired - expiration in future
        key_info = APIKeyInfo(
            key_id="abc123",
            prefix="pyorg_",
            name="Future Expiration",
            scopes=[],
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(days=30),
        )
        assert not key_info.is_expired

        # Expired - expiration in past
        key_info = APIKeyInfo(
            key_id="abc123",
            prefix="pyorg_",
            name="Past Expiration",
            scopes=[],
            created_at=datetime.utcnow() - timedelta(days=2),
            expires_at=datetime.utcnow() - timedelta(days=1),
        )
        assert key_info.is_expired

    def test_is_valid_property(self) -> None:
        """Test is_valid property."""
        # Valid - active and not expired
        key_info = APIKeyInfo(
            key_id="abc123",
            prefix="pyorg_",
            name="Valid Key",
            scopes=[],
            created_at=datetime.utcnow(),
            is_active=True,
        )
        assert key_info.is_valid

        # Invalid - revoked
        key_info = APIKeyInfo(
            key_id="abc123",
            prefix="pyorg_",
            name="Revoked Key",
            scopes=[],
            created_at=datetime.utcnow(),
            is_active=False,
        )
        assert not key_info.is_valid

        # Invalid - expired
        key_info = APIKeyInfo(
            key_id="abc123",
            prefix="pyorg_",
            name="Expired Key",
            scopes=[],
            created_at=datetime.utcnow() - timedelta(days=2),
            expires_at=datetime.utcnow() - timedelta(days=1),
            is_active=True,
        )
        assert not key_info.is_valid

    def test_has_scope(self, base_key_info: APIKeyInfo) -> None:
        """Test has_scope method."""
        assert base_key_info.has_scope("read:users")
        assert base_key_info.has_scope("write:posts")
        assert not base_key_info.has_scope("admin:delete")

    def test_has_scopes_all_requirement(self, base_key_info: APIKeyInfo) -> None:
        """Test has_scopes with 'all' requirement."""
        # All scopes present
        assert base_key_info.has_scopes(
            ["read:users", "write:posts"],
            requirement="all",
        )

        # Some scopes missing
        assert not base_key_info.has_scopes(
            ["read:users", "admin:delete"],
            requirement="all",
        )

        # Empty list
        assert base_key_info.has_scopes([], requirement="all")

    def test_has_scopes_any_requirement(self, base_key_info: APIKeyInfo) -> None:
        """Test has_scopes with 'any' requirement."""
        # At least one scope present
        assert base_key_info.has_scopes(
            ["read:users", "admin:delete"],
            requirement="any",
        )

        # No scopes present
        assert not base_key_info.has_scopes(
            ["admin:delete", "admin:write"],
            requirement="any",
        )

        # Empty list
        assert not base_key_info.has_scopes([], requirement="any")

    def test_has_scopes_default_requirement(self, base_key_info: APIKeyInfo) -> None:
        """Test that has_scopes defaults to 'all' requirement."""
        # Default should be "all"
        result = base_key_info.has_scopes(["read:users", "write:posts"])
        assert result is True

        result = base_key_info.has_scopes(["read:users", "admin:delete"])
        assert result is False

    def test_metadata_default_factory(self) -> None:
        """Test that metadata uses default factory and doesn't share state."""
        key1 = APIKeyInfo(
            key_id="key1",
            prefix="test_",
            name="Key 1",
            scopes=[],
            created_at=datetime.utcnow(),
        )

        key2 = APIKeyInfo(
            key_id="key2",
            prefix="test_",
            name="Key 2",
            scopes=[],
            created_at=datetime.utcnow(),
        )

        # Metadata should be separate instances
        assert key1.metadata is not key2.metadata
        assert key1.metadata == {}
        assert key2.metadata == {}
